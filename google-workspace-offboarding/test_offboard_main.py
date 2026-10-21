#!/usr/bin/env python3
"""
Integration tests for offboard_user.py's main() flow.

Stdlib only. Drives main() end to end with a scripted fake in place of
run_gam / run_gyb / subprocess, and asserts the ORDER of gam commands, the
exit code and the summary. These pin the behaviours that live in the
orchestrator and nowhere else: phase order, the licence hold after a failed
transfer, the forced suspension when containment fails, the scorched-earth
Shared Drive gate, the temporary-unsuspend contract, and restore-only mode.

    python3 test_offboard_main.py -v

Nothing here can reach a tenant: subprocess.run and subprocess.Popen are
replaced for the whole module, and shutil.which answers without looking.
"""

import atexit
import contextlib
import importlib.util
import io
import logging
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("offboard_user", HERE / "offboard_user.py")
offb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(offb)

LEAVER = "leaver@yourdomain.com"
SUCCESSOR = "successor@yourdomain.com"


def fixture(name: str) -> str:
    """Captured GAM 7.48.01 output from fixtures/, first (comment) line dropped."""
    text = (HERE / "fixtures" / f"gam7_{name}.txt").read_text(encoding="utf-8")
    return text.split("\n", 1)[1]


def quick_fields(**overrides) -> str:
    """`gam info user X quick` output for LEAVER with fields overridden."""
    base = {
        "Is a Super Admin": "False", "Is Delegated Admin": "False",
        "2-step enrolled": "False", "2-step enforced": "False",
        "Account Suspended": "False", "Mailbox is setup": "True",
        "Google Org Unit Path": "/",
    }
    base.update(overrides)
    lines = [f"User: {LEAVER}", "  Settings:", "    Full Name: Test Leaver"]
    lines += [f"    {k}: {v}" for k, v in base.items()]
    return "\n".join(lines) + "\n"


SHARED_DRIVES_SOLE = (
    "User,id,name,role\n"
    f"{LEAVER},0AAdrive,Finance,organizer\n"
)
ACL_SOLE_ORGANIZER = (
    "Owner,id,permissions.0.emailAddress,permissions.0.role\n"
    f"{LEAVER},0AAdrive,{LEAVER},organizer\n"
)
ACL_CO_ORGANIZER = (
    "Owner,id,permissions.0.emailAddress,permissions.0.role,"
    "permissions.1.emailAddress,permissions.1.role\n"
    f"{LEAVER},0AAdrive,{LEAVER},organizer,{SUCCESSOR},organizer\n"
)


class ScriptedGam:
    """Stand-in for run_gam that answers by argv prefix and records every call.

    Rules are (prefix tuple, response); a response is (ok, output) or a
    callable(args) returning one, so a rule can be stateful (the suspension
    flag flips when `suspended on/off` is issued). Unmatched commands succeed
    with empty output, which is what every read the script does not parse
    needs. Tracks suspension state so `info user quick` answers honestly.
    """

    def __init__(self, suspended=False, admin=False, enrolled_2sv=False):
        self.calls = []
        self.suspended = suspended
        self.admin = admin
        self.enrolled_2sv = enrolled_2sv
        self.rules = []
        self.on_call = None  # optional hook(args) -> None, after recording

    def rule(self, prefix, response):
        self.rules.append((tuple(prefix), response))
        return self

    def argv(self):
        return [" ".join(a) for a, _ in self.calls]

    def writes(self):
        """argv of every state-changing command issued for real (dry_run=False)."""
        out = []
        for a, kw in self.calls:
            if kw.get("dry_run", True) or {"show", "print", "info"} & set(a):
                continue
            if a[0] in ("update", "delete", "create") or any(
                    t in a for t in ("deprovision", "signout", "turnoff2sv",
                                     "forward", "vacation", "transfer",
                                     "add", "delete")):
                out.append(" ".join(a))
        return out

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        if self.on_call:
            self.on_call(args)
        if kwargs.get("dry_run", True):
            # The real run_gam returns before executing anything in dry run.
            return True, ""
        for prefix, response in self.rules:
            if tuple(args[:len(prefix)]) == prefix:
                return response(args) if callable(response) else response
        # Stateful suspension so read-backs see what the run did.
        if args[:2] == ["update", "user"] and "suspended" in args:
            self.suspended = args[args.index("suspended") + 1] == "on"
            return True, "Updated"
        if args[:2] == ["info", "user"] and args[-1] == "quick":
            return True, quick_fields(**{
                "Account Suspended": str(self.suspended),
                "Is a Super Admin": str(self.admin),
                "2-step enrolled": str(self.enrolled_2sv),
            })
        if args[:2] == ["info", "user"]:
            return True, quick_fields() + fixture("info_user_licences_block")
        if args == ["info", "domain"]:
            return True, "Customer ID: C000\nPrimary Domain: yourdomain.com"
        if args[:1] == ["version"]:
            return True, "GAM 7.48.01"
        if "shareddrives" in args:
            return True, "User,id,name,role\n"
        if "gmailprofile" in args:
            return True, f"User: {args[1]}, Gmail Profile: ok"
        return True, ""


class FakePopen:
    """What _stream_process needs from a child: stdout.read(n), wait, returncode."""

    def __init__(self, text="", returncode=0):
        self.stdout = io.StringIO(text)
        self.returncode = returncode

    def wait(self):
        return self.returncode

    def terminate(self):
        pass


class FakeCompleted:
    def __init__(self, stdout="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, "", returncode


class MainFlowCase(unittest.TestCase):
    """Runs main() with everything external faked; each test scripts its own gam."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        offb.logger = logging.getLogger("offboard-main-test")
        offb.logger.handlers[:] = [logging.NullHandler()]
        offb.logger.propagate = False
        for lst in (offb.summary_actions, offb.summary_skipped,
                    offb.summary_errors, offb.summary_warnings, offb.phase_timings):
            del lst[:]
        offb.exit_code = 0
        offb.shutdown_requested = False
        offb.no_suspend_contract_waived = False
        offb._resuspend_email = None
        offb.BACKUP_DIRECTORY = Path("./offboarding_backups")
        self.atexit_handlers = []
        self.popen_factory = lambda cmd, **kw: FakePopen(
            "Got 1 Drive Files/Folders\nOwnership Transferred to User: ok\n", 0)
        self.gyb_calls = []
        self.inputs = []

    def run_main(self, gam, *argv, gyb_ok=True, popen=None, inputs=()):
        """Invoke main() with argv; returns the SystemExit code."""
        self.inputs = list(inputs)
        full_argv = ["offboard_user.py", *argv,
                     "--backup-dir", str(self.tmp / "bk"),
                     "--log-dir", str(self.tmp / "logs")]

        def fake_gyb(args, dry_run=True, **kw):
            # Like the real run_gyb: a dry-run call only logs the command.
            if not dry_run:
                self.gyb_calls.append(list(args))
                if "backup" in args and "--local-folder" in args:
                    # Real GYB always leaves msg-db.sqlite; verification now
                    # treats a missing one as a failed backup.
                    folder = Path(args[args.index("--local-folder") + 1])
                    folder.mkdir(parents=True, exist_ok=True)
                    with contextlib.closing(sqlite3.connect(folder / "msg-db.sqlite")) as db:
                        db.execute("CREATE TABLE IF NOT EXISTS messages "
                                   "(message_filename TEXT, message_internaldate TEXT)")
                        db.commit()
            return (True, "") if gyb_ok else (False, "gyb failed")

        def fake_run(cmd, *a, **kw):
            if cmd[:1] == ["rclone"]:
                return FakeCompleted("workspace:\n", 0)
            return FakeCompleted("", 0)  # gyb quota probe

        def fake_input(prompt=""):
            if not self.inputs:
                raise EOFError
            return self.inputs.pop(0)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(offb, "run_gam", gam))
            stack.enter_context(mock.patch.object(offb, "run_gyb", fake_gyb))
            stack.enter_context(mock.patch.object(offb.subprocess, "run", fake_run))
            stack.enter_context(mock.patch.object(
                offb.subprocess, "Popen", popen or self.popen_factory))
            stack.enter_context(mock.patch.object(offb.shutil, "which", lambda n: f"/bin/{n}"))
            stack.enter_context(mock.patch.object(offb, "check_for_updates", lambda: None))
            stack.enter_context(mock.patch.object(offb, "install_signal_handlers", lambda: None))
            stack.enter_context(mock.patch.object(offb, "configure_colours", lambda: None))
            stack.enter_context(mock.patch.object(
                offb, "setup_logging", lambda *a, **k: offb.logger))
            stack.enter_context(mock.patch.object(
                offb.atexit, "register", lambda fn, *a: self.atexit_handlers.append((fn, a))))
            stack.enter_context(mock.patch("builtins.input", fake_input))
            stack.enter_context(mock.patch.object(offb.time, "sleep", lambda s: None))
            stack.enter_context(mock.patch.object(offb.sys, "argv", full_argv))
            with self.assertRaises(SystemExit) as cm:
                offb.main()
        return cm.exception.code

    @staticmethod
    def assert_subsequence(needles, haystack):
        """Each needle appears, in order, as a substring of successive haystack items."""
        pos = 0
        for needle in needles:
            while pos < len(haystack) and needle not in haystack[pos]:
                pos += 1
            if pos == len(haystack):
                raise AssertionError(f"{needle!r} not found in order in:\n  " + "\n  ".join(haystack))
            pos += 1


class TestDryRun(MainFlowCase):

    def test_dry_run_default_issues_no_writes_and_creates_no_backup_dir(self):
        gam = ScriptedGam()
        code = self.run_main(gam, "--user", LEAVER, "--force", "--all-transfer-to", SUCCESSOR)
        self.assertEqual(code, 0)
        self.assertEqual(gam.writes(), [])
        self.assertEqual(self.gyb_calls, [], "GYB must not run in a dry run")
        # The snapshot is the one documented write; nothing else under bk/.
        created = sorted(p.relative_to(self.tmp / "bk").parts[0]
                         for p in (self.tmp / "bk").glob("*"))
        self.assertEqual(created, ["snapshots"])


class TestFullRun(MainFlowCase):

    def test_doit_force_full_run_phase_order(self):
        gam = ScriptedGam()
        gam.rule(("user", LEAVER, "show", "forwardingaddresses"),
                 (True, f"  Forwarding Address: {SUCCESSOR}, Verification Status: accepted"))
        gam.rule(("print", "aliases", "user", LEAVER),
                 (True, f"Alias,Target,TargetType\nold.name@yourdomain.com,{LEAVER},User\n"))
        code = self.run_main(gam, "--doit", "--force", "--user", LEAVER,
                             "--all-transfer-to", SUCCESSOR)
        self.assertEqual(code, 0, offb.summary_errors)
        self.assert_subsequence([
            f"info user {LEAVER}",                       # snapshot (full info user)
            f"update user {LEAVER} org /Offboarding",    # kill switch 1
            "recoveryemail",                             # 2
            "deprovision",                               # 3
            f"user {LEAVER} signout",                    # 4
            "password random",                           # 6
            "gal off",                                   # 7
            "print mobile",                              # devices
            f"user {LEAVER} print groups",               # groups
            f"user {LEAVER} show delegates",             # delegates
            f"user {LEAVER} print shareddrives",         # shared drive check
            "delete alias old.name@yourdomain.com",      # aliases
            f"create alias old.name@yourdomain.com user {SUCCESSOR}",
            f"add calendaracls {LEAVER} writer user:{SUCCESSOR}",
            f"add forwardingaddress {SUCCESSOR}",
            f"forward on {SUCCESSOR} keep",
            "vacation on",
            "delete license 1010010001",                 # licences after transfers
            "delete license 1010020020",
            f"update user {LEAVER} suspended on",        # suspension last
        ], gam.argv())
        # Drive transfer and the GYB backup/restore ran in between.
        self.assertTrue(any("--action" in c and "backup" in c for c in self.gyb_calls))
        self.assertTrue(any("restore" in c for c in self.gyb_calls))
        self.assertTrue(any("Email migrated" in a for a in offb.summary_actions))
        self.assertTrue(any("verified by read-back" in a for a in offb.summary_actions))
        self.assertEqual(offb.summary_errors, [])

    def test_licences_come_from_snapshot_not_print_licenses(self):
        gam = ScriptedGam()
        self.run_main(gam, "--doit", "--force", "--user", LEAVER, "--no-transfer")
        self.assertFalse(any("print licenses" in a for a in gam.argv()))
        self.assertEqual(sum(1 for a in gam.argv() if a == f"info user {LEAVER}"), 1)


class TestScorchedEarth(MainFlowCase):

    def _sole_organizer_gam(self, acl=ACL_SOLE_ORGANIZER):
        gam = ScriptedGam()
        gam.rule(("user", LEAVER, "print", "shareddrives"), (True, SHARED_DRIVES_SOLE))
        gam.rule(("user", LEAVER, "print", "drivefileacls"), (True, acl))
        return gam

    def test_refuses_sole_organizer_drive_before_any_change(self):
        gam = self._sole_organizer_gam()
        code = self.run_main(gam, "--doit", "--force", "--scorched-earth",
                             "--user", LEAVER, inputs=[LEAVER])
        self.assertEqual(code, 2)
        self.assertEqual(gam.writes(), [])
        self.assertTrue(any("Scorched earth aborted" in e for e in offb.summary_errors))

    def test_unreadable_acl_also_refuses(self):
        gam = self._sole_organizer_gam()
        gam.rule(("user", LEAVER, "print", "drivefileacls"), (False, "Failed"))
        code = self.run_main(gam, "--doit", "--force", "--scorched-earth",
                             "--user", LEAVER, inputs=[LEAVER])
        self.assertEqual(code, 2)
        self.assertEqual(gam.writes(), [])

    def test_override_deletes_and_never_transfers(self):
        gam = self._sole_organizer_gam()
        code = self.run_main(gam, "--doit", "--force", "--scorched-earth",
                             "--allow-orphaned-shared-drives", "--user", LEAVER,
                             inputs=[LEAVER])
        self.assertEqual(code, 0, offb.summary_errors)
        self.assert_subsequence([
            f"update user {LEAVER} org /Offboarding",
            "password random",
            "print groups",
            "delete license",
            f"update user {LEAVER} suspended on",
            f"delete user {LEAVER}",
        ], gam.argv())
        self.assertFalse(any("transfer drive" in a or "calendaracls" in a
                             or "forward on" in a for a in gam.argv()))
        self.assertEqual(self.gyb_calls, [])
        # The snapshot still ran: it is read-only and the last record of the account.
        self.assertTrue(list((self.tmp / "bk" / "snapshots").glob("*.json")))

    def test_co_organizer_deletes(self):
        gam = self._sole_organizer_gam(ACL_CO_ORGANIZER)
        code = self.run_main(gam, "--doit", "--force", "--scorched-earth",
                             "--user", LEAVER, inputs=[LEAVER])
        self.assertEqual(code, 0, offb.summary_errors)
        self.assertIn(f"delete user {LEAVER}", gam.argv())

    def _refuses_without_delete(self, listing):
        gam = ScriptedGam()
        gam.rule(("user", LEAVER, "print", "shareddrives"), listing)
        code = self.run_main(gam, "--doit", "--force", "--scorched-earth",
                             "--user", LEAVER, inputs=[LEAVER])
        self.assertEqual(code, 2)
        self.assertFalse(any("delete user" in a for a in gam.argv()))
        self.assertEqual(gam.writes(), [])
        self.assertTrue(any("Scorched earth aborted" in e for e in offb.summary_errors))

    def test_failed_shared_drive_listing_refuses(self):
        self._refuses_without_delete((False, "Failed"))

    def test_unparseable_shared_drive_listing_refuses(self):
        self._refuses_without_delete((True, "garbage"))

    def test_genuinely_empty_shared_drive_listing_deletes(self):
        gam = ScriptedGam()
        gam.rule(("user", LEAVER, "print", "shareddrives"),
                 (True, "User,id,name,role\nGot 0 Shared Drives\n"))
        code = self.run_main(gam, "--doit", "--force", "--scorched-earth",
                             "--user", LEAVER, inputs=[LEAVER])
        self.assertEqual(code, 0, offb.summary_errors)
        self.assertIn(f"delete user {LEAVER}", gam.argv())

    def test_wrong_confirmation_email_aborts(self):
        gam = ScriptedGam()
        code = self.run_main(gam, "--doit", "--force", "--scorched-earth",
                             "--user", LEAVER, inputs=["someone.else@yourdomain.com"])
        self.assertEqual(code, 2)
        self.assertEqual(gam.writes(), [])


class TestContainment(MainFlowCase):

    def test_no_suspend_overridden_when_containment_fails(self):
        gam = ScriptedGam()
        gam.rule(("update", "user", LEAVER, "password"), (False, "Update Failed"))
        code = self.run_main(gam, "--doit", "--force", "--no-suspend", "--no-transfer",
                             "--user", LEAVER)
        self.assertEqual(code, 1)
        self.assertIn(f"update user {LEAVER} suspended on", gam.argv())
        self.assertTrue(any("--no-suspend overridden" in w for w in offb.summary_warnings))
        self.assertTrue(any("CONTAINMENT INCOMPLETE" in e for e in offb.summary_errors))

    def test_ctrl_c_during_kill_switch_still_completes_containment(self):
        gam = ScriptedGam()

        def interrupt_after_ou_move(args):
            if args[:4] == ["update", "user", LEAVER, "org"]:
                offb.shutdown_requested = True
        gam.on_call = interrupt_after_ou_move
        code = self.run_main(gam, "--doit", "--force", "--no-transfer", "--user", LEAVER)
        self.assert_subsequence([
            f"update user {LEAVER} org /Offboarding", "recoveryemail", "deprovision",
            f"user {LEAVER} signout", "password random", "gal off",
        ], gam.argv())
        # Contained, so the run stopped at the checkpoint after the kill switch
        # without touching groups or licences.
        self.assertFalse(any("delete groups" in a or "delete license" in a for a in gam.argv()))
        self.assertEqual(code, 0, offb.summary_errors)

    def test_ctrl_c_with_failed_containment_suspends_before_exit(self):
        gam = ScriptedGam()
        gam.rule(("update", "user", LEAVER, "password"), (False, "Update Failed"))

        def interrupt_after_ou_move(args):
            if args[:4] == ["update", "user", LEAVER, "org"]:
                offb.shutdown_requested = True
        gam.on_call = interrupt_after_ou_move
        code = self.run_main(gam, "--doit", "--force", "--no-transfer", "--user", LEAVER)
        self.assertIn(f"update user {LEAVER} suspended on", gam.argv())
        self.assertEqual(code, 1)


class TestLicenceHold(MainFlowCase):

    def test_transfer_failure_holds_licence_but_still_suspends(self):
        gam = ScriptedGam()
        failing = lambda cmd, **kw: FakePopen("Got 1 Drive Files/Folders\nAPI error\n", 1)
        code = self.run_main(gam, "--doit", "--force", "--user", LEAVER,
                             "--drive-to", SUCCESSOR, "--no-email", "--no-alias",
                             "--no-calendar", "--no-forward", popen=failing)
        self.assertEqual(code, 1)
        self.assertFalse(any("delete license" in a for a in gam.argv()))
        self.assertIn(f"update user {LEAVER} suspended on", gam.argv())
        self.assertTrue(any("held back by failed phase(s): Drive transfer" in s
                            for s in offb.summary_skipped))

    def test_short_email_backup_skips_restore_and_holds_licence(self):
        gam = ScriptedGam()
        # A msg-db that lists a message with no .eml on disk: the backup is short.
        bk = self.tmp / "bk" / "mailboxes"
        bk.mkdir(parents=True)
        real_migrate = offb.migrate_email

        def plant_short_db(*a, **kw):
            # migrate_email picks the folder; plant the DB the moment it exists.
            folder = offb._select_email_backup_path(LEAVER, force=True)
            folder.mkdir(parents=True, exist_ok=True)
            db = sqlite3.connect(folder / "msg-db.sqlite")
            db.execute("CREATE TABLE messages (message_filename TEXT, message_internaldate TEXT)")
            db.execute("INSERT INTO messages VALUES ('2026/1/a.eml', '2026-01-01')")
            db.commit(); db.close()
            return real_migrate(*a, **kw)
        with mock.patch.object(offb, "migrate_email", plant_short_db):
            code = self.run_main(gam, "--doit", "--force", "--user", LEAVER,
                                 "--email-to", SUCCESSOR, "--no-drive", "--no-alias",
                                 "--no-calendar", "--no-forward")
        self.assertEqual(code, 1)
        self.assertFalse(any("restore" in c for c in self.gyb_calls), "restore must not run on a short backup")
        self.assertFalse(any("Email migrated" in a for a in offb.summary_actions))
        self.assertFalse(any("delete license" in a for a in gam.argv()))


class TestTemporaryUnsuspend(MainFlowCase):

    def test_completed_run_resuspends_and_records_it_once_verified(self):
        gam = ScriptedGam(suspended=True)
        code = self.run_main(gam, "--doit", "--force", "--unsuspend", "--no-transfer",
                             "--user", LEAVER)
        self.assertEqual(code, 0, offb.summary_errors)
        self.assert_subsequence([f"update user {LEAVER} suspended off",
                                 "password random",
                                 f"update user {LEAVER} suspended on"], gam.argv())
        self.assertTrue(any("Re-suspended (restored original state)" in a
                            for a in offb.summary_actions))
        self.assertTrue(gam.suspended)

    def test_failed_resuspend_is_not_reported_as_resuspended(self):
        gam = ScriptedGam(suspended=True)

        def lying_update(args):
            # 'Updated' but the state never flips back to suspended.
            if args[-1] == "off":
                gam.suspended = False
            return True, "Updated"
        gam.rule(("update", "user", LEAVER, "suspended"), lying_update)
        with mock.patch.object(offb.time, "time", side_effect=[i * 10.0 for i in range(10000)]):
            code = self.run_main(gam, "--doit", "--force", "--unsuspend", "--no-transfer",
                                 "--user", LEAVER)
        self.assertEqual(code, 1)
        self.assertFalse(any("Re-suspended" in a for a in offb.summary_actions))
        self.assertTrue(any("NOT verified" in e or "NOT restored" in e
                            for e in offb.summary_errors))

    def test_crash_mid_run_resuspends_via_atexit_even_after_ctrl_c(self):
        gam = ScriptedGam(suspended=True)
        with mock.patch.object(offb, "manage_devices", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_main(gam, "--doit", "--force", "--unsuspend", "--no-transfer",
                              "--user", LEAVER)
        self.assertFalse(gam.suspended, "precondition: the run had unsuspended the account")
        self.assertEqual(len(self.atexit_handlers), 1)
        fn, args = self.atexit_handlers[0]
        # The old guard could never run after Ctrl+C: every gam call it made
        # returned "Shutdown requested". Prove it works with the flag set.
        offb.shutdown_requested = True
        with mock.patch.object(offb, "run_gam", gam), \
                mock.patch.object(offb.time, "sleep", lambda s: None):
            self.assertTrue(fn(*args))
        self.assertTrue(gam.suspended)
        self.assertIn(f"update user {LEAVER} suspended on", gam.argv())

    def test_unsuspend_flag_with_no_suspend_is_refused_at_parse_time(self):
        gam = ScriptedGam(suspended=True)
        code = self.run_main(gam, "--doit", "--force", "--unsuspend", "--no-suspend",
                             "--no-transfer", "--user", LEAVER)
        self.assertEqual(code, 2)
        self.assertEqual(gam.calls, [])

    def test_interactive_no_suspend_completion_waives_the_guard(self):
        # Without --force the unsuspend comes from the prompt, so --no-suspend
        # can reach the end of the run: that is the operator's informed choice
        # and the guard stands down instead of re-suspending behind their back.
        gam = ScriptedGam(suspended=True)
        code = self.run_main(gam, "--doit", "--no-suspend", "--no-transfer",
                             "--user", LEAVER,
                             inputs=["y",   # temporarily unsuspend?
                                     "y",   # are you sure you want to proceed?
                                     "y"])  # proceed with this plan?
        self.assertEqual(code, 0, offb.summary_errors)
        self.assertFalse(gam.suspended)
        self.assertTrue(offb.no_suspend_contract_waived)
        self.assertTrue(any("CONTRACT VIOLATION" in w for w in offb.summary_warnings))
        fn, args = self.atexit_handlers[0]
        with mock.patch.object(offb, "run_gam", gam):
            self.assertTrue(fn(*args))
        self.assertFalse(gam.suspended)


class TestRestoreOnly(MainFlowCase):

    def test_reuse_email_backup_runs_only_the_restore(self):
        gam = ScriptedGam()
        backup = self.tmp / "old_backup"
        backup.mkdir()
        db = sqlite3.connect(backup / "msg-db.sqlite")
        db.execute("CREATE TABLE messages (message_filename TEXT, message_internaldate TEXT)")
        db.commit(); db.close()
        code = self.run_main(gam, "--doit", "--force", "--user", LEAVER,
                             "--reuse-email-backup", str(backup), "--email-to", SUCCESSOR)
        self.assertEqual(code, 0, offb.summary_errors)
        self.assertEqual(gam.writes(), [])
        self.assertTrue(any("restore" in c and "--local-folder" in c for c in self.gyb_calls))
        self.assertFalse(any("backup" in c for c in self.gyb_calls))

    def test_reuse_email_backup_refuses_the_leaver_as_destination(self):
        gam = ScriptedGam()
        backup = self.tmp / "old_backup"
        backup.mkdir()
        code = self.run_main(gam, "--doit", "--force", "--user", LEAVER,
                             "--reuse-email-backup", str(backup), "--email-to", LEAVER)
        self.assertEqual(code, 2)
        self.assertEqual(self.gyb_calls, [])


class TestAdminGate(MainFlowCase):

    def test_admin_account_blocks_before_any_write(self):
        gam = ScriptedGam(admin=True)
        code = self.run_main(gam, "--doit", "--force", "--no-transfer", "--user", LEAVER)
        self.assertEqual(code, 1)
        self.assertEqual(gam.writes(), [])
        self.assertTrue(any("administrator privileges" in e for e in offb.summary_errors))

    def test_allow_admin_account_proceeds_with_a_warning(self):
        gam = ScriptedGam(admin=True)
        code = self.run_main(gam, "--doit", "--force", "--no-transfer",
                             "--allow-admin-account", "--user", LEAVER)
        self.assertEqual(code, 0, offb.summary_errors)
        self.assertIn(f"update user {LEAVER} suspended on", gam.argv())
        self.assertTrue(any("OVERRIDDEN" in w for w in offb.summary_warnings))


class TestAliasInput(MainFlowCase):
    ALIAS = "old.alias@yourdomain.com"

    def test_alias_input_runs_every_write_on_the_primary(self):
        gam = ScriptedGam()  # `info user <anything> quick` answers "User: LEAVER"
        gam.rule(("user", LEAVER, "show", "forwardingaddresses"),
                 (True, f"  Forwarding Address: {SUCCESSOR}, Verification Status: accepted"))
        code = self.run_main(gam, "--doit", "--force", "--user", self.ALIAS,
                             "--all-transfer-to", SUCCESSOR)
        self.assertEqual(code, 0, offb.summary_errors)
        self.assertIn(f"update user {LEAVER} suspended on", gam.argv())
        self.assertTrue(gam.writes())
        for cmd in gam.writes():
            self.assertNotIn(self.ALIAS, cmd, cmd)

    def test_alias_input_scorched_earth_deletes_the_primary(self):
        gam = ScriptedGam()
        code = self.run_main(gam, "--doit", "--force", "--scorched-earth",
                             "--user", self.ALIAS, inputs=[LEAVER])
        self.assertEqual(code, 0, offb.summary_errors)
        self.assertIn(f"delete user {LEAVER}", gam.argv())
        self.assertFalse(any(self.ALIAS in a for a in gam.argv()
                             if not a.startswith("info user")))

    def test_unreadable_primary_refuses_before_any_write(self):
        gam = ScriptedGam()
        gam.rule(("info", "user", self.ALIAS, "quick"),
                 (True, "  Settings:\n    Full Name: X\n"))
        code = self.run_main(gam, "--doit", "--force", "--no-transfer",
                             "--user", self.ALIAS)
        self.assertEqual(code, 2)
        self.assertEqual(gam.writes(), [])


class TestFailedReads(MainFlowCase):

    def test_failed_group_listing_is_an_error_not_no_groups(self):
        gam = ScriptedGam()
        gam.rule(("user", LEAVER, "print", "groups"), (False, "Timeout"))
        code = self.run_main(gam, "--doit", "--force", "--no-transfer", "--user", LEAVER)
        self.assertEqual(code, 1)
        self.assertFalse(any("delete groups" in a for a in gam.argv()))
        self.assertFalse(any("No group memberships" in a for a in offb.summary_actions))
        self.assertTrue(any("Group listing failed" in e for e in offb.summary_errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
