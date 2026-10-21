#!/usr/bin/env python3
"""
Offline unit tests for offboard_user.py.

Stdlib only (unittest + unittest.mock). Every GAM/GYB/rclone call is stubbed:
setUpModule replaces subprocess.run and subprocess.Popen with a function that
raises, so a test that reaches a real child process fails instead of touching
a tenant. Run before AND after every change to offboard_user.py:

    python3 test_offboard_user.py -v

Organised by feature. Each ported test keeps its original bug/round ID in the
docstring ("Was A2_3.") so the history in the release notes stays traceable.
GAM output comes from fixtures/gam7_*.txt, captured live on GAM 7.48.01; the
first line of each is a comment header and is stripped by fixture().
"""

import argparse
import builtins
import contextlib
import importlib.util
import io
import json
import logging
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

SCRIPT_PATH = Path(__file__).parent / "offboard_user.py"
FIXTURE_DIR = Path(__file__).parent / "fixtures"

# Import offboard_user.py as a module despite spaces in the folder path.
_spec = importlib.util.spec_from_file_location("offboard_user", SCRIPT_PATH)
offb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(offb)

U = "leaver@yourdomain.com"
D = "successor@yourdomain.com"


###############################################################################
# Helpers
###############################################################################

def fixture(name: str) -> str:
    """Captured GAM 7.48.01 output, minus the comment header on line 1."""
    text = (FIXTURE_DIR / f"gam7_{name}.txt").read_text(encoding="utf-8")
    return text.split("\n", 1)[1]


def stdout_only(text: str) -> str:
    """What run_gam(stdout_only=True) hands the caller.

    The fixtures merge stderr into stdout; GAM writes its "Getting ..." /
    "Got N ..." progress there, so those lines (and the blank ones between
    them) never reach a stdout_only caller.
    """
    return "\n".join(
        line for line in text.splitlines()
        if line.strip() and not line.startswith(("Getting ", "Got "))
    )


class FakeGam:
    """Stand-in for run_gam.

    rules: [(prefix_tuple, result), ...]. The first rule whose prefix equals
    args[:len(prefix)] wins; result is (ok, output) or a callable
    (args, kwargs) -> (ok, output). No match returns (True, ""). Every call is
    recorded in self.calls as (args, kwargs).

    Two parts of run_gam's contract are mirrored because phases depend on
    them: a dry-run call (dry_run defaults to True) returns (True, "")
    without matching a rule, and once offb.shutdown_requested is set a call
    without bypass_shutdown=True gets (False, "Shutdown requested") — so a
    phase that must finish after Ctrl+C fails its test if it forgets the flag.
    """

    def __init__(self, rules=()):
        self.rules = list(rules)
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        if kwargs.get("dry_run", True):
            return True, ""
        if offb.shutdown_requested and not kwargs.get("bypass_shutdown"):
            return False, "Shutdown requested"
        for prefix, result in self.rules:
            if tuple(args[:len(prefix)]) == tuple(prefix):
                return result(args, kwargs) if callable(result) else result
        return True, ""

    def argv(self):
        return [" ".join(a) for a, _ in self.calls]

    def matching(self, *prefix):
        """argv entries that start with the given words."""
        head = " ".join(prefix)
        return [a for a in self.argv() if a == head or a.startswith(head + " ")]


def gam(fake):
    return mock.patch.object(offb, "run_gam", fake)


class _FakeClock:
    """Deterministic time.time()/time.sleep() so the poll loops are instant."""

    def __init__(self):
        self.now = 1000.0

    def time(self):
        self.now += 5.0
        return self.now

    def sleep(self, secs):
        self.now += secs


@contextlib.contextmanager
def clocked():
    clock = _FakeClock()
    with mock.patch("time.time", clock.time), \
         mock.patch("time.sleep", clock.sleep):
        yield clock


def msg_db(backup: Path, rows):
    """Create GYB's msg-db.sqlite with one messages row per (filename, date)."""
    backup.mkdir(parents=True, exist_ok=True)
    with offb._gyb_db(backup / "msg-db.sqlite") as db:
        db.execute("CREATE TABLE messages(message_num INTEGER PRIMARY KEY, "
                   "message_filename TEXT, message_internaldate TIMESTAMP)")
        db.executemany("INSERT INTO messages VALUES (?,?,?)",
                       [(i, f, d) for i, (f, d) in enumerate(rows, 1)])


def restored_db(backup: Path, destination: str, count: int):
    """Create GYB's <dest>-restored.sqlite resume DB with `count` rows."""
    with offb._gyb_db(backup / f"{destination}-restored.sqlite") as db:
        db.execute("CREATE TABLE restored_messages(message_num INTEGER PRIMARY KEY)")
        db.executemany("INSERT INTO restored_messages VALUES (?)",
                       [(i,) for i in range(1, count + 1)])


def fake_popen(text: str, returncode: int):
    """Patch subprocess.Popen with a child whose merged output is `text`.

    _stream_process reads stdout in 256-byte chunks, so the fake's stdout is
    a StringIO rather than a line iterator.
    """
    proc = mock.MagicMock()
    proc.stdout = io.StringIO(text)
    proc.returncode = returncode
    return mock.patch.object(offb.subprocess, "Popen", return_value=proc)


@contextlib.contextmanager
def unreadable(path):
    """Make ONE file raise PermissionError on open, on any OS.

    chmod(0o000) does not remove read access on Windows, so the AV-lock
    simulation silently did nothing there (2026-07-29). Patch the read
    itself, which is what an AV lock actually does to us.
    """
    real_open = builtins.open

    def fake_open(file, *args, **kwargs):
        try:
            same = Path(file) == Path(path)
        except TypeError:
            same = False
        if same:
            raise PermissionError(13, "Permission denied")
        return real_open(file, *args, **kwargs)

    with mock.patch("builtins.open", fake_open):
        yield


_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen
_SUBPROCESS_GUARDS = []
_TEST_LOGGER = logging.getLogger("offboard-test")
_TEST_LOGGER.addHandler(logging.NullHandler())
_TEST_LOGGER.propagate = False


def _no_subprocess(*_args, **_kwargs):
    raise AssertionError("test reached a real subprocess")


def setUpModule():
    offb.logger = _TEST_LOGGER
    for name in ("run", "Popen"):
        guard = mock.patch.object(offb.subprocess, name, _no_subprocess)
        guard.start()
        _SUBPROCESS_GUARDS.append(guard)


def tearDownModule():
    for guard in _SUBPROCESS_GUARDS:
        guard.stop()


@contextlib.contextmanager
def real_subprocess():
    """Opt one test back in to real child processes."""
    with mock.patch.object(offb.subprocess, "run", _REAL_RUN), \
         mock.patch.object(offb.subprocess, "Popen", _REAL_POPEN):
        yield


class OffboardTestCase(unittest.TestCase):
    """Common reset of the module's global run state."""

    def setUp(self):
        offb.logger = _TEST_LOGGER
        del offb.summary_actions[:]
        del offb.summary_skipped[:]
        del offb.summary_errors[:]
        del offb.summary_warnings[:]
        del offb.phase_timings[:]
        offb.exit_code = 0
        offb.shutdown_requested = False
        offb.no_suspend_contract_waived = False
        offb._resuspend_email = None

    def tearDown(self):
        # run_gam and the streaming phases swallow exceptions into the summary,
        # so the subprocess guard's AssertionError would otherwise be silent.
        leaked = [e for e in offb.summary_errors if "real subprocess" in e]
        self.assertFalse(leaked, f"a test reached a real subprocess: {leaked}")
        offb.shutdown_requested = False

    def actions(self):
        return "\n".join(offb.summary_actions)

    def tmpdir(self) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Path(tmp.name)


ACTIVE_USER = fixture("info_user_quick_cloud_identity")
SUSPENDED_USER = fixture("info_user_quick_suspended")


def quick_gam(output, ok=True):
    """FakeGam answering every `info user ...` with one canned output."""
    return FakeGam([(("info", "user"), (ok, output))])


class _Args:
    """Minimal stand-in for the argparse namespace preflight_destinations reads."""
    def __init__(self, **kw):
        self.no_drive = self.no_email = self.no_alias = False
        self.no_calendar = self.no_forward = False
        self.drive_to = self.email_to = self.alias_to = None
        self.calendar_to = self.forward_to = None
        self.all_transfer_to = None
        self.force = True
        self.__dict__.update(kw)


class _PlanArgs(_Args):
    """argparse stand-in for collect_plan: adds the skip flags it reads."""
    def __init__(self, **kw):
        super().__init__()
        self.no_auto_reply = self.no_suspend = False
        self.strip_labels = True
        self.__dict__.update(kw)


###############################################################################
# User verification and suspension reads
###############################################################################

class TestUserVerification(OffboardTestCase):

    def test_active_user_fields_parsed_from_quick_output(self):
        """Was A8_1."""
        fake = quick_gam(ACTIVE_USER)
        with gam(fake):
            info = offb.verify_user(U)
        self.assertEqual(fake.argv(), [f"info user {U} quick"])
        self.assertEqual(info["_is_suspended"], "False")
        self.assertEqual(info["_is_admin"], "False")
        self.assertEqual(info["2-step enrolled"].lower(), "false")
        self.assertEqual(info["full name"], "NoLic Receiver")
        self.assertFalse(offb.summary_warnings)

    def test_suspended_user_is_flagged_with_a_warning(self):
        """Was A8_2."""
        with gam(quick_gam(SUSPENDED_USER)):
            info = offb.verify_user(U)
        self.assertEqual(info["_is_suspended"], "True")
        self.assertTrue(any("already suspended" in w.lower()
                            for w in offb.summary_warnings))

    def test_unreadable_user_is_none_and_a_summary_error(self):
        with gam(quick_gam("", ok=False)):
            self.assertIsNone(offb.verify_user(U))
        self.assertTrue(any("verification failed" in e.lower()
                            for e in offb.summary_errors))

    def test_delegated_admin_sets_the_admin_flag_without_warning(self):
        # The gate reports admin roles; verify_user only records the fact.
        admin = ACTIVE_USER.replace("Is Delegated Admin: False",
                                    "Is Delegated Admin: True")
        with gam(quick_gam(admin)):
            info = offb.verify_user(U)
        self.assertEqual(info["_is_admin"], "True")
        self.assertFalse(offb.summary_warnings)

    def test_read_suspended_matches_the_field_not_the_word(self):
        """Was B15_1."""
        with gam(quick_gam(SUSPENDED_USER)):
            self.assertIs(offb.read_suspended(U), True)
        surnamed = ACTIVE_USER.replace("Last Name: Receiver", "Last Name: Suspended")
        with gam(quick_gam(surnamed)):
            self.assertIs(offb.read_suspended(U), False)

    def test_read_suspended_is_none_when_the_read_fails(self):
        """Was B15_2."""
        with gam(quick_gam("", ok=False)):
            self.assertIsNone(offb.read_suspended(U))

    def test_wait_for_suspended_gives_up_at_the_timeout(self):
        """Was B15_3."""
        with gam(quick_gam(ACTIVE_USER)), clocked():
            self.assertFalse(offb.wait_for_suspended(U, True, timeout=30))

    def test_wait_for_suspended_stops_on_shutdown_unless_bypassed(self):
        fake = quick_gam(ACTIVE_USER)
        offb.shutdown_requested = True
        with gam(fake), clocked():
            self.assertFalse(offb.wait_for_suspended(U, True, timeout=60))
        self.assertEqual(len(fake.calls), 1, "must not keep polling after Ctrl+C")

        fake = quick_gam(ACTIVE_USER)
        with gam(fake), clocked():
            self.assertFalse(offb.wait_for_suspended(U, True, timeout=60,
                                                     bypass_shutdown=True))
        self.assertGreater(len(fake.calls), 1, "bypass must poll to the deadline")

    def test_force_alone_never_unsuspends(self):
        """Was A4_1: --force must not imply --unsuspend."""
        self.assertFalse(offb.decide_unsuspend(force=True, unsuspend_flag=False,
                                               prompt_fn=lambda: True))
        self.assertTrue(offb.decide_unsuspend(force=True, unsuspend_flag=True,
                                              prompt_fn=lambda: False))

    def test_interactive_prompt_is_asked_without_force(self):
        """Was A4_2."""
        asked = []
        self.assertTrue(offb.decide_unsuspend(force=False, unsuspend_flag=False,
                                              prompt_fn=lambda: asked.append(1) or True))
        self.assertEqual(asked, [1])


###############################################################################
# Admin account gate
###############################################################################

class TestAdminGate(OffboardTestCase):

    ADMIN = {"_is_admin": "True"}
    USER = {"_is_admin": "False"}

    def test_admin_is_blocked_by_default(self):
        """Was B18_1."""
        with self.assertRaises(offb.AdminAccountSafetyError):
            offb.enforce_admin_account_gate(U, self.ADMIN, allow_admin_account=False)

    def test_force_is_not_an_argument_of_the_gate(self):
        """Was B18_2: --force must not be able to bypass it."""
        import inspect
        self.assertNotIn("force", inspect.signature(
            offb.enforce_admin_account_gate).parameters)

    def test_dedicated_override_allows_admin_with_a_warning(self):
        """Was B18_3."""
        offb.enforce_admin_account_gate(U, self.ADMIN, allow_admin_account=True)
        self.assertTrue(any("OVERRIDDEN" in w for w in offb.summary_warnings))

    def test_normal_user_passes_quietly(self):
        """Was B18_4."""
        with mock.patch.object(offb, "print_error") as printed:
            offb.enforce_admin_account_gate(U, self.USER, allow_admin_account=False)
        printed.assert_not_called()
        self.assertFalse(offb.summary_warnings)

    def test_remediation_names_the_role_assignment_commands(self):
        """Was B18_5."""
        printed = []
        with mock.patch.object(offb, "print_error", printed.append):
            with self.assertRaises(offb.AdminAccountSafetyError):
                offb.enforce_admin_account_gate(U, self.ADMIN, allow_admin_account=False)
        output = "\n".join(printed)
        self.assertIn(f"gam print admins user {U}", output)
        self.assertIn("gam delete admin <roleAssignmentId>", output)


###############################################################################
# Destination and dependency preflight
###############################################################################

class TestDestinationPreflight(OffboardTestCase):

    def test_suspended_destination_is_rejected(self):
        """Was B5_1."""
        with gam(quick_gam(SUSPENDED_USER)):
            self.assertFalse(offb.validate_destination(D))

    def test_destination_surnamed_suspended_is_not_a_false_positive(self):
        """Was B5_2: "Last Name: Suspended" must not trip the field check."""
        surnamed = ACTIVE_USER.replace("Last Name: Receiver", "Last Name: Suspended")
        with gam(quick_gam(surnamed)):
            self.assertTrue(offb.validate_destination(D))

    def test_group_destination_is_accepted_only_for_forwarding(self):
        fake = FakeGam([(("info", "user"), (False, "Does not exist")),
                        (("info", "group"), (True, "Group: team@yourdomain.com"))])
        with gam(fake):
            self.assertTrue(offb.validate_destination("team@yourdomain.com",
                                                      allow_group=True))
            self.assertFalse(offb.validate_destination("team@yourdomain.com"))
        self.assertTrue(any("Destination not found" in e for e in offb.summary_errors))

    def test_self_transfer_is_refused(self):
        """Was B10_1."""
        args = _Args(all_transfer_to=U)
        with mock.patch.object(offb, "_list_aliases", return_value=[]), \
             mock.patch.object(offb, "validate_destination", return_value=True):
            with self.assertRaises(SystemExit) as cm:
                offb.preflight_destinations(args, source=U)
        self.assertEqual(cm.exception.code, 2)

    def test_self_transfer_is_caught_regardless_of_case(self):
        """Was B10_2."""
        args = _Args(all_transfer_to="Leaver@YourDomain.com")
        with mock.patch.object(offb, "_list_aliases", return_value=[]), \
             mock.patch.object(offb, "validate_destination", return_value=True):
            with self.assertRaises(SystemExit):
                offb.preflight_destinations(args, source=U)

    def test_one_self_targeted_phase_is_enough_to_refuse(self):
        """Was B10_3."""
        args = _Args(all_transfer_to=D, forward_to=U)
        with mock.patch.object(offb, "_list_aliases", return_value=[]), \
             mock.patch.object(offb, "validate_destination", return_value=True):
            with self.assertRaises(SystemExit):
                offb.preflight_destinations(args, source=U)

    def test_a_real_successor_passes(self):
        """Was B10_4."""
        args = _Args(all_transfer_to=D)
        with gam(FakeGam()), \
             mock.patch.object(offb, "_list_aliases", return_value=[]), \
             mock.patch.object(offb, "validate_destination", return_value=True):
            got = offb.preflight_destinations(args, source=U)
        self.assertEqual(got["drive"], D)
        self.assertEqual(got["email"], D)

    def test_no_source_skips_the_self_check(self):
        """Was B10_5."""
        args = _Args(all_transfer_to=U)
        with gam(FakeGam()), \
             mock.patch.object(offb, "validate_destination", return_value=True):
            got = offb.preflight_destinations(args)
        self.assertEqual(got["drive"], U)

    def test_an_alias_of_the_leaver_is_caught(self):
        """Was B10_6: a different address, the same mailbox."""
        args = _Args(all_transfer_to="l.old@yourdomain.com")
        with mock.patch.object(offb, "_list_aliases", return_value=["l.old@yourdomain.com"]), \
             mock.patch.object(offb, "validate_destination", return_value=True):
            with self.assertRaises(SystemExit) as cm:
                offb.preflight_destinations(args, source=U)
        self.assertEqual(cm.exception.code, 2)

    def test_alias_lookup_is_skipped_when_nothing_is_targeted(self):
        """Was B10_7."""
        args = _Args(no_drive=True, no_email=True, no_alias=True,
                     no_calendar=True, no_forward=True)
        with mock.patch.object(offb, "_list_aliases") as la:
            offb.preflight_destinations(args, source=U)
        la.assert_not_called()

    def test_preflight_blocks_a_mailboxless_email_destination(self):
        """Was B19_2: gam exits non-zero for the unlicensed user, and the
        'not enabled' text must still block the restore."""
        args = _Args(no_drive=True, no_alias=True, no_calendar=True,
                     no_forward=True, email_to=D)
        fake = FakeGam([
            (("user", D, "show", "gmailprofile"),
             (False, fixture("show_gmailprofile_not_enabled"))),
            (("info", "user"), (True, ACTIVE_USER)),
        ])
        with gam(fake):
            with self.assertRaises(SystemExit) as cm:
                offb.preflight_destinations(args, source=U)
        self.assertEqual(cm.exception.code, 2)

    def test_typed_alias_of_the_leaver_is_refused_then_reasked(self):
        """Was B20_1."""
        with mock.patch.object(offb, "prompt_email",
                               side_effect=["leaver.alias@yourdomain.com", D]), \
             mock.patch.object(offb, "validate_destination", return_value=True), \
             mock.patch.object(offb, "_list_aliases",
                               return_value=["leaver.alias@yourdomain.com"]):
            self.assertEqual(offb._plan_email("Email dest", source=U), D)

    def test_typed_leaver_literal_is_refused(self):
        """Was B20_2."""
        with mock.patch.object(offb, "prompt_email",
                               side_effect=["LEAVER@yourdomain.com", D]), \
             mock.patch.object(offb, "validate_destination", return_value=True), \
             mock.patch.object(offb, "_list_aliases", return_value=[]):
            self.assertEqual(offb._plan_email("Drive dest", source=U), D)

    def test_typed_mailboxless_email_destination_is_refused_then_reasked(self):
        """Was B20_3."""
        with mock.patch.object(offb, "prompt_email",
                               side_effect=["nolic@yourdomain.com", D]), \
             mock.patch.object(offb, "validate_destination", return_value=True), \
             mock.patch.object(offb, "_list_aliases", return_value=[]), \
             mock.patch.object(offb, "_email_mailbox_missing",
                               side_effect=["Gmail service not enabled", None]):
            got = offb._plan_email("Email dest", source=U, needs_mailbox=True)
        self.assertEqual(got, D)

    def test_mailbox_probe_not_run_for_non_email_prompts(self):
        """Was B20_4."""
        with mock.patch.object(offb, "prompt_email", return_value=D), \
             mock.patch.object(offb, "validate_destination", return_value=True), \
             mock.patch.object(offb, "_list_aliases", return_value=[]), \
             mock.patch.object(offb, "_email_mailbox_missing") as probe:
            offb._plan_email("Drive dest", source=U)
        probe.assert_not_called()

    def _deps(self, which, **kwargs):
        fake = FakeGam([(("version",), (True, "GAM 7.48.01"))])
        with gam(fake), mock.patch.object(offb.shutil, "which", which):
            return offb.check_dependencies(**kwargs)

    def test_dry_run_dependency_check_creates_no_backup_directory(self):
        root = self.tmpdir() / "offboarding_backups"
        with mock.patch.object(offb, "BACKUP_DIRECTORY", root):
            self.assertTrue(self._deps(lambda cmd: f"/usr/bin/{cmd}", dry_run=True))
            self.assertFalse(root.exists())
            self.assertTrue(self._deps(lambda cmd: f"/usr/bin/{cmd}", dry_run=False))
            self.assertTrue(root.is_dir())

    def test_missing_gyb_fails_the_dependency_check(self):
        which = lambda cmd: None if cmd == offb.GYB_COMMAND else f"/usr/bin/{cmd}"
        printed = []
        with mock.patch.object(offb, "print_error", printed.append):
            self.assertFalse(self._deps(which, need_gyb=True, dry_run=True))
        self.assertTrue(any("GYB not found" in p for p in printed))


###############################################################################
# Plan collection
###############################################################################

class TestPlan(OffboardTestCase):

    @staticmethod
    def _plan(enrolled, enforced, **kw):
        args = _PlanArgs(no_drive=True, no_email=True, no_alias=True,
                         no_calendar=True, no_forward=True, **kw)
        dest_map = {k: None for k in ("drive", "email", "alias", "calendar", "forward")}
        return offb.collect_plan(args, dest_map, enrolled, enforced)

    def test_not_enrolled_means_nothing_to_turn_off(self):
        """Was B12_1."""
        self.assertFalse(self._plan(False, False)["turnoff2sv"]["do"])

    def test_enrolled_not_enforced_is_attempted(self):
        """Was B12_2."""
        self.assertTrue(self._plan(True, False)["turnoff2sv"]["do"])

    def test_enforced_is_still_attempted_under_force(self):
        """Was B12_3: enforcement follows the OU and the kill switch moves
        the user first, so the plan-time reading describes the OU being left."""
        self.assertTrue(self._plan(True, True)["turnoff2sv"]["do"])

    def test_enforced_but_not_enrolled_is_skipped(self):
        """Was B12_4."""
        self.assertFalse(self._plan(False, True)["turnoff2sv"]["do"])

    def test_strip_labels_is_always_present(self):
        plan = self._plan(False, False)
        self.assertFalse(plan["email"]["do"])
        self.assertIs(plan["email"]["strip_labels"], True)
        self.assertIs(self._plan(False, False, strip_labels=False)["email"]["strip_labels"],
                      False)

    def test_email_prompt_gets_source_and_mailbox_probe(self):
        """Was B20_5."""
        args = _PlanArgs(no_drive=True, no_alias=True, no_calendar=True,
                         no_forward=True, force=False)
        dest_map = {k: None for k in ("drive", "email", "alias", "calendar", "forward")}
        with mock.patch.object(offb, "prompt_yes_no", return_value=True), \
             mock.patch.object(offb, "_plan_email", return_value=D) as pe:
            plan = offb.collect_plan(args, dest_map, False, False, source=U)
        pe.assert_called_once_with("Email migration destination email",
                                   allow_group=False, source=U, needs_mailbox=True)
        self.assertEqual(plan["email"], {"do": True, "dest": D, "strip_labels": True})


###############################################################################
# Kill switch (containment)
###############################################################################

ENFORCED_ERR = (f'User: {U}, Turn Off 2-Step Verification Failed: 2-Step '
                'Verification cannot be turned off: user is required by admin '
                'policy to have 2-Step Verification ("enforced")')
KILL_CLAIMS = ("Wiped recovery email", "Forced sign-out", "Password scrambled",
               "Hidden from GAL")


class TestKillSwitch(OffboardTestCase):

    def _kill(self, fake, **kw):
        params = dict(dry_run=False, is_suspended=False, is_2sv_enrolled=False,
                      has_mailbox=True, turn_off_2sv=True)
        params.update(kw)
        with gam(fake):
            return offb.execute_kill_switch(U, **params)

    def test_failed_steps_are_not_reported_as_actions(self):
        """Was A1_3."""
        self._kill(FakeGam([((), (False, "err"))]), is_2sv_enrolled=True)
        for claim in KILL_CLAIMS:
            self.assertNotIn(claim, self.actions())

    def test_successful_steps_are_reported(self):
        """Was A1_3b."""
        self._kill(FakeGam(), is_2sv_enrolled=True)
        for claim in KILL_CLAIMS:
            self.assertIn(claim, self.actions())

    def _step5(self, enrolled_readback, turnoff_result=(True, "")):
        state = "True" if enrolled_readback else "False"
        fake = FakeGam([
            (("user", U, "turnoff2sv"), turnoff_result),
            (("info", "user"), (True, f"    2-step enrolled: {state}")),
        ])
        self._kill(fake, is_2sv_enrolled=True)
        return len(fake.matching("user", U, "turnoff2sv"))

    def test_turnoff2sv_is_not_refired_when_already_off(self):
        """Was A12_1: deprovision already turned it off."""
        self.assertEqual(self._step5(enrolled_readback=False), 0)
        self.assertIn("2SV off (verified by read-back)", self.actions())
        self.assertFalse(offb.summary_errors)

    def test_turnoff2sv_fires_when_still_enrolled(self):
        """Was A12_2."""
        self.assertEqual(self._step5(enrolled_readback=True), 1)
        self.assertIn("Turned off 2SV", self.actions())

    def test_turnoff2sv_failure_while_enrolled_is_an_error(self):
        """Was A12_3."""
        self._step5(enrolled_readback=True, turnoff_result=(False, "boom"))
        self.assertTrue(any("turnoff2sv failed" in e for e in offb.summary_errors))

    def _deprov_argv(self, has_mailbox):
        fake = FakeGam()
        self._kill(fake, has_mailbox=has_mailbox)
        return fake.matching("user", U, "deprovision")[0]

    def test_no_mailbox_drops_popimap(self):
        """Was A10_1."""
        self.assertNotIn("popimap", self._deprov_argv(has_mailbox=False))

    def test_mailbox_keeps_popimap(self):
        """Was A10_2."""
        self.assertIn("popimap", self._deprov_argv(has_mailbox=True))

    def _kill_enforced(self, fake, enrolled_readback=False):
        with mock.patch.object(offb, "_read_2sv_enrolled", return_value=enrolled_readback):
            self._kill(fake, is_2sv_enrolled=True)

    def test_enforced_refusal_in_the_bundle_still_reports_containment(self):
        """Was B13_1: everything else in the deprovision bundle completed."""
        self._kill_enforced(FakeGam([(("user", U, "deprovision"), (True, ENFORCED_ERR))]))
        self.assertTrue(any("Deprovisioned" in a for a in offb.summary_actions))
        self.assertFalse(any("deprovision" in e.lower() for e in offb.summary_errors))

    def test_explicit_turnoff2sv_policy_refusal_is_a_warning(self):
        """Was B13_2."""
        self._kill_enforced(FakeGam([(("user", U, "turnoff2sv"), (False, ENFORCED_ERR))]),
                            enrolled_readback=True)
        self.assertTrue(any("enforced by policy" in w for w in offb.summary_warnings))
        self.assertFalse(any("turnoff2sv failed" in e for e in offb.summary_errors))

    def test_unrelated_turnoff2sv_failure_is_still_an_error(self):
        """Was B13_3."""
        self._kill_enforced(FakeGam([(("user", U, "turnoff2sv"),
                                      (False, "Turn Off 2-Step Verification Failed: backendError"))]),
                            enrolled_readback=True)
        self.assertTrue(any("turnoff2sv failed" in e for e in offb.summary_errors))

    def test_not_enrolled_after_deprovision_is_success_not_a_skip(self):
        """Was B13_4: the directory read lags the deprovision."""
        not_enrolled = (f"\nUser: {U}, Turn Off 2-Step Verification Failed: 2-Step "
                        "Verification cannot be turned off: user not enrolled in "
                        "2-Step Verification")
        self._kill_enforced(FakeGam([(("user", U, "turnoff2sv"), (False, not_enrolled))]),
                            enrolled_readback=True)
        self.assertTrue(any("Turned off 2SV" in a for a in offb.summary_actions))
        self.assertFalse(any("skipped" in w for w in offb.summary_warnings))

    def test_a_reason_is_never_quoted_as_an_empty_string(self):
        """Was B13_5."""
        self.assertEqual(offb._first_line("\nreal reason\nmore"), "real reason")
        self.assertEqual(offb._first_line(""), "no reason given")

    def test_failed_password_scramble_is_not_contained(self):
        """Was B17_1."""
        result = self._kill(FakeGam([(("update", "user", U, "password"),
                                      (False, "Update Failed"))]), turn_off_2sv=False)
        self.assertFalse(result["contained"])
        self.assertFalse(result["password_scrambled"])
        self.assertTrue(any("CONTAINMENT INCOMPLETE" in e for e in offb.summary_errors))

    def test_a_clean_kill_switch_reports_contained(self):
        """Was B17_2."""
        result = self._kill(FakeGam(), turn_off_2sv=False)
        self.assertTrue(result["contained"])
        self.assertTrue(result["started"])
        self.assertFalse(any("CONTAINMENT INCOMPLETE" in e for e in offb.summary_errors))

    def test_deprovision_signout_covers_a_failed_explicit_signout(self):
        """Was B17_3."""
        result = self._kill(FakeGam([(("user", U, "signout"), (False, ""))]),
                            turn_off_2sv=False)
        self.assertTrue(result["signed_out"])
        self.assertTrue(result["contained"])

    def test_shutdown_before_entry_runs_nothing(self):
        offb.shutdown_requested = True
        fake = FakeGam()
        result = self._kill(fake)
        self.assertEqual(result, {"password_scrambled": False, "signed_out": False,
                                  "contained": False, "started": False})
        self.assertEqual(fake.calls, [])

    def test_ctrl_c_after_the_first_step_still_finishes_all_seven(self):
        def ou_move(_args, _kw):
            offb.shutdown_requested = True
            return True, ""

        fake = FakeGam([(("update", "user", U, "org"), ou_move),
                        (("info", "user"), (True, "    2-step enrolled: True"))])
        result = self._kill(fake, is_2sv_enrolled=True)
        self.assertTrue(result["contained"])
        argv = fake.argv()
        for step in (f"update user {U} org {offb.OFFBOARDING_OU}",
                     f"update user {U} recoveryemail",
                     f"user {U} deprovision popimap signout turnoff2sv",
                     f"user {U} signout",
                     f"user {U} turnoff2sv",
                     f"update user {U} password random changepassword on",
                     f"update user {U} gal off"):
            self.assertTrue(any(a.startswith(step) for a in argv), f"missing: {step}")
        self.assertFalse(offb.summary_errors)

    def test_already_suspended_user_is_not_containment_incomplete(self):
        # A suspended account cannot sign out and does not need to.
        fake = FakeGam([(("user", U, "signout"), (False, "suspended")),
                        (("user", U, "deprovision"), (False, "suspended"))])
        result = self._kill(fake, is_suspended=True, turn_off_2sv=False)
        self.assertTrue(result["signed_out"])
        self.assertTrue(result["contained"])
        self.assertFalse(any("CONTAINMENT INCOMPLETE" in e for e in offb.summary_errors))

    def test_run_gam_refuses_after_shutdown_unless_bypassed(self):
        spawned = []

        def fake_run(cmd, **_kw):
            spawned.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

        offb.shutdown_requested = True
        with mock.patch.object(offb.subprocess, "run", fake_run):
            self.assertEqual(offb.run_gam(["info", "domain"], dry_run=False),
                             (False, "Shutdown requested"))
            self.assertEqual(offb.run_gam(["info", "domain"], dry_run=False,
                                          bypass_shutdown=True), (True, "ok"))
        self.assertEqual(len(spawned), 1)


###############################################################################
# Suspension and the re-suspend guard
###############################################################################

class TestSuspension(OffboardTestCase):

    def test_failed_update_is_not_reported_as_suspended(self):
        """Was A1_1."""
        with gam(FakeGam([(("update",), (False, "err"))])):
            self.assertFalse(offb.suspend_user(U, dry_run=False))
        self.assertNotIn("suspended", self.actions().lower())
        self.assertTrue(any("Suspension failed" in e for e in offb.summary_errors))

    def test_verified_suspension_is_reported(self):
        """Was A1_1b."""
        with gam(quick_gam(SUSPENDED_USER)), clocked():
            self.assertTrue(offb.suspend_user(U, dry_run=False))
        self.assertIn("verified by read-back", self.actions())

    def test_lying_update_is_caught_by_read_back(self):
        """Was A11_1: 'Updated' can report success with no state change."""
        with gam(quick_gam(ACTIVE_USER)), clocked():
            self.assertFalse(offb.suspend_user(U, dry_run=False))
        self.assertNotIn("suspended (verified", self.actions().lower())
        self.assertTrue(any("NOT verified" in e for e in offb.summary_errors))

    def test_slow_flip_after_the_kill_switch_is_still_caught(self):
        """Was A11_2: measured 54s on dev straight after the kill switch's
        burst of directory writes; reads stay False for 40s here."""
        with clocked() as clock:
            start = clock.now

            def quick(_args, _kw):
                return True, (SUSPENDED_USER if clock.now - start > 40 else ACTIVE_USER)

            with gam(FakeGam([(("info", "user"), quick)])):
                self.assertTrue(offb.suspend_user(U, dry_run=False))
        self.assertIn("verified by read-back", self.actions().lower())
        self.assertFalse(offb.summary_errors)

    def test_dry_run_reports_without_a_read_back(self):
        fake = FakeGam()
        with gam(fake):
            self.assertTrue(offb.suspend_user(U, dry_run=True))
        self.assertEqual(fake.argv(), [f"update user {U} suspended on"])
        self.assertIn("User account suspended", self.actions())

    def test_guard_makes_no_change_when_already_suspended(self):
        """Was B15_4."""
        fake = quick_gam(SUSPENDED_USER)
        with gam(fake):
            self.assertTrue(offb.restore_original_suspension(U))
        self.assertEqual(fake.matching("update"), [])

    def test_guard_attempts_the_restore_then_reports_an_error(self):
        """Was B15_5."""
        fake = quick_gam(ACTIVE_USER)
        with gam(fake), clocked():
            self.assertFalse(offb.restore_original_suspension(U, attempts=2))
        self.assertEqual(len(fake.matching("update", "user", U, "suspended", "on")), 2)
        self.assertTrue(any("NOT restored" in e for e in offb.summary_errors))

    def test_guard_resuspends_when_the_no_suspend_contract_is_not_waived(self):
        """Was B22_1: a crashed --no-suspend run made no informed choice."""
        fake = quick_gam(ACTIVE_USER)
        with gam(fake), mock.patch.object(offb, "wait_for_suspended", return_value=True):
            self.assertTrue(offb.restore_original_suspension(U))
        self.assertEqual(fake.matching("update", "user", U, "suspended", "on"),
                         [f"update user {U} suspended on"])

    def test_guard_stands_down_after_a_normal_no_suspend_completion(self):
        """Was B22_2."""
        offb.no_suspend_contract_waived = True
        fake = FakeGam()
        with gam(fake):
            self.assertTrue(offb.restore_original_suspension(U))
        self.assertEqual(fake.calls, [])

    def test_guard_still_resuspends_after_ctrl_c(self):
        # The old HIGH bug: after Ctrl+C every gam call in the guard returned
        # "Shutdown requested", so the update was never issued.
        state = {"suspended": False}

        def quick(_args, _kw):
            return True, (SUSPENDED_USER if state["suspended"] else ACTIVE_USER)

        def update(_args, _kw):
            state["suspended"] = True
            return True, ""

        fake = FakeGam([(("info", "user"), quick),
                        (("update", "user", U, "suspended", "on"), update)])
        offb.shutdown_requested = True
        with gam(fake), clocked():
            self.assertTrue(offb.restore_original_suspension(U))
        self.assertIn(f"update user {U} suspended on", fake.argv())
        self.assertFalse(offb.summary_errors)


###############################################################################
# Groups and devices
###############################################################################

class TestGroupsAndDevices(OffboardTestCase):

    def _groups(self, listing, dry_run=False):
        fake = FakeGam([(("user", U, "print", "groups"), listing)])
        with gam(fake):
            offb.remove_groups(U, dry_run=dry_run)
        return fake

    def test_one_group_from_captured_output_is_removed(self):
        fake = self._groups((True, stdout_only(fixture("print_groups_one"))))
        self.assertEqual(fake.matching("user", U, "delete", "groups"),
                         [f"user {U} delete groups"])
        self.assertIn("Removed from 1 group(s)", self.actions())

    def test_groupemail_header_variant_is_parsed(self):
        listing = f"User,GroupEmail,Role\n{U},team@yourdomain.com,MEMBER\n"
        fake = self._groups((True, listing))
        self.assertTrue(fake.matching("user", U, "delete", "groups"))
        self.assertIn("Removed from 1 group(s)", self.actions())

    def test_email_column_without_group_in_its_name_is_used(self):
        listing = f"User,Email,Role\n{U},team@yourdomain.com,MEMBER\n"
        fake = self._groups((True, listing))
        self.assertTrue(fake.matching("user", U, "delete", "groups"))
        self.assertIn("Removed from 1 group(s)", self.actions())

    def test_no_groups_removes_nothing(self):
        fake = self._groups((True, ""))
        self.assertEqual(fake.matching("user", U, "delete"), [])
        self.assertIn("No group memberships to remove", self.actions())

    def test_failed_listing_is_an_error_naming_the_manual_command(self):
        fake = self._groups((False, "timeout"))
        self.assertEqual(fake.matching("user", U, "delete"), [])
        self.assertNotIn("No group memberships", self.actions())
        self.assertTrue(any(f"gam user {U} delete groups" in e
                            for e in offb.summary_errors))

    def test_dry_run_lists_but_does_not_remove(self):
        fake = self._groups((True, stdout_only(fixture("print_groups_one"))), dry_run=True)
        delete = [kw for a, kw in fake.calls if a[:4] == ["user", U, "delete", "groups"]]
        self.assertEqual([kw["dry_run"] for kw in delete], [True])
        self.assertIn("Would remove 1 group membership(s)", self.actions())

    def _devices(self, mobile, cros):
        fake = FakeGam([(("print", "mobile"), mobile), (("print", "cros"), cros)])
        with gam(fake):
            offb.manage_devices(U, False)
        return fake

    def test_no_devices_from_captured_output(self):
        fake = self._devices((True, stdout_only(fixture("print_mobile_none"))),
                             (True, stdout_only(fixture("print_cros_none"))))
        self.assertIn("No mobile devices", self.actions())
        self.assertIn("No ChromeOS devices", self.actions())
        self.assertEqual(sorted(fake.argv()),
                         sorted([f"print mobile query email:{U}",
                                 f"print cros query user:{U}"]))

    def test_devices_found_are_listed_for_review(self):
        self._devices((True, "resourceId\nAFiQxQ123\n"), (True, "deviceId\nabc\n"))
        self.assertIn("Mobile devices found", self.actions())
        self.assertIn("ChromeOS devices found", self.actions())

    def test_failed_device_query_is_an_error_not_no_devices(self):
        self._devices((False, ""), (False, ""))
        self.assertNotIn("No mobile devices", self.actions())
        self.assertNotIn("No ChromeOS devices", self.actions())
        self.assertTrue(any(f'gam print mobile query "email:{U}"' in e
                            for e in offb.summary_errors))
        self.assertTrue(any(f'gam print cros query "user:{U}"' in e
                            for e in offb.summary_errors))

    def test_run_gam_parallel_keeps_input_order(self):
        fake = FakeGam([(("b",), (True, "B")), (("a",), (False, "A"))])
        with gam(fake):
            got = offb.run_gam_parallel({"b": (["b"], dict(dry_run=False)),
                                         "a": (["a"], dict(dry_run=False))})
        self.assertEqual(list(got.items()), [("b", (True, "B")), ("a", (False, "A"))])


###############################################################################
# Delegates
###############################################################################

class TestDelegates(OffboardTestCase):

    DELEGATE = "testload06@yourdomain.com"

    def _cleanup(self, listing, delete=(True, ""), dry_run=False):
        fake = FakeGam([(("user", U, "show", "delegates"), listing),
                        (("user", U, "delete", "delegate"), delete)])
        with gam(fake):
            offb.cleanup_delegates(U, dry_run=dry_run)
        return fake

    def test_one_delegate_from_captured_output_is_removed(self):
        fake = self._cleanup((True, fixture("show_delegates_one")))
        self.assertEqual(fake.matching("user", U, "delete", "delegate"),
                         [f"user {U} delete delegate {self.DELEGATE}"])
        self.assertIn("Removed 1/1 inbound delegate(s)", self.actions())

    def test_no_delegates_removes_nothing(self):
        fake = self._cleanup((True, fixture("show_delegates_none")))
        self.assertEqual(fake.matching("user", U, "delete"), [])
        self.assertIn("No inbound delegates to remove", self.actions())

    def test_failed_delete_is_counted_honestly(self):
        self._cleanup((True, fixture("show_delegates_one")), delete=(False, "err"))
        self.assertIn("Removed 0/1 inbound delegate(s)", self.actions())

    def test_dry_run_reports_what_it_would_remove(self):
        self._cleanup((True, fixture("show_delegates_one")), dry_run=True)
        self.assertIn("Would remove 1 inbound delegate(s)", self.actions())

    def test_outbound_delegation_is_always_a_warning_with_the_command(self):
        self._cleanup((True, fixture("show_delegates_none")))
        self.assertTrue(any(f"gam all users print delegates | grep {U}" in w
                            for w in offb.summary_warnings))


###############################################################################
# Licences and the pre-flight snapshot
###############################################################################

LICENCES = [("1010010001", "Cloud Identity Free"),
            ("1010020020", "Google Workspace Enterprise Plus (formerly G Suite Enterprise)")]


class TestLicences(OffboardTestCase):

    def test_licence_block_parsed_from_captured_output(self):
        self.assertEqual(offb._parse_info_user_licences(fixture("info_user_licences_block")),
                         LICENCES)

    def test_zero_licences_is_an_empty_list(self):
        self.assertEqual(offb._parse_info_user_licences("  Licenses: (0)\n"), [])

    def test_missing_block_is_none(self):
        self.assertIsNone(offb._parse_info_user_licences(ACTIVE_USER))

    def test_cached_licences_are_deleted_by_sku_with_full_labels(self):
        """Was A5_1: multi-word display names must survive intact."""
        fake = FakeGam()
        with gam(fake):
            offb.remove_licences(U, dry_run=False, cached_licences=LICENCES[:1])
        self.assertEqual(fake.argv(), [f"user {U} delete license 1010010001"])
        self.assertIn("Cloud Identity Free (1010010001)", self.actions())

    def test_multiple_licences_are_each_labelled_and_deleted(self):
        """Was A5_2."""
        fake = FakeGam()
        with gam(fake):
            offb.remove_licences(U, dry_run=False, cached_licences=LICENCES)
        self.assertEqual(fake.argv(), [f"user {U} delete license 1010010001",
                                       f"user {U} delete license 1010020020"])
        self.assertIn("Cloud Identity Free (1010010001)", self.actions())
        self.assertIn("(formerly G Suite Enterprise) (1010020020)", self.actions())
        self.assertNotIn("Cloud (", self.actions())

    def test_uncached_licences_are_read_from_the_full_info_user(self):
        fake = FakeGam([(("info", "user", U), (True, fixture("info_user_licences_block")))])
        with gam(fake):
            offb.remove_licences(U, dry_run=False)
        self.assertEqual(fake.argv()[0], f"info user {U}")
        self.assertEqual(len(fake.matching("user", U, "delete", "license")), 2)

    def test_failed_licence_query_is_an_error_not_no_licences(self):
        fake = FakeGam([(("info", "user", U), (False, "timeout"))])
        with gam(fake):
            offb.remove_licences(U, dry_run=False)
        self.assertEqual(fake.matching("user", U, "delete"), [])
        self.assertNotIn("No licences", self.actions())
        self.assertTrue(any(f"gam info user {U}" in e for e in offb.summary_errors))

    def test_no_licences_is_reported_without_a_delete(self):
        fake = FakeGam()
        with gam(fake):
            offb.remove_licences(U, dry_run=False, cached_licences=[])
        self.assertEqual(fake.calls, [])
        self.assertIn("No licences found", self.actions())

    def test_auto_assigned_licence_is_a_warning(self):
        fake = FakeGam([(("user", U, "delete", "license"),
                         (True, "Licence is auto-assigned and cannot be removed"))])
        with gam(fake):
            offb.remove_licences(U, dry_run=False, cached_licences=LICENCES[:1])
        self.assertTrue(any("auto-assigned" in w for w in offb.summary_warnings))
        self.assertNotIn("Removed", self.actions())

    def test_failed_delete_is_an_error(self):
        fake = FakeGam([(("user", U, "delete", "license"), (False, "boom"))])
        with gam(fake):
            offb.remove_licences(U, dry_run=False, cached_licences=LICENCES[:1])
        self.assertTrue(any("Licence removal failed" in e for e in offb.summary_errors))

    def test_dry_run_lists_without_deleting(self):
        fake = FakeGam()
        with gam(fake):
            offb.remove_licences(U, dry_run=True, cached_licences=LICENCES[:1])
        self.assertEqual([kw["dry_run"] for _, kw in fake.calls], [True])
        self.assertIn("Licences listed (dry run)", self.actions())

    def test_snapshot_writes_the_file_and_returns_the_licences(self):
        root = self.tmpdir()
        fake = FakeGam([(("info", "user", U),
                         (True, ACTIVE_USER + fixture("info_user_licences_block")))])
        with gam(fake), mock.patch.object(offb, "BACKUP_DIRECTORY", root):
            path, licences = offb.preflight_snapshot(U, dry_run=True,
                                                     timestamp="20260902_120000")
        self.assertEqual(licences, LICENCES)
        self.assertEqual(path, root / "snapshots" / f"{U}_20260902_120000.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["script_version"], offb.SCRIPT_VERSION)
        self.assertEqual(data["data"]["licenses"][0], {"skuId": "1010010001",
                                                       "name": "Cloud Identity Free"})
        self.assertFalse(fake.matching("print", "licenses"),
                         "print licenses is slow and no longer run")
        self.assertIn(f"info user {U}", fake.argv())

    def test_snapshot_returns_no_licence_list_when_the_read_fails(self):
        root = self.tmpdir()
        fake = FakeGam([(("info", "user", U), (False, ""))])
        with gam(fake), mock.patch.object(offb, "BACKUP_DIRECTORY", root):
            path, licences = offb.preflight_snapshot(U, dry_run=False)
        self.assertIsNone(licences)
        self.assertTrue(path.exists())


###############################################################################
# Aliases
###############################################################################

class TestAliases(OffboardTestCase):

    ALIAS = "evan.legacy@yourdomain.com"
    ALIAS_CSV = f"Alias,Target,TargetType\n{ALIAS},{U},user\n"

    def _fake(self, create_results):
        creates = []

        def create(_args, _kw):
            result = create_results[min(len(creates), len(create_results) - 1)]
            creates.append(1)
            return result

        return FakeGam([(("print", "aliases"), (True, self.ALIAS_CSV)),
                        (("delete", "alias"), (True, "")),
                        (("create", "alias"), create)])

    def test_duplicate_then_success_retries_and_reports_success(self):
        """Was A9_1: the create races propagation of its own delete."""
        fake = self._fake([(False, "Update Failed: Duplicate"), (True, "Created")])
        with gam(fake), clocked():
            offb.transfer_aliases(U, D, dry_run=False)
        self.assertGreaterEqual(len(fake.matching("create", "alias")), 2)
        self.assertEqual(fake.matching("delete", "alias"), [f"delete alias {self.ALIAS}"])
        self.assertIn(self.ALIAS, self.actions())
        self.assertFalse(offb.summary_errors)

    def test_permanent_create_failure_is_an_error_not_success(self):
        """Was A9_2."""
        fake = self._fake([(False, "Update Failed: Duplicate")])
        with gam(fake), clocked():
            offb.transfer_aliases(U, D, dry_run=False)
        self.assertNotIn("evan.legacy", self.actions())
        self.assertTrue(any("evan.legacy" in e for e in offb.summary_errors))

    def test_no_aliases_from_captured_output(self):
        fake = FakeGam([(("print", "aliases"),
                         (True, stdout_only(fixture("print_aliases_none"))))])
        with gam(fake):
            self.assertEqual(offb._list_aliases(U), [])
            offb.transfer_aliases(U, D, dry_run=False)
        self.assertEqual(fake.matching("delete"), [])
        self.assertIn("No aliases to transfer", self.actions())


###############################################################################
# Drive transfer
###############################################################################

class TestDriveTransfer(OffboardTestCase):

    def _transfer(self, output, returncode):
        with fake_popen(output, returncode):
            offb.transfer_drive(U, D, dry_run=False)

    def test_exit_56_with_moves_is_a_warning_not_an_error(self):
        """Was B19_5 / B21_2: non-owned files skipped; owned ones moved."""
        self._transfer("Got 3 Drive Files/Folders for Source User\n"
                       "Ownership Transferred to User: ok\n", 56)
        self.assertFalse(offb.summary_errors)
        self.assertTrue(any("exit 56" in w for w in offb.summary_warnings))

    def test_exit_56_with_nothing_moved_is_an_error(self):
        """Was B21_1."""
        self._transfer("Got 3 Drive Files/Folders for Source User\n", 56)
        self.assertTrue(any("0 files" in e for e in offb.summary_errors))

    def test_other_exit_codes_are_errors(self):
        """Was B19_6."""
        self._transfer("", 1)
        self.assertTrue(any("Drive transfer failed" in e for e in offb.summary_errors))

    def test_confirmations_are_counted_not_the_header(self):
        self._transfer("Got 100 Drive Files/Folders for Source User\n"
                       "Ownership Transferred to User: a\r"
                       "Ownership Transferred to User: b\n", 0)
        self.assertIn(f"Drive transferred to {D} (2 file(s)/folder(s))", self.actions())

    def test_zero_files_on_success_is_a_warning(self):
        self._transfer("Got 0 Drive Files/Folders for Source User\n", 0)
        self.assertTrue(any("moved 0 files" in w for w in offb.summary_warnings))

    def test_stream_process_splits_on_cr_and_lf_and_drops_blanks(self):
        seen = []
        with fake_popen("a\r\n\nb\rc\n  \nd", 7):
            self.assertEqual(offb._stream_process(["x"], seen.append), 7)
        self.assertEqual(seen, ["a", "b", "c", "d"])

    def test_dry_run_spawns_nothing(self):
        offb.transfer_drive(U, D, dry_run=True)
        self.assertIn(f"Drive transfer planned to {D}", self.actions())


###############################################################################
# Drive backup (rclone) and its reconciliation
###############################################################################

class TestDriveBackup(OffboardTestCase):

    def setUp(self):
        super().setUp()
        self.b = self.tmpdir()

    @staticmethod
    def _filelist(n, forms=0):
        rows = [f"u,id{i},application/vnd.google-apps.document" for i in range(n - forms)]
        rows += [f"u,form{i},application/vnd.google-apps.form" for i in range(forms)]
        return "Owner,id,mimeType\n" + "\n".join(rows)

    @staticmethod
    def _drive_gam(untrashed, trashed="Owner,id\n", ok=True):
        def filelist(args, _kw):
            if not ok:
                return False, ""
            return (True, trashed) if "trashed = true" in args[-1] else (True, untrashed)
        return FakeGam([(("user", U, "print", "filelist"), filelist)])

    def _verify(self, untrashed, duplicates=None, trashed="Owner,id\n", ok=True):
        with gam(self._drive_gam(untrashed, trashed, ok)):
            return offb.verify_drive_backup_complete(U, self.b, duplicates)

    def test_short_backup_is_an_error(self):
        """Was B9_1: a warning left exit_code 0 and a wrapper deleted the source."""
        (self.b / "one.docx").write_text("x")
        self.assertEqual(self._verify(self._filelist(3)), (3, 1))
        self.assertTrue(any("unaccounted for" in e for e in offb.summary_errors))
        self.assertEqual(offb.exit_code, 1)

    def test_matching_backup_is_quiet(self):
        """Was B9_2."""
        for name in ("a.docx", "b.docx"):
            (self.b / name).write_text("x")
        self.assertEqual(self._verify(self._filelist(2)), (2, 2))
        self.assertFalse(offb.summary_warnings)
        self.assertFalse(offb.summary_errors)

    def test_nested_files_are_counted(self):
        """Was B9_3."""
        sub = self.b / "Projects" / "2024"
        sub.mkdir(parents=True)
        (sub / "deep.docx").write_text("x")
        self.assertEqual(self._verify(self._filelist(1)), (1, 1))

    def test_gam_failure_does_not_raise_or_warn(self):
        """Was B9_4."""
        self.assertEqual(self._verify(self._filelist(1), ok=False), (0, 0))
        self.assertFalse(offb.summary_warnings)

    def test_progress_lines_do_not_inflate_the_count(self):
        """Was B9_5."""
        out = (f"Getting all Drive Files/Folders for {U}\n"
               f"Got 2 Drive Files/Folders that matched query for {U}...\n"
               + self._filelist(2))
        for name in ("a.docx", "b.docx"):
            (self.b / name).write_text("x")
        self.assertEqual(self._verify(out), (2, 2))
        self.assertFalse(offb.summary_warnings)

    def test_paged_output_uses_the_last_running_total(self):
        """Was B9_6: one "Got N" per page, CR-separated, N the running total."""
        out = (self._filelist(256) + "\n"
               f"Getting all Drive Files/Folders for {U}\n"
               f"Got 100 Drive Files/Folders for {U}...\r"
               f"Got 200 Drive Files/Folders for {U}...\r"
               f"Got 256 Drive Files/Folders for {U}...")
        for i in range(150):
            (self.b / f"f{i}.docx").write_text("x")
        self.assertEqual(self._verify(out), (256, 150))
        self.assertTrue(any("unaccounted for" in e for e in offb.summary_errors))

    def test_row_fallback_ignores_stray_progress_lines(self):
        """Was B9_7."""
        out = self._filelist(2) + f"\nGetting all Drive Files/Folders for {U}"
        self.assertEqual(self._verify(out)[0], 2)

    def test_rclone_named_duplicates_are_listed(self):
        """Was B9_8."""
        (self.b / "one.docx").write_text("x")
        self._verify(self._filelist(3), ["folder/Notes.docx", "folder/Line one.docx"])
        joined = " ".join(offb.summary_errors)
        self.assertIn("folder/Notes.docx", joined)
        self.assertIn("folder/Line one.docx", joined)
        self.assertEqual(offb.exit_code, 1)

    def test_duplicates_are_an_error_even_when_the_counts_match(self):
        # Leftovers from an earlier backup pad local_files past drive_files.
        for name in ("a.docx", "b.docx", "c.docx"):
            (self.b / name).write_text("x")
        self._verify(self._filelist(2), ["Notes.docx"])
        self.assertTrue(any("Notes.docx" in e for e in offb.summary_errors))

    def test_forms_only_shortfall_stays_a_warning(self):
        """Was B9_9: Forms and Sites have no export format."""
        (self.b / "one.docx").write_text("x")
        self.assertEqual(self._verify(self._filelist(3, forms=2)), (3, 1))
        self.assertFalse(offb.summary_errors)
        self.assertEqual(offb.exit_code, 0)
        self.assertTrue(any("not exportable" in w for w in offb.summary_warnings))

    def test_shortfall_beyond_the_forms_is_an_error(self):
        """Was B9_10."""
        (self.b / "one.docx").write_text("x")
        self._verify(self._filelist(4, forms=1))
        self.assertTrue(any("2 of them unaccounted for" in e for e in offb.summary_errors))

    def test_trashed_files_are_counted_from_their_own_listing(self):
        (self.b / "a.docx").write_text("x")
        self._verify(self._filelist(1), trashed=f"Got 3 Drive Files/Folders for {U}\n"
                                                "Owner,id\nu,t1\nu,t2\nu,t3")
        self.assertTrue(any("3 trashed file(s)" in w for w in offb.summary_warnings))
        self.assertFalse(offb.summary_errors)

    def _dated_drive_backup(self, root, days_ago):
        stamp = (datetime.now() - timedelta(days=days_ago)).strftime("%Y%m%d")
        folder = root / "drive" / f"{U}_{stamp}"
        folder.mkdir(parents=True)
        (folder / "somefile.pdf").write_bytes(b"x")
        return folder

    def test_recent_folder_is_synced_into_under_force(self):
        """Was B23_3."""
        prior = self._dated_drive_backup(self.b, 0)
        printed = []
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.b), \
             mock.patch.object(offb, "print_info", printed.append):
            self.assertEqual(offb._select_drive_backup_path(U, force=True), prior)
        self.assertTrue(any("syncing into it (--force, within 30 days)." in p
                            for p in printed))

    def test_old_folder_starts_fresh_under_force(self):
        """Was B23_4."""
        old = self._dated_drive_backup(self.b, 400)
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.b):
            self.assertNotEqual(offb._select_drive_backup_path(U, force=True), old)

    def test_empty_prior_folder_is_not_offered(self):
        """Was B23_5."""
        (self.b / "drive" / f"{U}_{datetime.now().strftime('%Y%m%d')}").mkdir(parents=True)
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.b), \
             mock.patch.object(offb, "prompt_yes_no") as p:
            offb._select_drive_backup_path(U, force=False)
        p.assert_not_called()

    def test_prompt_offers_to_sync_into_the_prior_folder(self):
        prior = self._dated_drive_backup(self.b, 1)
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.b), \
             mock.patch.object(offb, "prompt_yes_no", return_value=True) as p:
            self.assertEqual(offb._select_drive_backup_path(U), prior)
        question = p.call_args[0][0]
        self.assertIn(f"Found an existing Drive backup {prior.name} (1 day(s) old). "
                      "Syncing into it (only new/changed content is fetched)", question)

    def _rclone(self, output, returncode):
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.b), \
             mock.patch.object(offb, "verify_drive_backup_complete",
                               return_value=(1, 1)) as verify, \
             fake_popen(output, returncode):
            ok = offb.backup_drive_rclone(U, dry_run=False, force=True)
        return ok, verify

    def test_clean_rclone_run_is_reconciled_with_its_duplicates(self):
        ok, verify = self._rclone(
            "NOTICE: a/Notes.docx: Duplicate object found in source - ignoring\n"
            "Transferred: 1 / 1, 100%\n", 0)
        self.assertTrue(ok)
        verify.assert_called_once_with(U, mock.ANY, ["a/Notes.docx"])
        self.assertIn("Drive backed up via rclone", self.actions())

    def test_only_abusive_files_failing_is_still_reconciled(self):
        ok, verify = self._rclone(
            "ERROR : bad.pdf: Failed to copy: cannotDownloadAbusiveFile\n", 1)
        self.assertTrue(ok)
        verify.assert_called_once()
        self.assertTrue(any("bad.pdf" in w for w in offb.summary_warnings))
        self.assertFalse(offb.summary_errors)

    def test_other_rclone_failure_is_an_error(self):
        ok, verify = self._rclone("ERROR : x.pdf: Failed to copy: 500\n", 1)
        self.assertFalse(ok)
        verify.assert_not_called()
        self.assertTrue(any("rclone backup failed" in e for e in offb.summary_errors))


###############################################################################
# Email backup and restore (GYB)
###############################################################################

class TestEmailBackupRestore(OffboardTestCase):

    def setUp(self):
        super().setUp()
        self.root = self.tmpdir()
        self.b = self.root / "mailboxes" / f"{U}_20260101"

    # --- batch ladder, throttle and terminal classification ---

    def test_ladder_from_one_hundred(self):
        """Was B1_1."""
        self.assertEqual(offb._build_batch_ladder(100), [100, 75, 50, 25, 10])

    def test_ladder_never_steps_above_start_and_always_descends(self):
        """Was B1_2."""
        for start in (500, 100, 50, 20, 10, 7, 1):
            ladder = offb._build_batch_ladder(start)
            self.assertEqual(ladder[0], start)
            self.assertEqual(ladder, sorted(ladder, reverse=True))
            self.assertEqual(len(ladder), len(set(ladder)))

    def test_ladder_floor_is_ten_unless_the_operator_asked_for_less(self):
        """Was B1_3."""
        self.assertEqual(min(offb._build_batch_ladder(100)), 10)
        self.assertEqual(offb._build_batch_ladder(3), [3])

    def test_throttling_markers_detected(self):
        """Was B2_1."""
        for marker in ("rateLimitExceeded", "userRateLimitExceeded",
                       "quotaExceeded", "backendError", "Backing off 16 seconds"):
            self.assertTrue(offb._looks_rate_limited(f"blah {marker} blah"), marker)

    def test_av_crash_is_not_treated_as_throttling(self):
        """Was B2_2."""
        crash = ("Traceback (most recent call last):\n"
                 "PermissionError: [Errno 1] Operation not permitted: '/b/a.eml'")
        self.assertFalse(offb._looks_rate_limited(crash))

    def test_terminal_markers_detected(self):
        """Was B24_1."""
        self.assertEqual(offb._looks_terminal("... failedPrecondition ..."),
                         "failedPrecondition")
        self.assertEqual(offb._looks_terminal("Mail service not enabled"),
                         "Mail service not enabled")
        self.assertIsNone(offb._looks_terminal("rateLimitExceeded, Backing off"))
        self.assertIsNone(offb._looks_terminal(""))

    def test_throttle_markers_stay_retryable(self):
        """Was B24_2: the two classifiers must never overlap."""
        for m in ("rateLimitExceeded", "userRateLimitExceeded",
                  "quotaExceeded", "Backing off", "backendError"):
            self.assertIsNone(offb._looks_terminal(m))
            self.assertTrue(offb._looks_rate_limited(m))

    def test_next_restore_action_table(self):
        ladder = [100, 75, 50]
        cases = [
            # progressed, output, quarantined, stalled, pos -> expected
            (0, "failedPrecondition", 0, 0, 0, ("STOP_TERMINAL", 0, 0)),
            (5, "failedPrecondition", 0, 0, 0, ("RETRY", 0, 0)),
            (5, "rateLimitExceeded", 0, 0, 0, ("STEP_DOWN", 1, 0)),
            (5, "rateLimitExceeded", 0, 0, 2, ("RETRY", 2, 0)),
            (5, "PermissionError: [Errno 13]", 1, 0, 0, ("RETRY", 0, 0)),
            (0, "PermissionError: [Errno 13]", 1, 2, 0, ("RETRY", 0, 0)),
            (0, "boom", 0, 0, 0, ("RETRY", 0, 1)),
            (0, "boom", 0, 2, 0, ("STOP_STALLED", 0, 3)),
            (3, "boom", 0, 2, 0, ("RETRY", 0, 0)),
            (0, "rateLimitExceeded", 0, 2, 0, ("STOP_STALLED", 1, 3)),
        ]
        for progressed, out, newly, stalled, pos, expected in cases:
            with self.subTest(out=out, progressed=progressed, stalled=stalled, pos=pos):
                self.assertEqual(
                    offb.next_restore_action(progressed, out, newly, stalled, pos, ladder),
                    expected)

    # --- quarantine ---

    def _locked_backup(self):
        (self.b / "2026" / "1").mkdir(parents=True)
        locked = self.b / "2026" / "1" / "deadbeef.eml"
        locked.write_bytes(b"poison")
        readable = self.b / "2026" / "1" / "cafe1234.eml"
        readable.write_bytes(b"fine")
        return locked, readable

    @staticmethod
    def _crash(path):
        return ("Traceback (most recent call last):\n"
                f"PermissionError: [Errno 1] Operation not permitted: '{path}'")

    def test_locked_file_named_in_a_crash_is_moved_aside(self):
        """Was B3_1."""
        locked, _ = self._locked_backup()
        with unreadable(locked):
            moved = offb.quarantine_gyb_locked_file(self.b, self._crash(locked))
        self.assertEqual(moved, ["deadbeef"])
        self.assertFalse(locked.exists())
        quarantined = (self.b.parent / f"{self.b.name}_quarantined"
                       / "2026" / "1" / "deadbeef.eml")
        self.assertTrue(quarantined.exists(), "file must be moved, never deleted")

    def test_file_readable_again_is_left_in_place(self):
        """Was B3_2: a transient AV block killed the run but reads fine now."""
        _, readable = self._locked_backup()
        self.assertEqual(offb.quarantine_gyb_locked_file(self.b, self._crash(readable)), [])
        self.assertTrue(readable.exists())

    def test_patched_gyb_warning_wording_is_also_parsed(self):
        """Was B3_3."""
        locked, _ = self._locked_backup()
        out = f"WARNING! could not read {locked} for message 60818: [Errno 13] Permission denied"
        with unreadable(locked):
            self.assertEqual(offb.quarantine_gyb_locked_file(self.b, out), ["deadbeef"])

    def test_path_outside_the_backup_is_ignored(self):
        """Was B3_4."""
        self._locked_backup()
        outside = self.root / "elsewhere.eml"
        outside.write_bytes(b"x")
        with unreadable(outside):
            self.assertEqual(offb.quarantine_gyb_locked_file(self.b, self._crash(outside)), [])
        self.assertTrue(outside.exists())

    def test_unparseable_crash_output_never_raises(self):
        """Was B3_5."""
        self._locked_backup()
        self.assertEqual(offb.quarantine_gyb_locked_file(self.b, "no paths here"), [])

    def test_skipped_messages_csv_is_appended_across_passes(self):
        locked, readable = self._locked_backup()
        with unreadable(locked):
            offb.quarantine_gyb_locked_file(self.b, self._crash(locked))
        with unreadable(readable):
            self.assertEqual(offb.quarantine_unreadable_messages(self.b), ["cafe1234"])
        csv_path = self.b.parent / f"{self.b.name}_skipped-messages.csv"
        lines = csv_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], "gmail_message_id,message_date,quarantined_file,note")
        self.assertEqual([ln.split(",")[0] for ln in lines[1:]], ["deadbeef", "cafe1234"])

    # --- backup verification ---

    def test_epoch_dated_messages_are_counted(self):
        """Was B4_1."""
        msg_db(self.b, [("1.eml", "1970-01-01 02:00:00"), ("2.eml", "2026-07-21 17:18:09"),
                        ("3.eml", "1970-01-01 02:00:00")])
        self.assertEqual(offb.count_undated_messages(self.b), 2)

    def test_healthy_backup_has_no_undated_messages(self):
        """Was B4_2."""
        msg_db(self.b, [("1.eml", "2024-01-01 00:00:00"), ("2.eml", "2026-07-21 17:18:09")])
        self.assertEqual(offb.count_undated_messages(self.b), 0)

    def test_missing_db_counts_zero_undated(self):
        """Was B4_3."""
        self.assertEqual(offb.count_undated_messages(self.b / "nope"), 0)

    def _backup(self, rows, files, quarantined=0):
        msg_db(self.b, [(f"2026/1/{i}.eml", "2026-01-01") for i in range(1, rows + 1)])
        (self.b / "2026" / "1").mkdir(parents=True)
        for i in range(1, files + 1):
            (self.b / "2026" / "1" / f"{i}.eml").write_bytes(b"x")
        if quarantined:
            qdir = self.b.parent / f"{self.b.name}_quarantined"
            qdir.mkdir()
            for i in range(quarantined):
                (qdir / f"q{i}.eml").write_bytes(b"x")

    def test_matching_backup_passes_quietly(self):
        """Was B6_1."""
        self._backup(5, 5)
        self.assertEqual(offb.verify_backup_complete(self.b), (5, 5))
        self.assertFalse(offb.summary_warnings)
        self.assertFalse(offb.summary_errors)

    def test_genuine_shortfall_is_an_error(self):
        """Was B6_2."""
        self._backup(5, 3)
        self.assertEqual(offb.verify_backup_complete(self.b), (5, 3))
        self.assertTrue(any("missing" in e for e in offb.summary_errors))

    def test_missing_db_is_an_error_and_is_not_created(self):
        """Was B6_3: (0, 0) alone passed a failed backup as an empty one, and
        sqlite3.connect() would have created the missing file."""
        self.assertEqual(offb.verify_backup_complete(self.b / "nope"), (0, 0))
        self.assertTrue(any("msg-db.sqlite" in e for e in offb.summary_errors))
        self.assertFalse((self.b / "nope").exists())

    def test_empty_valid_db_verifies_clean(self):
        msg_db(self.b, [])
        self.assertEqual(offb.verify_backup_complete(self.b), (0, 0))
        self.assertFalse(offb.summary_errors)

    def test_quarantine_accounted_shortfall_is_clean(self):
        """Was B6_4."""
        self._backup(5, 3, quarantined=2)
        offb.verify_backup_complete(self.b)
        self.assertFalse(offb.summary_errors)
        self.assertFalse(offb.summary_warnings)

    def test_shortfall_beyond_quarantine_still_errors(self):
        """Was B6_5."""
        self._backup(5, 2, quarantined=2)
        offb.verify_backup_complete(self.b)
        self.assertTrue(any("missing 1" in e for e in offb.summary_errors))

    def test_extra_files_on_disk_only_warn(self):
        """Was B6_6."""
        self._backup(3, 5)
        offb.verify_backup_complete(self.b)
        self.assertFalse(offb.summary_errors)
        self.assertTrue(any("more .eml" in w for w in offb.summary_warnings))

    # --- restore destination readiness and storage parsing ---

    def test_gmail_disabled_blocks_the_restore(self):
        """Was B7_1 and B19_1: gam exits non-zero for the unlicensed user,
        and the output text still decides."""
        for ok in (True, False):
            with self.subTest(ok=ok):
                del offb.summary_errors[:]
                fake = FakeGam([(("user", D, "show", "gmailprofile"),
                                 (ok, fixture("show_gmailprofile_not_enabled")))])
                with gam(fake):
                    self.assertFalse(offb.check_restore_destination_ready(
                        D, self.b, dry_run=False))
                self.assertTrue(any("Gmail not enabled" in e for e in offb.summary_errors))

    def test_gmail_enabled_proceeds(self):
        """Was B7_2."""
        fake = FakeGam([(("user", D, "show", "gmailprofile"),
                         (True, f"User: {D}, historyId: 50524, messagesTotal: 3296, "
                                "threadsTotal: 3180"))])
        with gam(fake):
            self.assertTrue(offb.check_restore_destination_ready(D, self.b, dry_run=False))

    def test_terabyte_limit_is_not_read_as_bytes(self):
        """Was B8_1."""
        self.assertEqual(offb._parse_gam_size(fixture("show_drivesettings"), "limit"),
                         int(329.85 * 1024 ** 4))

    def test_megabyte_usage_parsed(self):
        """Was B8_2."""
        self.assertEqual(offb._parse_gam_size(fixture("show_drivesettings"), "usage"),
                         int(148.63 * 1024 ** 2))

    def test_usage_does_not_match_usageindrive(self):
        """Was B8_3: usageInDrive is 0 KB and follows usage."""
        self.assertNotEqual(offb._parse_gam_size(fixture("show_drivesettings"), "usage"), 0)

    def test_missing_or_unparseable_size_is_none(self):
        """Was B8_5."""
        self.assertIsNone(offb._parse_gam_size(fixture("show_drivesettings"), "nosuch"))
        self.assertIsNone(offb._parse_gam_size("limit: banana", "limit"))

    def test_mailbox_estimate_subtracts_drive_usage(self):
        """Was B23_1."""
        out = (f"User: {U}\n  limit: 329.85 TB\n  usage: 12.5 GB\n"
               "  usageInDrive: 2.5 GB\n  usageInDriveTrash: 0.5 GB\n")
        with gam(FakeGam([(("user", U, "show", "drivesettings"), (True, out))])):
            est = offb._estimate_mailbox_bytes(U)
        gb = 1024 ** 3
        self.assertEqual(est, int(12.5 * gb) - int(2.5 * gb) - int(0.5 * gb))

    def test_mailbox_estimate_is_none_when_unparseable(self):
        """Was B23_2."""
        with gam(FakeGam([(("user", U, "show", "drivesettings"), (True, "garbage"))])):
            self.assertIsNone(offb._estimate_mailbox_bytes(U))
        with gam(FakeGam([(("user", U, "show", "drivesettings"), (False, ""))])):
            self.assertIsNone(offb._estimate_mailbox_bytes(U))

    # --- backup-only ---

    def test_backup_email_only_fails_on_a_short_backup(self):
        """Was B21_3."""
        def short_verify(path):
            offb.summary_error(f"Backup at {path} is missing 2 message(s)")
            return (5, 3)

        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root), \
             mock.patch.object(offb, "run_gyb", return_value=(True, "")), \
             mock.patch.object(offb, "verify_backup_complete", side_effect=short_verify):
            self.assertFalse(offb.backup_email_only(U, dry_run=False))
        self.assertNotIn("backed up via GYB", self.actions())

    def _backup_email_only_with_db(self, make_db):
        """Run backup_email_only with a GYB stand-in that leaves `make_db(path)`
        behind (or nothing, for None); returns (result, the DB path)."""
        db_path = self.root / "mailboxes" / (
            f"{U}_email_{datetime.now().strftime('%Y%m%d')}") / "msg-db.sqlite"

        def fake_gyb(args, dry_run=True, **kw):
            if make_db:
                make_db(db_path)
            return True, ""

        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root), \
             mock.patch.object(offb, "run_gyb", fake_gyb):
            return offb.backup_email_only(U, dry_run=False), db_path

    def test_backup_email_only_fails_when_gyb_left_no_db(self):
        ok, db_path = self._backup_email_only_with_db(None)
        self.assertFalse(ok)
        self.assertTrue(any("msg-db.sqlite" in e for e in offb.summary_errors))
        self.assertFalse(db_path.exists(), "verification must not create the DB")

    def test_backup_email_only_fails_when_db_has_no_messages_table(self):
        def other_table(path):
            with offb._gyb_db(path) as db:
                db.execute("CREATE TABLE unrelated(x)")

        ok, _ = self._backup_email_only_with_db(other_table)
        self.assertFalse(ok)
        self.assertTrue(any("could not be verified" in e for e in offb.summary_errors))

    def test_backup_email_only_empty_valid_db_succeeds(self):
        def empty_messages(path):
            with offb._gyb_db(path) as db:
                db.execute("CREATE TABLE messages(message_num INTEGER PRIMARY KEY, "
                           "message_filename TEXT, message_internaldate TIMESTAMP)")

        ok, _ = self._backup_email_only_with_db(empty_messages)
        self.assertTrue(ok)
        self.assertFalse(offb.summary_errors)

    def test_backup_email_only_verified_clean_succeeds(self):
        """Was B21_4."""
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root), \
             mock.patch.object(offb, "run_gyb", return_value=(True, "")) as gyb, \
             mock.patch.object(offb, "verify_backup_complete", return_value=(5, 5)):
            self.assertTrue(offb.backup_email_only(U, dry_run=False))
        self.assertIn("backed up via GYB", self.actions())
        self.assertEqual(gyb.call_args[0][0][:4], ["--email", U, "--action", "backup"])

    # --- backup folder selection ---

    def _dated_backup(self, days_ago, prefix=U):
        stamp = (datetime.now() - timedelta(days=days_ago)).strftime("%Y%m%d")
        folder = self.root / "mailboxes" / f"{prefix}_{stamp}"
        folder.mkdir(parents=True)
        (folder / "msg-db.sqlite").touch()
        return folder

    def test_force_resumes_a_recent_folder(self):
        """Was B19_3."""
        old = self._dated_backup(2)
        printed = []
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root), \
             mock.patch.object(offb, "print_info", printed.append):
            self.assertEqual(offb._select_email_backup_path(U, force=True), old)
        self.assertTrue(any("resuming into it (--force, within 30 days)." in p
                            for p in printed))

    def test_force_starts_fresh_when_the_folder_is_stale(self):
        """Was B19_3b: a folder past 30 days is likely a previous engagement."""
        old = self._dated_backup(40)
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root):
            self.assertNotEqual(offb._select_email_backup_path(U, force=True), old)

    def test_interactive_prompt_decides(self):
        """Was B19_3c."""
        old = self._dated_backup(2)
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root), \
             mock.patch.object(offb, "prompt_yes_no", return_value=True) as p:
            self.assertEqual(offb._select_email_backup_path(U), old)
        self.assertIn(f"Found an existing mailbox backup {old.name} (2 day(s) old). "
                      "Resuming into it (only new/changed content is fetched) instead "
                      "of downloading from scratch?", p.call_args[0][0])
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root), \
             mock.patch.object(offb, "prompt_yes_no", return_value=False):
            self.assertNotEqual(offb._select_email_backup_path(U), old)

    def test_declined_same_day_folder_gets_a_distinct_name(self):
        """Was B19_3d."""
        old = self._dated_backup(0)
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root), \
             mock.patch.object(offb, "prompt_yes_no", return_value=False):
            fresh = offb._select_email_backup_path(U)
        self.assertNotEqual(fresh, old)
        self.assertRegex(fresh.name, rf"^{U}_\d{{8}}_\d{{6}}$")

    def test_foreign_and_empty_folders_are_ignored(self):
        """Was B19_4."""
        (self.root / "mailboxes" / f"{U}_email_20260701").mkdir(parents=True)
        empty = self.root / "mailboxes" / f"{U}_20260702"
        empty.mkdir()
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root):
            chosen = offb._select_email_backup_path(U, force=True)
        self.assertNotEqual(chosen.name, f"{U}_email_20260701")
        self.assertNotEqual(chosen, empty)
        self.assertRegex(chosen.name, rf"^{U}_\d{{8}}$")

    def test_digits_in_the_address_do_not_confuse_the_date_stamp(self):
        user = "a_12345678b@yourdomain.com"
        old = self._dated_backup(2, prefix=user)
        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root):
            self.assertEqual(offb._select_email_backup_path(user, force=True), old)

    # --- migrate_email ---

    def _dest_gam(self):
        return FakeGam([(("info", "user"), (True, ACTIVE_USER))])

    def test_dry_run_creates_no_directories(self):
        """Was A6_1."""
        root = self.root / "offboarding_backups"
        with mock.patch.object(offb, "BACKUP_DIRECTORY", root), \
             gam(self._dest_gam()), \
             mock.patch.object(offb, "run_gyb", return_value=(True, "")):
            offb.migrate_email(U, D, dry_run=True)
            offb.backup_email_only(U, dry_run=True)
            offb.backup_drive_rclone(U, dry_run=True)
        self.assertFalse(root.exists())

    def test_short_backup_skips_the_restore(self):
        def short_verify(path):
            offb.summary_error(f"Backup at {path} is missing 2 message(s)")
            return (5, 3)

        with mock.patch.object(offb, "BACKUP_DIRECTORY", self.root), \
             gam(self._dest_gam()), \
             mock.patch.object(offb, "run_gyb", return_value=(True, "")) as gyb, \
             mock.patch.object(offb, "verify_backup_complete", side_effect=short_verify):
            offb.migrate_email(U, D, dry_run=False, force=True)
        actions = [c[0][0][3] for c in gyb.call_args_list]
        self.assertEqual(actions, ["backup"])
        self.assertNotIn("Email migrated", self.actions())

    def _reusable_backup(self, emls=2):
        (self.b / "2026" / "1").mkdir(parents=True)
        msg_db(self.b, [(f"2026/1/{i}.eml", "2026-01-01") for i in range(1, emls + 1)])
        for i in range(1, emls + 1):
            (self.b / "2026" / "1" / f"{i}.eml").write_bytes(b"x")

    def test_ctrl_c_after_a_failed_attempt_stops_without_a_quarantine_scan(self):
        self._reusable_backup()

        def restore(_args, **_kw):
            offb.shutdown_requested = True
            return False, "boom"

        with gam(self._dest_gam()), \
             mock.patch.object(offb, "run_gyb", side_effect=restore), \
             mock.patch.object(offb, "quarantine_gyb_locked_file") as crash_scan, \
             mock.patch.object(offb, "quarantine_unreadable_messages",
                               return_value=[]) as full_scan:
            offb.migrate_email(U, D, dry_run=False, reuse_backup=self.b)
        crash_scan.assert_not_called()
        full_scan.assert_called_once()   # the pre-scan before the first attempt
        self.assertTrue(any("FAILED after 1 attempt(s)" in e for e in offb.summary_errors))

    def test_successful_restore_reports_the_resume_db_count(self):
        self._reusable_backup(emls=2)
        with gam(self._dest_gam()), \
             mock.patch.object(offb, "run_gyb", return_value=(True, "")):
            offb.migrate_email(U, D, dry_run=False, reuse_backup=self.b)
        self.assertTrue(any(a.endswith("; GYB resume DB: 0 restored of 2 on disk")
                            for a in offb.summary_actions), self.actions())
        self.assertTrue(any("0 restored message(s) but 2 .eml" in w
                            for w in offb.summary_warnings))

    def test_full_resume_db_does_not_warn(self):
        self._reusable_backup(emls=2)
        restored_db(self.b, D, 2)
        with gam(self._dest_gam()), \
             mock.patch.object(offb, "run_gyb", return_value=(True, "")):
            offb.migrate_email(U, D, dry_run=False, reuse_backup=self.b)
        self.assertTrue(any(a.endswith("; GYB resume DB: 2 restored of 2 on disk")
                            for a in offb.summary_actions), self.actions())
        self.assertFalse(offb.summary_warnings)
        self.assertFalse(offb.summary_errors)


###############################################################################
# Email forwarding
###############################################################################

class TestForwarding(OffboardTestCase):

    OTHER = "already-there@yourdomain.com"

    def _forward(self, poll):
        fake = FakeGam([(("user", U, "show", "forwardingaddresses"), poll)])
        with gam(fake), clocked():
            offb.setup_forwarding(U, D, dry_run=False)
        return fake

    def _activated(self, fake):
        return bool(fake.matching("user", U, "forward", "on", D, "keep"))

    def test_accepted_target_from_captured_output_activates(self):
        """Was A2_2."""
        status = fixture("show_forwardingaddresses_accepted").replace(
            "successor@example.com", D)
        fake = self._forward((True, status))
        self.assertTrue(self._activated(fake))
        self.assertEqual(fake.argv()[0], f"user {U} add forwardingaddress {D}")
        self.assertIn(f"Email forwarding set to {D} (keep copy)", self.actions())

    def test_another_accepted_address_does_not_verify_a_pending_target(self):
        """Was A2_1."""
        status = (f"User: {U}, Show 2 Forwarding Addresses\n"
                  f"  Forwarding Address: {self.OTHER}, Verification Status: accepted\n"
                  f"  Forwarding Address: {D}, Verification Status: pending\n")
        fake = self._forward((True, status))
        self.assertFalse(self._activated(fake))

    def test_forwarding_pending_after_60s_is_reported_not_activated(self):
        """Was A2_3: one summary error for the outcome, not one per poll."""
        fake = self._forward((False, "transient API error"))
        self.assertGreater(len(fake.matching("user", U, "show", "forwardingaddresses")), 1)
        self.assertFalse(self._activated(fake))
        self.assertEqual(len(offb.summary_errors), 1)
        self.assertIn("still awaiting confirmation", offb.summary_errors[0])
        self.assertIn(f"gam user {U} forward on {D} keep", offb.summary_errors[0])

    def test_poll_loop_exits_early_on_shutdown(self):
        def poll(_args, _kw):
            offb.shutdown_requested = True
            return True, fixture("show_forward_off")

        fake = self._forward(poll)
        self.assertEqual(len(fake.matching("user", U, "show", "forwardingaddresses")), 1)
        self.assertFalse(self._activated(fake))

    def test_failed_registration_is_an_error(self):
        fake = FakeGam([(("user", U, "add", "forwardingaddress"), (False, "Invalid"))])
        with gam(fake):
            offb.setup_forwarding(U, D, dry_run=False)
        self.assertEqual(len(fake.calls), 1)
        self.assertTrue(any("registration failed" in e for e in offb.summary_errors))


###############################################################################
# Shared Drives
###############################################################################

SD_LIST = (f"Getting all Shared Drives for {U}\n"
           f"Got 1 Shared Drive for {U}...\n"
           "User,id,name,role\n"
           f"{U},0ABC123,Client Contracts,organizer\n")

# Real `gam print drivefileacls` shape: indexed permissions.N.* columns.
SD_ACL_SOLE = (
    "Owner,id,permissions,permissions.0.emailAddress,permissions.0.role\n"
    f"{U},0ABC123,1,{U},organizer\n"
)
SD_ACL_SHARED = (
    "Owner,id,permissions,permissions.0.emailAddress,permissions.0.role,"
    "permissions.1.emailAddress,permissions.1.role\n"
    f"{U},0ABC123,2,{U},organizer,{D},organizer\n"
)


class TestSharedDrives(OffboardTestCase):

    def _check(self, listing, acl=(True, SD_ACL_SOLE)):
        fake = FakeGam([(("user", U, "print", "shareddrives"), listing),
                        (("user", U, "print", "drivefileacls"), acl)])
        with gam(fake):
            return offb.check_shared_drives(U, dry_run=False)

    def test_sole_organizer_is_flagged_as_orphaned(self):
        """Was B11_1."""
        orphaned = self._check((True, SD_LIST))
        self.assertEqual(len(orphaned), 1)
        self.assertIn("Client Contracts", orphaned[0])
        self.assertTrue(any("no organizer other than" in w for w in offb.summary_warnings))

    def test_another_organizer_means_not_orphaned(self):
        """Was B11_2."""
        self.assertEqual(self._check((True, SD_LIST), (True, SD_ACL_SHARED)), [])
        self.assertTrue(offb.summary_warnings, "content is still not backed up")

    def test_no_shared_drives_is_quiet(self):
        """Was B11_3."""
        self.assertEqual(self._check((True, "Got 0 Shared Drives\nUser,id,name,role\n")), [])
        self.assertFalse(offb.summary_warnings)

    def test_gam_failure_never_raises_and_blocks(self):
        """Was B11_4: an unreadable list is not "no drives" -- the scorched-earth
        gate only blocks a non-empty return."""
        blockers = self._check((False, ""))
        self.assertEqual(len(blockers), 1)
        self.assertIn("could not be read", blockers[0])
        self.assertTrue(any("inconclusive" in w for w in offb.summary_warnings))

    def test_dry_run_makes_no_calls(self):
        """Was B11_5."""
        fake = FakeGam()
        with gam(fake):
            self.assertEqual(offb.check_shared_drives(U, dry_run=True), [])
        self.assertEqual(fake.calls, [])

    def test_unreadable_acl_is_unknown_not_orphaned_but_still_blocks(self):
        """Was B11_6: a failed read is not evidence of absence."""
        blockers = self._check((True, SD_LIST), (False, ""))
        self.assertTrue(any("unknown" in w.lower() for w in offb.summary_warnings))
        self.assertFalse(any("no organizer other than" in w for w in offb.summary_warnings))
        self.assertEqual(len(blockers), 1)

    def test_unparseable_drive_list_is_not_silence(self):
        """Was B11_7."""
        blockers = self._check((True, "garbage"))
        self.assertEqual(len(blockers), 1)
        self.assertIn("could not be parsed", blockers[0])
        self.assertTrue(any("inconclusive" in w for w in offb.summary_warnings))

    def test_remedy_command_runs_as_the_leaver(self):
        """Was B11_8: a non-member cannot grant themselves organizer."""
        printed = []
        with mock.patch.object(offb, "print_error", printed.append):
            self._check((True, SD_LIST))
        self.assertTrue(any(f"gam user {U} add drivefileacl" in p for p in printed))

    def test_zero_shared_drives_exit_60_is_not_a_failed_read(self):
        """Was B11_9: GAM 7.48.01 exits 60 for a user in no shared drive,
        having printed the CSV header; run_gam must forgive it."""
        def exit_60(cmd, **_kw):
            return subprocess.CompletedProcess(
                cmd, 60, stdout="User,id,name,role\n",
                stderr=f"Got 0 Shared Drives for {U}...")

        printed = []
        with mock.patch.object(offb.subprocess, "run", exit_60), \
             mock.patch.object(offb, "print_warning", printed.append):
            self.assertEqual(offb.check_shared_drives(U, dry_run=False), [])
        self.assertFalse(any("Could not list" in p for p in printed))
        self.assertFalse(offb.summary_warnings)
        self.assertFalse(offb.summary_errors)


###############################################################################
# Argument parsing
###############################################################################

class TestArgParsing(OffboardTestCase):

    def _parse(self, *argv):
        with mock.patch.object(offb.sys, "argv", ["offboard_user.py", *argv]), \
             mock.patch("sys.stderr", io.StringIO()):
            return offb.parse_args()

    def _usage_error(self, *argv):
        with self.assertRaises(SystemExit) as cm:
            self._parse(*argv)
        self.assertEqual(cm.exception.code, 2, " ".join(argv))

    def test_restore_batch_size_one_is_a_usage_error(self):
        # GYB's single-message path never commits the resume DB mid-run.
        self._usage_error("--restore-batch-size", "1")

    def test_restore_batch_size_outside_gyb_range_is_a_usage_error(self):
        self._usage_error("--restore-batch-size", "0")
        self._usage_error("--restore-batch-size", "101")
        self.assertEqual(self._parse("--restore-batch-size", "10").restore_batch_size, 10)

    def test_scorched_earth_requires_doit_and_force(self):
        self._usage_error("--scorched-earth")
        self._usage_error("--scorched-earth", "--doit")
        self._usage_error("--scorched-earth", "--force")

    def test_scorched_earth_refuses_backup_and_transfer_flags(self):
        for extra in (["--backup-drive"], ["--backup-email"], ["--unsuspend"],
                      ["--no-suspend"], ["--reuse-email-backup", "/x"],
                      ["--all-transfer-to", D], ["--drive-to", D], ["--email-to", D],
                      ["--alias-to", D], ["--calendar-to", D], ["--forward-to", D]):
            with self.subTest(flag=extra[0]):
                self._usage_error("--doit", "--force", "--scorched-earth", *extra)

    def test_scorched_earth_skips_transfers_but_keeps_the_snapshot(self):
        args = self._parse("--doit", "--force", "--scorched-earth")
        self.assertFalse(args.no_snapshot)
        for flag in ("no_drive", "no_email", "no_alias", "no_calendar",
                     "no_forward", "no_delegates", "no_auto_reply"):
            self.assertTrue(getattr(args, flag), flag)

    def test_reuse_email_backup_requires_a_destination(self):
        self._usage_error("--reuse-email-backup", "/x")
        self.assertEqual(self._parse("--reuse-email-backup", "/x", "--email-to", D)
                         .reuse_email_backup, "/x")
        self.assertEqual(self._parse("--reuse-email-backup", "/x", "--all-transfer-to", D)
                         .reuse_email_backup, "/x")

    def test_reuse_email_backup_refuses_flags_it_would_ignore(self):
        for extra in ("--no-email", "--no-transfer", "--backup-drive",
                      "--backup-email", "--unsuspend"):
            with self.subTest(flag=extra):
                self._usage_error("--reuse-email-backup", "/x", "--email-to", D, extra)

    def test_unsuspend_and_no_suspend_are_contradictory(self):
        self._usage_error("--unsuspend", "--no-suspend")

    def test_no_transfer_implies_every_transfer_skip(self):
        args = self._parse("--no-transfer")
        for flag in ("no_drive", "no_email", "no_alias", "no_calendar",
                     "no_forward", "no_delegates", "no_auto_reply"):
            self.assertTrue(getattr(args, flag), flag)

    def test_eof_at_the_user_prompt_exits_cleanly(self):
        """Was A3_1: the only test that runs the script for real; it exits
        at the email prompt, before any dependency check or gam call."""
        with real_subprocess(), tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(SCRIPT_PATH)],
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                cwd=tmp, timeout=60,
            )
        self.assertNotIn("Traceback", result.stderr, result.stderr)
        self.assertEqual(result.returncode, 2)


###############################################################################
# Summary honesty, phase running and exit state
###############################################################################

class TestSummaryAndExit(OffboardTestCase):

    def test_delete_failure_is_not_reported_as_deleted(self):
        """Was A1_2."""
        with gam(FakeGam([((), (False, "err"))])):
            offb.delete_user(U, dry_run=False)
        self.assertNotIn("USER DELETED", self.actions())
        self.assertTrue(any("Deletion failed" in e for e in offb.summary_errors))

    def test_delete_success_is_reported(self):
        """Was A1_2b."""
        fake = FakeGam()
        with gam(fake):
            offb.delete_user(U, dry_run=False)
        self.assertEqual(fake.argv(), [f"delete user {U}"])
        self.assertIn(f"USER DELETED: {U}", self.actions())

    def test_calendar_failure_is_not_reported_as_an_action(self):
        """Was A1_4."""
        with gam(FakeGam([((), (False, "err"))])):
            offb.transfer_calendar(U, D, dry_run=False)
        self.assertNotIn("Calendar editor access", self.actions())

    def test_calendar_grant_is_reported_with_the_right_argv(self):
        fake = FakeGam()
        with gam(fake):
            offb.transfer_calendar(U, D, dry_run=False)
        self.assertEqual(fake.argv(), [f"user {U} add calendaracls {U} writer user:{D}"])
        self.assertIn(f"Calendar editor access granted to {D}", self.actions())

    def test_auto_reply_failure_is_not_reported_as_an_action(self):
        """Was A1_4b."""
        with gam(FakeGam([((), (False, "err"))])):
            offb.set_auto_reply(U, dry_run=False)
        self.assertNotIn("Auto-reply message configured", self.actions())

    def test_summary_error_sets_the_exit_code(self):
        offb.summary_error("boom")
        self.assertEqual(offb.exit_code, 1)
        offb.summary_warning("meh")
        self.assertEqual(offb.exit_code, 1)

    def test_a_phase_that_errors_is_recorded(self):
        """Was B16_1."""
        failures = []
        with offb.record_failure("Drive transfer", failures):
            offb.summary_error("Drive transfer lost 3 files")
        self.assertEqual(failures, ["Drive transfer"])

    def test_a_clean_phase_is_not_recorded(self):
        """Was B16_2."""
        failures = []
        with offb.record_failure("Drive transfer", failures):
            offb.summary_action("Transferred 244 files")
        self.assertEqual(failures, [])

    def test_an_exception_still_records_and_propagates(self):
        """Was B16_3."""
        failures = []
        with self.assertRaises(RuntimeError):
            with offb.record_failure("Email migration", failures):
                offb.summary_error("boom")
                raise RuntimeError("boom")
        self.assertEqual(failures, ["Email migration"])

    def test_run_phase_turns_an_exception_into_a_summary_error(self):
        def boom():
            raise RuntimeError("boom")

        self.assertIsNone(offb.run_phase("Drive transfer", boom))
        self.assertIn("Drive transfer exception: boom", offb.summary_errors)
        self.assertEqual([name for name, _ in offb.phase_timings], ["Drive transfer"])

    def test_run_phase_holds_a_phase_that_recorded_an_error(self):
        hold = []
        offb.run_phase("Drive transfer", offb.summary_error, "lost files", hold=hold)
        self.assertEqual(hold, ["Drive transfer"])
        self.assertEqual(offb.run_phase("Aliases", lambda x: x * 2, 21, hold=hold), 42)
        self.assertEqual(hold, ["Drive transfer"])

    def test_summary_prints_every_section_with_its_marker(self):
        offb.summary_action("did a thing")
        offb.summary_warning("hmm")
        offb.summary_skip("nah")
        offb.summary_error("bad")
        offb.phase_timings.append(("Kill switch", 1.5))
        lines = []
        with mock.patch.object(offb, "_emit", lambda _level, text: lines.append(text)):
            offb.print_summary(dry_run=True)
        joined = "\n".join(lines)
        for expected in ("DRY RUN ONLY", "Actions completed (1):", "  + did a thing",
                         "Warnings (1):", "  ~ hmm", "Skipped (1):", "  - nah",
                         "Errors (1):", "  ! bad", "  Kill switch: 1.5s", "  Total: 1.5s"):
            self.assertIn(expected, joined)

    def test_console_is_reconfigured_to_utf8(self):
        """Was B14_1: cp1252 consoles lost the very line naming a missing file."""
        calls = []

        class FakeStream:
            def reconfigure(self, **kw):
                calls.append(kw)

        with mock.patch.object(offb.sys, "stdout", FakeStream()), \
             mock.patch.object(offb.sys, "stderr", FakeStream()):
            offb._force_utf8_console()
        self.assertEqual(calls, [{"encoding": "utf-8", "errors": "replace"}] * 2)

    def test_a_stream_that_cannot_reconfigure_is_survivable(self):
        """Was B14_2."""
        class Stubborn:
            def reconfigure(self, **kw):
                raise ValueError("underlying buffer detached")

        with mock.patch.object(offb.sys, "stdout", Stubborn()), \
             mock.patch.object(offb.sys, "stderr", Stubborn()):
            offb._force_utf8_console()


###############################################################################
# Repo hygiene
###############################################################################

class TestRepoHygiene(unittest.TestCase):

    def test_header_version_matches_script_version(self):
        """Was A7_1."""
        import re
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        m = re.search(r"^Version:\s+(\S+)", source, re.MULTILINE)
        self.assertIsNotNone(m, "no 'Version:' line in the header")
        self.assertEqual(m.group(1), offb.SCRIPT_VERSION)

    def test_version_file_matches_script_version(self):
        """Was A7_3: check_for_updates compares against this file."""
        version_file = SCRIPT_PATH.parent / "VERSION"
        self.assertEqual(version_file.read_text(encoding="utf-8").strip(),
                         offb.SCRIPT_VERSION)

    def test_no_crlf_line_endings(self):
        for path in (SCRIPT_PATH, Path(__file__)):
            self.assertNotIn(b"\r\n", path.read_bytes(), path.name)

    def test_max_restore_attempts_is_the_documented_ceiling(self):
        self.assertEqual(offb.MAX_RESTORE_ATTEMPTS, 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)
