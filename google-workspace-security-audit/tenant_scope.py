#!/usr/bin/env python3
"""
Google Workspace Security Audit (Tenant Scoping Audit)
=============================================================================
Copyright (c) 2026 Paul Ogier, Outsource House (South Africa)
Website: https://osh.co.za | Email: support@osh.co.za
Training provided by Taming.Tech (https://taming.tech)

Google Workspace GAM7 Course on Udemy   https://taming.tech/GAMCourse
Google Workspace Admin Course on Udemy  https://www.taming.tech/GoogleWorkspaceAdmin
Google Workspace End-User Course on Udemy  https://www.taming.tech/TheCompleteWorkspaceCourse

Credit: after six months of using this script to audit our own clients, Dirk
Grobler's request for help with his tenant-scoping batch script on the
google-apps-manager group inspired us to publish it for the community
(https://groups.google.com/g/google-apps-manager/c/9r_AeuiWOSg).

The tenant-settings checks against the CISA SCuBA Google Workspace baselines
use CISA's ScubaGoggles (https://github.com/cisagov/ScubaGoggles, public
domain) as a guide: its rules for what passes, and its reading of Google's
documented policy defaults. The checks themselves are this script's own and
run on the data GAM collects.

Licence: Apache License 2.0 (full text in LICENSE at the repository root)

In plain English:
  - Free to use, including for commercial purposes.
  - Modify and redistribute freely; closed-source derivatives are allowed.
  - PLEASE KEEP THE ATTRIBUTION above intact. If you redistribute this
    file (modified or not), the copyright, contact, and course-link block
    at the top must stay in place. This is the one real obligation the
    licence puts on you (Apache 2.0 clause 4(c)) and it is what lets
    users find the original author and the training resources. Removing
    or replacing it is a licence violation.
  - No warranty: the disclaimer below is part of the licence terms.
  - "OSH", "Outsource House", and "Taming.Tech" are trademarks and are
    not licensed for use in your own product or marketing names
    (Apache 2.0 clause 6).

DISCLAIMER & LIMITATION OF LIABILITY:
This software is provided "AS IS", without warranty of any kind, express or
implied. The authors (Paul Ogier, Outsource House) and training providers
(Taming.Tech) accept NO RESPONSIBILITY for any damages, data loss, or system
issues that may arise from its use.

YOU ASSUME ALL RISK ASSOCIATED WITH THE USE OF THIS SOFTWARE.
=============================================================================

Author:       Paul Ogier
Created:      2026-08-15
Updated:      2026-10-21
Version:      1.7.2
Status:       Production
Python:       3.9+
Dependencies: GAM ADV X (GAM7) only. Stdlib only on the Python side.

What it does
------------
A READ-ONLY Google Workspace tenant audit. Three stages, each restartable:

  collect -> check -> render

  collect : runs a registry of GAM7 print/report commands, each writing one
            CSV into a timestamped run directory. manifest.json records
            completed modules so a re-run resumes instead of restarting.
  check   : a findings engine reads ONLY the collected CSVs and produces
            findings (severity, plain-English title, what it means,
            remediation, evidence rows).
  render  : a single self-contained HTML report (print stylesheet -> clean
            PDF), compared with the previous completed run of the same
            customer, and an internal qa_report.html that says whether the
            report is ready to send. Preflight results and any modules that
            could not run are always listed - nothing is silently absent.

Safety posture
--------------
Every GAM command issued is a read (print / report / info / oauth info /
check serviceaccount). GAM's filelist cannot use admin access, so a
non-member scan silently returns zero rows; each Shared Drive is therefore
listed as one of its own active members, and nobody's access changes. ONE
opt-in exception: --grant-temp-access, for a drive no member can list,
temporarily adds the auditing admin as organizer, scans, then removes that
access again. Off by default; without it those drives are reported as
UNSCANNED.

Module tiers
------------
  1  tenant-level, cheap (domains, users, groups, admins, shared drive
     metadata, devices, policies, tokens, Vault, reports, the last
     30 days of admin log, risky sign-ins and Alert Center alerts, and
     Classroom courses, rosters, invitations and guardians on Education
     tenants)
  2  per-user Gmail/Calendar settings via domain-wide delegation
     (send-as, delegates, forwarding, filters, IMAP/POP, ASPs,
     backup-code counts, calendar ACLs)
  3  heavy Drive scans, skippable (external sharing outbound and inbound,
     Shared Drive external exposure, Sites inventory)
  4  off by default, enabled with --full (vacation, browsers,
     context-aware access levels, mailbox profiles, file counts)
  DNS  per-domain MX/SPF/DKIM/DMARC via the tamingdns.com MCP endpoint,
     with a dns.google fallback when it is unreachable

Example usage:
  python tenant_scope.py --list                      # show the module registry
  python tenant_scope.py --admin admin@example.com   # full default audit
  python tenant_scope.py --admin admin@example.com --only users,groups,dns
  python tenant_scope.py --admin admin@example.com --skip-tier 3
  python tenant_scope.py --admin admin@example.com --run-dir <dir>  # resume
  python tenant_scope.py --admin admin@example.com --full --grant-temp-access
  python tenant_scope.py --render-only --run-dir <dir>  # re-render, no GAM
  python tenant_scope.py --tenant clienta --admin admin@clienta.example
  python tenant_scope.py --all --yes --no-open       # every tenant in tenants.json

Exit codes: 0 complete; 1 preflight failed or wrong tenant; 2 complete but
some modules could not run; 130 interrupted. --all returns the worst, in that order of priority.

Notes that matter when reading results:
  - "all users" in GAM iterates ACTIVE users only. By default this audit does
    the same and says so in the report; --include-suspended adds suspended
    users to the per-user modules.
  - Backup verification codes are LIVE codes. The collector keeps only the
    count; the codes themselves are never written to disk.
  - Spam/Trash, suspended-user mail settings and 2-day report lag are stated
    in the report where they apply.

Changelog
  2026-10-21 - v1.7.2 - A --run-dir holding another customer's run is refused
                        at preflight instead of being resumed under this
                        tenant. A Shared Drive scan that left drives unscanned
                        is now partial, so the report is held for review and
                        the run exits 2. A check that fails to run, or a
                        temporary organizer grant that could not be removed,
                        also holds the report and exits 2; the QA report
                        names the drive and the admin to remove. 294 tests.
  2026-10-07 - v1.7.1 - Rendering error fixed: the report no longer needs
                        JavaScript to open, so a viewer that blocks scripts
                        shows it instead of a blank page. The credit names
                        the tool and links to the repository instead of
                        saying who prepared the report, and is readable on
                        the dark header. Repository renamed to
                        GoogleWorkspaceScripts; the update check reads the
                        new path.
  2026-10-07 - v1.7.0 - New findings: files made public or shared outside
                        in the last 30 days (Drive audit log), domain-wide
                        delegation granted in the last 30 days, Gmail
                        filters matching business-email-compromise
                        patterns, super admins without a phishing-resistant
                        second factor, files shared with target audiences,
                        and settings below the CISA SCuBA Google Workspace
                        baseline (each row cites its requirement). Settings
                        the Policy API omits are judged at Google's
                        documented default (policy_defaults.json). Each run
                        is compared with the last completed run of the same
                        customer (resolved, new, rows new this month), with
                        a posture score and six-run trend; a finding whose
                        data was incomplete in either run is not compared,
                        never resolved, and a module that ran in neither run
                        is left out. --tenants/--tenant/--all with a
                        customer-ID hard stop and break-glass accounts;
                        qa_report.html delivery gate; exit codes 0/1/2/130,
                        with not-applicable modules (Classroom without an
                        Education licence) not counted. Shared Drive scan
                        reads ACLs only for items shared beyond the drive's
                        members. Gmail filters run by default. Log lines
                        carry one tag.
  2026-10-02 - v1.6.2 - Shared Drives are listed as one of their own
                        active members (organizers first), so no grant is
                        needed and an unlicensed audit admin works;
                        --grant-temp-access is only the fallback for a
                        drive no member can list, and a refused grant
                        reports Google's reason. Any resume re-runs drives
                        left UNSCANNED. My Drive scan limit 1h -> 4h.
                        Admin app passwords are HIGH, not CRITICAL: they
                        cannot sign in to the Admin console, only to
                        mail, calendar and contacts apps. Target audiences
                        are no longer reported as external domain shares.
  2026-10-01 - v1.6.1 - Classroom, after the first run on an Education
                        tenant: rosters, class invitations and guardians
                        are collected; classes with outside members or
                        invitations are HIGH, classes owned by a deleted
                        or suspended account MEDIUM, and letting
                        self-declared (pending) teachers create classes
                        MEDIUM; guardians and pending guardian invitations
                        are listed with their age. Course owners are read.
                        GAM's progress lines ahead of the invitations CSV
                        are stripped so the file parses. Classroom's own
                        classroom_teachers group is no longer reported as
                        ownerless. 225 tests.
  2026-10-01 - v1.6.0 - Four new checks from the collected policies: super
                        admin self-recovery on, Gmail Safety protections off
                        (per switch, per OU), Chat spaces open to every
                        outside domain, and a list of checklist settings no
                        API exposes so the report never implies they were
                        checked. Also from policies: alert rules switched
                        off, Takeout per service, Drive for desktop on any
                        device, Meet safety, mail delegation, third-party
                        app access (raw), and the security features the
                        tenant's edition includes but does not use (DLP,
                        Context-Aware Access, trust rules, security center,
                        advanced mobile management), silent on editions
                        without them. New default reads: 30 days of admin
                        log, risky sign-in events and Alert Center alerts
                        (alerts moved out of --full). Preflight waits 300s for `info domain` and
                        accepts a non-zero exit that still printed the
                        tenant identity (seen on a tenant created that day).
                        Same day, from an audit of the audit: the report
                        lists every check that ran and found nothing, and
                        findings_evidence.csv carries every evidence row;
                        data collected since 1.0.0 but read by nothing now
                        has checks (send-as, forwarding addresses on file,
                        group members and owners, vacation, Vault exports,
                        Google-suspended accounts, new accounts, recovery
                        phones, 2SV enforcement on admins, root-OU users,
                        per-drive copy controls, app inventory, weak
                        passwords and second factors from the usage
                        report); SPF, DKIM and MX get findings beside
                        DMARC; read-only Gmail and Drive scopes count as
                        risky; five more hand-check rows (domain-wide
                        delegation first); Classroom settings and courses
                        on Education tenants. gmailprofile and filecounts
                        moved to --full. After a live run on a
                        Business Standard tenant: Google's blocked
                        sensitive actions get their own MEDIUM finding
                        (with the action named) instead of counting as
                        HIGH risky sign-ins, and a missing recovery email
                        no longer counts as an at-risk factor. 215 tests.
  2026-09-30 - v1.5.1 - Repository folder renamed from "Tenant Scoping
                        Audit" to google-workspace-security-audit; the
                        startup update check now reads VERSION from the new
                        path. A VERSION copy stays at the old path so
                        earlier releases keep checking. No functional
                        change.
  2026-09-01 - v1.5.0 - Tenant-level modules collect four at a time; the
                        tier-3 Drive sweeps and calendar ACLs run as one GAM
                        batch per module instead of one process per user;
                        DNS domains are checked in parallel. A timeout now
                        kills GAM's batch children too, and Ctrl+C lets the
                        running module finish (exit 130). Fixes: the
                        external-forwarding check read a column GAM7 does
                        not emit and could never fire; licence waste fired
                        on every SKU when the licenses module had not run,
                        and summed archived-user seats into the parent SKU;
                        a selection filter that left nobody widened the scan
                        to every mailbox; --render-only without --run-dir
                        rendered an empty "clean" report; the log file
                        carried ANSI codes; a resumed run kept a DNS
                        fallback decided by a blip. App-password check now
                        covers delegated admins; archived accounts no longer
                        count as unenrolled or dormant. Load-tested on a
                        130k-file tenant: 5m51s, no rate-limit retries.
                        148 tests.
  2026-08-15 - v1.3.7 - First public release. Everything from the internal
                        1.x line: external-share findings (named users,
                        whole domains, inbound), people-centric checks
                        (dormancy tiers, mailbox delegation, at-risk
                        composite, offboarding debt), policy checks from
                        the Policy API (password, session length, per-OU
                        2SV, shared-drive defaults, per-service on/off),
                        licence waste, admin-role hygiene. 104 unit tests.
  2026-08-15 - v1.0.0 - Initial release: preflight gates, module registry
                        (tiers 1-4 + DNS), manifest-based resume, findings
                        engine, self-contained HTML report.
"""

import argparse
import csv
import hashlib
import io
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Set, Tuple

# `print policies formatjson` puts a whole policy JSON in one cell; the csv
# module's default 128 KB field limit raises mid-check on a large DLP rule.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

###############################################################################
# CONFIGURATION
###############################################################################

SCRIPT_VERSION = "1.7.2"

# [OPTIONAL] Startup check against the remote VERSION file. Fail-silent.
CHECK_FOR_UPDATES = True
UPDATE_CHECK_URL = (
    "https://raw.githubusercontent.com/PaulOgier/GoogleWorkspaceScripts/main/"
    "google-workspace-security-audit/VERSION"
)

# [IMPORTANT] The GAM command name or full path. If "gam" is not on PATH the
# preflight also tries the macOS installer location (~/bin/gam7/gam - the
# installer writes a shell alias, not a PATH entry, so which() misses it)
# and the conventional Windows path C:\GAM7\gam.exe.
GAM_COMMAND = "gam"

# The report credit, shown in the header and footer of every report. Plain
# HTML with no script, so the report opens wherever it is shared.
CREDIT_NAME = "Outsource House (OSH.co.za)"
CREDIT_URL = "https://github.com/PaulOgier/GoogleWorkspaceScripts"
SCRIPT_DIR = Path(__file__).resolve().parent
# Where tenants.json is looked for when --tenants is not given, in order.
# JSON rather than TOML: the script supports Python 3.9 and tomllib is 3.11.
TENANTS_FILE_CANDIDATES = [
    Path("~/.osh/workspace-audit/tenants.json").expanduser(),
    SCRIPT_DIR / "tenants.json",
]
# Modules behind the Critical checks: if one of these failed, the report may
# be missing its most serious findings and must not go out unreviewed.
DELIVERY_CRITICAL_MODULES = ("users", "forwards", "asps", "mydrive_external",
                             "shareddrive_external")
# Google's documented default for each policy field the API leaves out when
# it was never changed (policy_defaults.json says where it comes from).
POLICY_DEFAULTS_FILE = SCRIPT_DIR / "policy_defaults.json"
# Exit codes, worst last, for --all to report the worst across tenants.
EXIT_PRIORITY = [0, 2, 1, 130]
FOLDER_MIME = "application/vnd.google-apps.folder"
GAM_FALLBACK_PATHS = [
    Path.home() / "bin" / "gam7" / "gam",
    Path(r"C:\GAM7\gam.exe"),
]

# [IMPORTANT] Root directory for audit runs. Each run gets its own
# tenant_audit_<domain>_<timestamp> subfolder. Override with --output-dir.
OUTPUT_DIRECTORY = Path("./tenant_audit_runs")

# [OPTIONAL] DNS checks. Primary path is the tamingdns.com MCP endpoint
# (stateless JSON-RPC POST per check, responses arrive already shaped as
# findings). If it is unreachable the module falls back to dns.google over
# HTTPS with minimal presence checks, and the report says which path ran.
TAMINGDNS_MCP_URL = "https://tamingdns.com/mcp"
DOH_URL = "https://dns.google/resolve"

# Thresholds used by the findings engine.
DORMANT_DAYS = 90            # licensed account with no login for this long
ANYONE_LINK_SCALE = 20       # "anyone with the link" files before it's a finding
EVIDENCE_ROWS = 10           # evidence rows shown per finding in the report
ACTIVITY_DAYS = 30           # look-back for admin log, sign-ins and alerts

# Login event names from Google's Reports API login activity appendix
# (developers.google.com/workspace/admin/reports/v1/appendix/activity/login,
# read 2026-09-14). Risk events are each worth a human look; failures are
# only counted.
LOGIN_RISK_EVENTS = [
    "suspicious_login", "suspicious_login_less_secure_app",
    "suspicious_programmatic_login",
    "user_signed_out_due_to_suspicious_session_cookie",
    "account_disabled_password_leak", "account_disabled_hijacked",
    "account_disabled_spamming", "account_disabled_spamming_through_relay",
    "account_disabled_generic", "gov_attack_warning",
    "email_forwarding_out_of_domain",
]
# Google judged the session risky and refused the action, so nothing changed.
# Kept out of LOGIN_RISK_EVENTS: on a live Business Standard tenant all 42
# "risk" events were these (Google Ads periodic checks, app grants), which a
# HIGH reading "suspicious logins, hijacks" misdescribed.
LOGIN_BLOCKED_EVENTS = ["risky_sensitive_action_blocked"]
LOGIN_FAILURE_EVENTS = ["login_failure"]
PASSWORD_MIN_LENGTH = 12     # policy minimums below this are flagged
SESSION_MAX_SECONDS = 14 * 86400   # Google's default web session length
LICENCE_WASTE_MIN_GAP = 5    # unused seats before licence waste is flagged
LICENCE_WASTE_MIN_FRACTION = 0.2   # ...and as a share of seats owned
ADMIN_SPRAWL_FRACTION = 0.2  # share of active users holding any admin role
ADMIN_SPRAWL_MIN_USERS = 10  # below this many users, sprawl is not scored

# Rough per-user bytes each tier-2/3 module tends to produce, used only for
# the disk-space preflight estimate. Deliberately generous.
DISK_COST_PER_USER = {2: 20_000, 3: 200_000}

###############################################################################
# COLOURS / CONSOLE
###############################################################################


class Colours:
    """ANSI colour codes; bright variants for dark-background readability."""
    RED = '\033[1;91m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[1;93m'
    BLUE = '\033[1;94m'
    CYAN = '\033[1;96m'
    RESET = '\033[0m'

    @staticmethod
    def strip_colours():
        Colours.RED = Colours.GREEN = Colours.YELLOW = ''
        Colours.BLUE = Colours.CYAN = Colours.RESET = ''


def _enable_windows_ansi() -> bool:
    """Enable ANSI escape processing on the Windows console (Windows 10+)."""
    if os.name != 'nt':
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


if os.name == 'nt':
    if not (os.environ.get('WT_SESSION') or os.environ.get('TERM_PROGRAM')
            or _enable_windows_ansi()):
        Colours.strip_colours()
elif not sys.stdout.isatty():
    Colours.strip_colours()


def _force_utf8_console():
    """Keep non-ASCII file/user names from killing console logging on
    Windows, where the streams default to the ANSI code page."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


###############################################################################
# LOGGING / DISPLAY
###############################################################################

logger: Optional[logging.Logger] = None
shutdown_requested = False


def signal_handler(_signum, _frame):
    global shutdown_requested
    if shutdown_requested:
        print(f"\n{Colours.RED}Forced exit.{Colours.RESET}")
        with _live_procs_lock:
            for proc in list(_live_procs):
                _kill_tree(proc)
        sys.exit(2)
    shutdown_requested = True
    print(f"\n{Colours.YELLOW}[WARN] Ctrl+C received. Finishing the current "
          f"module, then stopping. The run directory can be resumed with "
          f"--run-dir. Press Ctrl+C again to force quit.{Colours.RESET}")


signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, signal_handler)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class _PlainFormatter(logging.Formatter):
    """The console gets colour; the log file must not (every line would
    otherwise carry escape codes on a tty run)."""

    def format(self, record):
        return _ANSI_RE.sub("", super().format(record))


def setup_logging(run_dir: Path):
    global logger
    _force_utf8_console()
    # No level name: print_warning and print_error tag their own lines, and
    # the level name doubled it ("[ERROR] [ERROR] [CRITICAL] ...").
    fmt = "%(asctime)s %(message)s"
    file_handler = logging.FileHandler(run_dir / "tenant_scope.log",
                                       encoding="utf-8")
    file_handler.setFormatter(_PlainFormatter(fmt))
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter(fmt))
    # force=True: a second call in one process (main() is callable) would
    # otherwise be a silent no-op and log into the previous run directory.
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, console],
                        force=True)
    logger = logging.getLogger(__name__)
    return logger


def _emit(level: str, text: str):
    if logger is None:
        print(text)
    elif level == 'error':
        logger.error(text)
    elif level == 'warning':
        logger.warning(text)
    else:
        logger.info(text)


def print_header(title: str):
    _emit('info', "")
    _emit('info', f"{Colours.BLUE}{'=' * 60}")
    _emit('info', f"  {title}")
    _emit('info', f"{'=' * 60}{Colours.RESET}")


def print_success(msg: str):
    _emit('info', f"{Colours.GREEN}[OK] {msg}{Colours.RESET}")


def print_warning(msg: str):
    _emit('warning', f"{Colours.YELLOW}[WARN] {msg}{Colours.RESET}")


def print_error(msg: str):
    _emit('error', f"{Colours.RED}[ERROR] {msg}{Colours.RESET}")


def print_info(msg: str):
    _emit('info', f"{Colours.CYAN}[INFO] {msg}{Colours.RESET}")


def check_for_updates():
    """Warn if a newer version exists. Any failure is swallowed."""
    if not CHECK_FOR_UPDATES:
        return
    try:
        req = urllib.request.Request(
            UPDATE_CHECK_URL, headers={"User-Agent": "tenant_scope.py"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            remote = resp.read().decode("utf-8", errors="replace").strip().splitlines()[0].strip()
        local_t = tuple(int(p) for p in SCRIPT_VERSION.split("."))
        remote_t = tuple(int(re.sub(r"\D", "", p) or 0) for p in remote.split("."))
        if remote_t > local_t:
            print_warning(f"A newer version is available: v{remote} "
                          f"(you are running v{SCRIPT_VERSION}) - "
                          f"https://github.com/PaulOgier/GoogleWorkspaceScripts/releases")
    except Exception:
        pass


###############################################################################
# GAM EXECUTION
###############################################################################

GAM_PATH = GAM_COMMAND  # resolved in preflight

# GAM processes currently running, so a forced exit can take their batch
# children with them.
_live_procs: set = set()
_live_procs_lock = threading.Lock()


def _popen_isolated(cmd, **kwargs) -> subprocess.Popen:
    """Start GAM in its own process group / session.

    Two reasons. Ctrl+C in the terminal goes to the whole foreground group,
    so without this the GAM child died at the same moment the handler
    promised to "finish the current module". And a timeout kill has to reach
    GAM's batch children, which needs a group to signal.
    """
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(cmd, **kwargs)


def _kill_tree(proc: subprocess.Popen):
    """Kill a GAM process and its batch children.

    proc.kill() reaches the parent only; with auto_batch_min the children are
    separate processes that keep writing the redirect CSV after the parent is
    gone, so the row count recorded and the file on disk would diverge.
    """
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


def locate_gam() -> Optional[str]:
    """Find the gam binary: PATH first, then known installer locations."""
    found = shutil.which(GAM_COMMAND)
    if found:
        return found
    for candidate in GAM_FALLBACK_PATHS:
        if candidate.is_file():
            return str(candidate)
    return None


PROGRESS_EVERY = 30   # seconds between GAM progress lines echoed to the console


def _echo_progress(pipe, collected: List[str]):
    """Keep every stderr line, echo one every PROGRESS_EVERY seconds.

    A Shared Drive scan can run for hours with nothing on screen, which reads
    as a hang. GAM's own counters are the honest progress signal, so show
    them - throttled, and only once a command has been running long enough
    that silence would worry someone.
    """
    last = time.time()
    for line in pipe:
        collected.append(line)
        now = time.time()
        if line.strip() and now - last >= PROGRESS_EVERY:
            last = now
            _emit('info', "    " + line.strip()[:120])
    pipe.close()


def run_gam(args: List[str], timeout: int = 900,
            dry_run: bool = False) -> Tuple[int, str, str]:
    """Run one GAM command, shell=False, returning (rc, stdout, stderr).

    stdout is the clean CSV/report payload; every GAM progress line
    ("Getting all...", per-user counters) goes to stderr. Callers must keep
    the two apart - mixing them corrupts the CSVs.
    """
    cmd = [GAM_PATH] + args
    if dry_run:
        print_info("DRY RUN: " + " ".join(cmd))
        return 0, "", ""
    _emit('info', "Running: " + " ".join(cmd))
    try:
        # stdout goes to a temp file rather than a pipe: a large Drive scan
        # can outrun a pipe buffer, and a file survives the kill on timeout so
        # partial results are still returned. stderr is read live so GAM's
        # "Got N files..." counters reach the console during a long scan.
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8",
                                    errors="replace") as out_fh:
            proc = _popen_isolated(
                cmd, stdout=out_fh, stderr=subprocess.PIPE, text=True,
                encoding="utf-8", errors="replace")
            with _live_procs_lock:
                _live_procs.add(proc)
            collected: List[str] = []
            reader = threading.Thread(target=_echo_progress,
                                      args=(proc.stderr, collected),
                                      daemon=True)
            reader.start()
            timed_out = False
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_tree(proc)
                rc, timed_out = -1, True
                proc.wait()
            finally:
                with _live_procs_lock:
                    _live_procs.discard(proc)
            reader.join(timeout=5)
            out_fh.seek(0)
            out = out_fh.read()
        err = "".join(collected)
        if timed_out:
            err = (err + f"\nTimed out after {timeout}s").strip()
        return rc, out, err
    except FileNotFoundError:
        return -2, "", f"GAM not found at {GAM_PATH}"
    except Exception as exc:  # keep one module failure from killing the run
        return -3, "", f"{type(exc).__name__}: {exc}"


def is_header_only(text: str) -> bool:
    """True when GAM emitted at most a CSV header (an empty result set)."""
    return len([ln for ln in text.strip().splitlines() if ln.strip()]) <= 1


def csv_data_rows(source) -> int:
    """Number of data rows in a CSV (a Path or the text itself).

    Counted through the csv reader, not by lines: vacation messages and
    filter criteria carry newlines inside a cell, and a line count reports
    more rows than there are. Streams a file, so a redirect CSV of hundreds
    of MB is never held in memory.
    """
    def count(fh):
        return max(0, sum(1 for row in csv.reader(fh) if row) - 1)
    if isinstance(source, Path):
        with open(source, newline="", encoding="utf-8",
                  errors="replace") as fh:
            return count(fh)
    return count(io.StringIO(source))


###############################################################################
# CSV HELPERS
###############################################################################

def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.is_file():
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def col(row: Dict[str, str], *names: str) -> str:
    """Case-insensitive column lookup, first match wins.

    GAM header casing follows the underlying API field names and has shifted
    between versions; matching by lowercase name keeps the checks engine
    working across that.
    """
    # Exact-key fast path first: every check calls this several times per
    # row, and rebuilding the lowered dict was the only measurable CPU cost
    # in the checks stage on a large file-share CSV.
    for name in names:
        if name in row:
            return (row[name] or "").strip()
    lowered = {k.lower().strip(): v for k, v in row.items() if k}
    for name in names:
        if name.lower() in lowered:
            return (lowered[name.lower()] or "").strip()
    return ""


def truthy(value: str) -> bool:
    return value.strip().lower() in ("true", "yes", "1", "enabled")


def email_domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip() if "@" in address else ""


def write_rows(path: Path, rows: List[Dict[str, str]]):
    """Write dict rows with the union of all headers (per-user modules like
    filecounts have data-dependent columns that differ between users)."""
    headers: List[str] = []
    for row in rows:
        for key in row:
            if key not in headers:
                headers.append(key)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers, restval="")
        writer.writeheader()
        writer.writerows(rows)


###############################################################################
# MODULE REGISTRY
###############################################################################

# DWD scope URLs per module family. Client-auth (Directory/Reports API)
# modules are not scope-gated here: a standard GAM install authorises all of
# them, and a missing one fails loudly at collect time and lands on the
# "not checked" list anyway.
SCOPE_GMAIL_BASIC = "https://www.googleapis.com/auth/gmail.settings.basic"
SCOPE_GMAIL_SHARING = "https://www.googleapis.com/auth/gmail.settings.sharing"
# users.getProfile accepts any of mail.google.com / gmail.modify /
# gmail.readonly / gmail.metadata. GAM's standard DWD set grants gmail.modify
# (verified PASS on dev 2026-08-15; gmail.readonly FAILed there), so gate on
# that rather than readonly.
SCOPE_GMAIL_MODIFY = "https://www.googleapis.com/auth/gmail.modify"
SCOPE_DRIVE = "https://www.googleapis.com/auth/drive"
SCOPE_CALENDAR = "https://www.googleapis.com/auth/calendar"

# Registry entry keys:
#   key, title, tier, args (list, or None for special collectors),
#   collector ("simple" | "per_user" | "mydrive_external" | "sd_external" |
#              "swm_external" | "sites" | "dns" | "backupcodes"),
#   scopes (DWD URLs to verify before running), timeout, size_risk.
MODULES: List[Dict] = [
    # ---- Tier 1: tenant level ----
    dict(key="domains", title="Domains (incl. aliases)", tier=1,
         args=["print", "domains"]),
    dict(key="domainaliases", title="Domain aliases", tier=1,
         args=["print", "domainaliases"]),
    dict(key="orgs", title="Organisational units", tier=1,
         args=["print", "orgs"]),
    dict(key="ou_counts", title="User counts by OU", tier=1,
         args=["print", "usercountsbyorgunit"]),
    dict(key="licenses", title="Licence assignments", tier=1,
         args=["print", "licenses"]),
    dict(key="users", title="Users (security fields + licences)", tier=1,
         args=["print", "users", "fields",
               "primaryEmail,suspended,archived,lastLoginTime,fullname,"
               "orgUnitPath,creationTime,isenrolledin2sv,isenforcedin2sv,"
               "recoveryemail,recoveryphone,isadmin,isdelegatedadmin",
               "licenses"]),
    dict(key="admins", title="Admin role assignments", tier=1,
         args=["print", "admins"]),
    dict(key="adminroles", title="Admin roles", tier=1,
         args=["print", "adminroles"]),
    dict(key="schema", title="Custom user schemas", tier=1,
         args=["print", "schema"]),
    dict(key="groups", title="Groups + settings", tier=1,
         args=["print", "groups", "fields", "email,name,directmemberscount",
               "settings"]),
    dict(key="group_members", title="Group members", tier=1,
         args=["print", "group-members", "fields", "role,type,email,status"]),
    dict(key="resources", title="Calendar resources", tier=1,
         args=["print", "resources", "allfields"]),
    dict(key="buildings", title="Buildings", tier=1,
         args=["print", "buildings"]),
    dict(key="features", title="Resource features", tier=1,
         args=["print", "features"]),
    dict(key="shareddrives", title="Shared Drives (admin view)", tier=1,
         args=["print", "shareddrives", "adminaccess"]),
    dict(key="shareddriveacls", title="Shared Drive ACLs", tier=1,
         args=["print", "shareddriveacls", "oneitemperrow"]),
    dict(key="shareddriveorganizers", title="Shared Drive organizers", tier=1,
         args=["print", "shareddriveorganizers"]),
    dict(key="mobile", title="Mobile devices", tier=1,
         args=["print", "mobile"]),
    dict(key="cros", title="ChromeOS devices", tier=1,
         args=["print", "cros"]),
    dict(key="ssoprofiles", title="Inbound SSO profiles", tier=1,
         args=["print", "inboundssoprofiles"]),
    dict(key="ssoassignments", title="Inbound SSO assignments", tier=1,
         args=["print", "inboundssoassignments"]),
    dict(key="datatransfers", title="Data transfers", tier=1,
         args=["print", "datatransfers"]),
    dict(key="userinvitations", title="Unmanaged-account invitations", tier=1,
         args=["print", "userinvitations"]),
    dict(key="vaultmatters", title="Vault matters", tier=1,
         args=["print", "vaultmatters"]),
    dict(key="vaultholds", title="Vault holds", tier=1,
         args=["print", "vaultholds"]),
    dict(key="vaultexports", title="Vault exports", tier=1,
         args=["print", "vaultexports"]),
    # Education tenants only; the collector skips itself when licenses.csv
    # holds no Education SKU. All four run live on an Education Fundamentals
    # tenant (2026-10-01); column names in the checks come from that run.
    dict(key="courses", title="Classroom courses (Education only)", tier=1,
         args=["print", "courses", "owneremail"], collector="classroom",
         csv_header="id,", timeout=1800),
    dict(key="course_participants", title="Classroom rosters (Education only)",
         tier=1, args=["print", "course-participants", "show", "all"],
         collector="classroom", csv_header="courseId,", timeout=1800),
    dict(key="classroominvitations",
         title="Classroom pending invitations (Education only)", tier=1,
         args=["print", "classroominvitations"], collector="classroom",
         csv_header="courseId,", timeout=1800),
    dict(key="guardians", title="Classroom guardians (Education only)",
         tier=1, args=["print", "guardians", "all", "showstudentemails"],
         collector="classroom", csv_header="studentEmail,", timeout=1800),
    dict(key="report_customers", title="Customer usage report", tier=1,
         args=["report", "customers"]),
    dict(key="report_users", title="Per-user usage report (~2-day lag)",
         tier=1, args=["report", "users"], timeout=1800),
    dict(key="policies", title="Tenant policies (formatjson)", tier=1,
         args=["print", "policies", "formatjson"]),
    dict(key="tokens", title="OAuth tokens (all users)", tier=1,
         args=["all", "users", "print", "tokens"], timeout=1800),
    dict(key="report_admin", title="Admin audit log (last 30 days)", tier=1,
         args=["report", "admin", "start", f"-{ACTIVITY_DAYS}d"],
         timeout=1800),
    # Only the risk events and failures: an unfiltered login report on a
    # large tenant is one row per sign-in.
    dict(key="report_login", title="Risky sign-in events (last 30 days)",
         tier=1, args=["report", "login", "start", f"-{ACTIVITY_DAYS}d",
                       "events", ",".join(LOGIN_RISK_EVENTS
                                          + LOGIN_BLOCKED_EVENTS
                                          + LOGIN_FAILURE_EVENTS)],
         timeout=1800),
    # The cheap monthly view of new Drive exposure. Event names checked
    # against the Reports API Drive appendix, 2026-10-07; tier 1 because it
    # is one tenant-level report, like the login report above.
    dict(key="report_drive_sharing",
         title="Drive sharing changes (last 30 days, audit log)", tier=1,
         args=["report", "drive", "start", f"-{ACTIVITY_DAYS}d", "events",
               "change_document_visibility,change_user_access"],
         timeout=1800),
    # createTime filter is mandatory in practice: one unfiltered "User
    # reported spam spike" alert embeds every reported message body.
    dict(key="alerts", title="Alert Center alerts (last 30 days)", tier=1,
         args=["print", "alerts", "filter",
               'createTime >= "' + (datetime.now(timezone.utc)
                                    - timedelta(days=ACTIVITY_DAYS))
               .strftime("%Y-%m-%dT%H:%M:%SZ") + '"']),
    # ---- Tier 2: per-user via DWD ----
    dict(key="sendas", title="Send-as addresses", tier=2,
         args=["all", "users", "print", "sendas", "compact"],
         scopes=[SCOPE_GMAIL_BASIC]),
    dict(key="delegates", title="Mailbox delegates", tier=2,
         args=["all", "users", "print", "delegates"],
         scopes=[SCOPE_GMAIL_SHARING]),
    dict(key="forwards", title="Mail forwarding", tier=2,
         args=["all", "users", "print", "forwards"],
         scopes=[SCOPE_GMAIL_SHARING]),
    dict(key="forwardingaddresses", title="Forwarding addresses", tier=2,
         args=["all", "users", "print", "forwardingaddresses"],
         scopes=[SCOPE_GMAIL_SHARING]),
    # Default since v1.7.0: filters hiding payment mail are one of the first
    # signs of a mailbox takeover, worth a sweep every month.
    dict(key="filters", title="Gmail filters", tier=2,
         args=["all", "users", "print", "filters"],
         scopes=[SCOPE_GMAIL_BASIC], timeout=3600),
    dict(key="imap", title="IMAP settings", tier=2,
         args=["all", "users", "print", "imap"],
         scopes=[SCOPE_GMAIL_BASIC]),
    dict(key="pop", title="POP settings", tier=2,
         args=["all", "users", "print", "pop"],
         scopes=[SCOPE_GMAIL_BASIC]),
    dict(key="asps", title="App-specific passwords", tier=2,
         args=["all", "users", "print", "asps"]),
    dict(key="backupcodes", title="Backup verification codes (count only)",
         tier=2, args=["all", "users", "print", "backupcodes"],
         collector="backupcodes"),
    dict(key="calendaracls", title="Primary calendar ACLs", tier=2,
         args=["all", "users", "print", "calendaracls", "primary"],
         scopes=[SCOPE_CALENDAR]),
    # ---- Tier 3: heavy Drive scans ----
    dict(key="mydrive_external", title="My Drive files shared externally",
         tier=3, args=None, collector="mydrive_external",
         scopes=[SCOPE_DRIVE], timeout=14400),
    # 3600s killed a 58-user tenant's scan with 0 rows (2026-10-01).
    # Applied per drive, not per module. 3600s killed a single large drive
    # mid-scan on a 660GB drive (2026-08-17) and lost every row for it.
    dict(key="shareddrive_external",
         title="Shared Drive files shared externally", tier=3,
         args=None, collector="sd_external",
         scopes=[SCOPE_DRIVE], timeout=14400),
    dict(key="sharedwithme_external",
         title="Files shared in from outside (inbound)", tier=3,
         args=None, collector="swm_external",
         scopes=[SCOPE_DRIVE], timeout=3600),
    dict(key="sites", title="Google Sites inventory", tier=3,
         args=None, collector="sites", scopes=[SCOPE_DRIVE], timeout=3600),
    # ---- Tier 4: off by default (--full) ----
    dict(key="vacation", title="Vacation responders", tier=4,
         args=["all", "users", "print", "vacation"],
         scopes=[SCOPE_GMAIL_BASIC], timeout=3600),
    dict(key="browsers", title="Managed browsers", tier=4,
         args=["print", "browsers"]),
    # Tier 4 since round 9: both are full per-user sweeps (one needs the
    # gmail.modify DWD scope) and no check reads them; the raw CSVs are for
    # sizing a migration, not for the findings.
    dict(key="gmailprofile", title="Gmail profiles (mailbox sizing)", tier=4,
         args=["all", "users", "print", "gmailprofile"],
         scopes=[SCOPE_GMAIL_MODIFY]),
    dict(key="filecounts", title="Drive file counts", tier=4,
         args=["all", "users", "print", "filecounts"],
         scopes=[SCOPE_DRIVE], timeout=3600),
    dict(key="caalevels", title="Context-aware access levels", tier=4,
         args=["print", "caalevels"]),
    # ---- DNS ----
    dict(key="dns", title="Mail DNS (MX/SPF/DKIM/DMARC)", tier=1,
         args=None, collector="dns"),
]

# print caalevels without a GCP-org role grant fails with this text; that is
# an authorisation gap, not a script failure.
CAALEVELS_AUTH_ERROR = "Access Context Manager"

# An `all users` print exits non-zero when ANY user fails; these stderr
# markers mean individual users were skipped (no Gmail licence, service off),
# not that the module itself broke. Seen live on dev: a Gmail-disabled user
# turned every Gmail-settings module into "exit 73" while the remaining
# users' data was fine.
PER_USER_SKIP_MARKERS = (
    "Service/App not enabled",
    "Service not applicable",
    "Does not exist",
)

# A per-user line naming an account that has no such service at all, or no
# longer exists: there is nothing to read for it, so it is not a gap.
_NO_SERVICE_RE = re.compile(
    r"User: ([^,\s]+), .*(?:Service/App not enabled|Service not applicable|"
    r"Does not exist)")
_FAILURE_RE = re.compile(r"error|fail|timed out|denied|quota|exceed|invalid|"
                         r"not authori", re.IGNORECASE)
NO_SERVICE_NOTE = "nothing to read for account(s) without the service: "


def no_service_only(err: str) -> Optional[List[str]]:
    """The accounts GAM skipped for having no such service, when that is the
    ONLY kind of failure in its stderr; None when anything else failed.

    Without this, one account with Gmail switched off left every Gmail module
    partial every month, so its findings were never compared month to month
    and the delivery gate always held."""
    users = []
    for line in err.splitlines():
        text = line.strip()
        if not text or text.startswith(("Getting ", "Got ")):
            continue
        match = _NO_SERVICE_RE.search(text)
        if match:
            users.append(match.group(1).lower())
        elif _FAILURE_RE.search(text):
            return None
    return sorted(set(users))


def _no_service_result(rows: int, users: List[str]) -> Tuple[str, int, str]:
    return (("empty" if rows == 0 else "ok"), rows,
            NO_SERVICE_NOTE + ", ".join(users))


# print browsers without Chrome browser management access fails 403.
BROWSERS_AUTH_ERROR = "Forbidden"

MODULE_BY_KEY = {m["key"]: m for m in MODULES}

# The external-share pm recipe. `pm not domain "d1,d2"` is WRONG (domain
# takes a single regex; a comma list matches nothing and `not` then matches
# every ACL) - hence notdomainlist throughout.
def external_pm_args(internal_domains: List[str]) -> List[str]:
    doms = ",".join(sorted(internal_domains))
    return ["pm", "typelist", "user,group", "notrole", "owner",
            "notdomainlist", doms, "em",
            "pm", "type", "domain", "notdomainlist", doms, "em",
            "pm", "type", "anyone", "em",
            "pmfilter", "oneitemperrow"]


###############################################################################
# RUN CONTEXT / MANIFEST
###############################################################################

class RunContext:
    """Everything the collect/check/render stages share for one run."""

    def __init__(self, run_dir: Path, args):
        self.run_dir = run_dir
        self.args = args
        self.manifest_path = run_dir / "manifest.json"
        self.manifest: Dict = {"modules": {}, "preflight": [], "meta": {}}
        if self.manifest_path.is_file():
            try:
                self.manifest = json.loads(
                    self.manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                print_warning("manifest.json unreadable; starting a fresh one")
        self.internal_domains: List[str] = self.manifest["meta"].get(
            "internal_domains", [])
        self.admin: str = args.admin or self.manifest["meta"].get("admin", "")
        self.failed_scopes: List[str] = []
        self._rows_cache: Dict[str, List[Dict[str, str]]] = {}
        self._policy_cache: Optional[List[Dict]] = None
        self._log_lock = threading.Lock()
        # (module key, usable) pairs the running check asked about, and the
        # checks that ran over real data and raised nothing (for the report).
        self.consulted: List[Tuple[str, bool]] = []
        self.clean_checks: List[Tuple[str, str]] = []
        # Names of checks that raised: their findings are missing, so the
        # delivery gate and the exit code must not read the run as complete.
        self.check_errors: List[str] = []

    def save(self):
        self.manifest["meta"]["internal_domains"] = self.internal_domains
        self.manifest["meta"]["admin"] = self.admin
        self.manifest_path.write_text(
            json.dumps(self.manifest, indent=2), encoding="utf-8")

    def module_status(self, key: str) -> str:
        return self.manifest["modules"].get(key, {}).get("status", "")

    def set_module(self, key: str, status: str, rows: int = 0, note: str = ""):
        self._rows_cache.pop(key, None)
        if key == "policies":
            self._policy_cache = None
        self.manifest["modules"][key] = {
            "status": status, "rows": rows, "note": note,
            "completed_at": datetime.now().isoformat(timespec="seconds")}
        self.save()

    def csv_path(self, key: str) -> Path:
        return self.run_dir / f"{key}.csv"

    def rows(self, key: str) -> List[Dict[str, str]]:
        """Parsed rows for a module, cached.

        The checks engine reads users.csv 13 times and policies.csv 5 times in
        one pass. Harmless on a 37-user tenant; on a few thousand users the
        heavy CSVs run to hundreds of MB and every re-read is a silent stall.
        set_module drops the entry, so a module collected after its file was
        read never serves a stale one.
        """
        if key not in self._rows_cache:
            self._rows_cache[key] = read_csv_rows(self.csv_path(key))
        return self._rows_cache[key]

    def stderr_log(self, key: str, text: str):
        """GAM progress output goes to a side log, keeping the console and
        the CSVs clean while preserving the full trail."""
        if not text.strip():
            return
        # Tier-1 modules collect in parallel; the lock keeps one module's
        # block from landing inside another's.
        with self._log_lock, open(self.run_dir / "gam_stderr.log", "a",
                                  encoding="utf-8") as fh:
            fh.write(f"\n===== {key} =====\n{text.strip()}\n")


###############################################################################
# PREFLIGHT
###############################################################################

def https_reachable(host: str, timeout: int = 5) -> bool:
    try:
        req = urllib.request.Request(f"https://{host}/", method="HEAD",
                                     headers={"User-Agent": "tenant_scope.py"})
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True  # got an HTTP response; the network path works
    except (urllib.error.URLError, socket.timeout, OSError):
        return False


def parse_info_domain(output: str) -> Dict[str, str]:
    """Pull Primary Domain and Customer ID out of `gam info domain`."""
    info = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key == "primary domain":
            info["primary_domain"] = value.strip()
        elif key == "customer id":
            info["customer_id"] = value.strip()
    return info


def parse_serviceaccount_check(output: str) -> Tuple[List[str], List[str]]:
    """Parse per-scope PASS/FAIL lines from `check serviceaccount scopes`.

    Returns (passed_scope_urls, failed_scope_urls). The command prints one
    line per tested scope containing the URL and PASS or FAIL, then
    "All scopes PASSED!" on full success.
    """
    passed, failed = [], []
    for line in output.splitlines():
        match = re.search(r"(https://\S+)", line)
        if not match:
            continue
        url = match.group(1).rstrip(",")
        # Anchor on the ", PASS" / ", FAIL" cell, not any word starting with
        # FAIL: a future "... FAILED to open" hint line would otherwise skip
        # a module.
        if re.search(r",\s*FAIL\b", line):
            failed.append(url)
        elif re.search(r",\s*PASS\b", line):
            passed.append(url)
    return passed, failed


def selected_modules(args) -> List[Dict]:
    """Apply --only / --skip / tier selection to the registry."""
    only = [k.strip() for k in (args.only or "").split(",") if k.strip()]
    skip = [k.strip() for k in (args.skip or "").split(",") if k.strip()]
    skip_tiers = set(args.skip_tier or [])
    for key in only + skip:
        if key not in MODULE_BY_KEY:
            print_error(f"Unknown module key: {key} (see --list)")
            sys.exit(2)
    chosen = []
    for mod in MODULES:
        if only:
            if mod["key"] in only:
                chosen.append(mod)
            continue
        if mod["key"] in skip:
            continue
        if mod["tier"] in skip_tiers:
            continue
        if mod["tier"] == 4 and not args.full:
            continue
        if mod["key"] == "dns" and args.no_dns:
            continue
        chosen.append(mod)
    return chosen


def preflight(ctx: RunContext, modules: List[Dict]) -> bool:
    """Gates 1-3 are hard stops; 4-5 degrade with a clear consequence.

    Everything lands in a check/result/consequence table that opens the run
    log and reappears in the report appendix.
    """
    global GAM_PATH
    args = ctx.args
    table: List[Tuple[str, str, str]] = []
    ok = True

    # Gate 1: GAM present and running.
    located = locate_gam()
    if not located:
        table.append(("GAM7 binary", "NOT FOUND",
                      "Install GAM7 or set GAM_COMMAND; run aborted"))
        ok = False
    else:
        GAM_PATH = located
        rc, out, err = run_gam(["version"], timeout=60)
        first = (out or err).strip().splitlines()[0] if (out or err).strip() else ""
        if rc == 0:
            table.append(("GAM7 binary", f"{located} ({first})", "-"))
        else:
            table.append(("GAM7 binary", f"{located} but `gam version` failed",
                          "Run aborted"))
            ok = False

    # Gate 2: internet.
    if ok:
        if https_reachable("www.googleapis.com"):
            table.append(("Internet (www.googleapis.com)", "reachable", "-"))
        else:
            table.append(("Internet (www.googleapis.com)", "UNREACHABLE",
                          "Run aborted"))
            ok = False
    dns_selected = any(m["key"] == "dns" for m in modules)
    if ok and dns_selected:
        reachable = https_reachable("tamingdns.com")
        if reachable:
            table.append(("DNS checker (tamingdns.com)", "reachable", "-"))
        else:
            table.append(("DNS checker (tamingdns.com)", "unreachable",
                          "DNS module falls back to dns.google (minimal checks)"))
        # Written on both branches: a resumed run must not inherit a fallback
        # decided by a network blip on the first attempt.
        ctx.manifest["meta"]["dns_fallback"] = not reachable

    # Gate 3: which tenant is this? Wrong-tenant audit is the worst silent
    # failure, and no per-tenant guard exists - so echo and confirm.
    if ok:
        # On a tenant created the same day, `info domain` walks back through
        # usage reports that do not exist yet and returns after ~171s with
        # "Start date can not be earlier than ...". 120s aborted that run.
        rc, out, err = run_gam(["info", "domain"], timeout=300)
        # That same run also EXITS NON-ZERO after printing a complete identity
        # block, so a non-zero rc is only a failure when the identity is missing.
        # A timeout never counts: the tenant must be positively identified.
        parsed = parse_info_domain(out)
        identified = bool(parsed.get("primary_domain")
                          and parsed.get("customer_id"))
        if rc != 0 and not (identified and rc > 0):
            table.append(("Tenant identity (gam info domain)", "FAILED",
                          "Run aborted"))
            ctx.stderr_log("preflight", err)
            ok = False
        else:
            info = parse_info_domain(out)
            # The raw output also carries per-SKU seat counts; keep it for
            # the licence-waste check (a second call would be pure waste).
            (ctx.run_dir / "domaininfo.txt").write_text(out, encoding="utf-8")
            domain = info.get("primary_domain", "?")
            customer = info.get("customer_id", "?")
            saved = ctx.manifest["meta"].get("customer_id")
            if saved and saved != "?" and customer != saved:
                # --run-dir holds another customer's completed modules, which
                # a resume would skip and then report as this tenant's.
                table.append(("Tenant", f"{domain} (customer {customer})",
                              f"NOT {saved} as this run directory holds; "
                              "run aborted"))
                ctx.manifest["preflight"] = [list(r) for r in table]
                ctx.save()
                print_error(f"Wrong run directory: GAM answered for "
                            f"{customer} ({domain}), but {ctx.run_dir} holds "
                            f"a run for {saved}. Use a new --run-dir.")
                return False
            ctx.manifest["meta"]["primary_domain"] = domain
            ctx.manifest["meta"]["customer_id"] = customer
            expected = (getattr(args, "tenant_entry", None) or {}).get(
                "customer_id")
            if expected and customer != expected:
                # The GAM config named for this tenant answers for another
                # one. Never collect: the report would carry the wrong
                # client's data under this client's name.
                table.append(("Tenant", f"{domain} (customer {customer})",
                              f"NOT {expected} as tenants.json says; run "
                              "aborted"))
                ctx.manifest["preflight"] = [list(r) for r in table]
                ctx.save()
                print_error(f"Wrong tenant: GAM answered for {customer} "
                            f"({domain}), tenants.json expects {expected}.")
                return False
            table.append(("Tenant", f"{domain} (customer {customer})",
                          "Confirmed by operator" if not args.yes
                          else "Confirmed via --yes"))
            print_header("TENANT CONFIRMATION")
            print_info(f"Primary domain : {domain}")
            print_info(f"Customer ID    : {customer}")
            if not args.yes:
                try:
                    answer = input("Audit THIS tenant? [y/N]: ").strip().lower()
                except EOFError:
                    # No console to answer with: a cron job, a pipe, an ssh
                    # command with no tty. Refuse rather than assume yes.
                    print_error("No console to confirm the tenant on. Re-run "
                                "with --yes once the domain above is the one "
                                "you meant to audit.")
                    return False
                if answer not in ("y", "yes"):
                    print_error("Tenant not confirmed; nothing was collected.")
                    return False

    # Gate 4 (degrade): authorisation for the DWD modules actually selected.
    if ok:
        rc, out, err = run_gam(["oauth", "info"], timeout=120)
        if rc == 0:
            granted = len(re.findall(r"https://", out))
            table.append(("Client OAuth (gam oauth info)",
                          f"{granted} scopes granted", "-"))
        else:
            table.append(("Client OAuth (gam oauth info)", "FAILED",
                          "Tenant-level modules may fail; each failure is "
                          "reported per module"))
            ctx.stderr_log("preflight", err)

        needed = sorted({s for m in modules for s in m.get("scopes", [])})
        if needed and ctx.admin:
            rc, out, err = run_gam(
                ["user", ctx.admin, "check", "serviceaccount", "scopes",
                 ",".join(needed)], timeout=300)
            combined = out + "\n" + err
            passed, failed = parse_serviceaccount_check(combined)
            ctx.failed_scopes = failed
            if failed:
                affected = sorted({m["key"] for m in modules
                                   if set(m.get("scopes", [])) & set(failed)})
                table.append(("Service account DWD scopes",
                              f"{len(failed)} scope(s) FAILED",
                              "Modules skipped (not authorised): "
                              + ", ".join(affected)))
                print_warning("DWD scopes missing. GAM printed the client ID "
                              "and Admin console path to authorise; see the "
                              "run log.")
                ctx.stderr_log("preflight_dwd", combined)
            else:
                table.append(("Service account DWD scopes",
                              f"all {len(needed)} required scopes PASS", "-"))
        elif needed:
            table.append(("Service account DWD scopes",
                          "NOT CHECKED (--admin not given)",
                          "Per-user modules will be attempted unverified"))

    # Gate 5 (degrade): output location sanity + disk estimate.
    if ok:
        try:
            probe = ctx.run_dir / ".write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            table.append(("Output directory writable", str(ctx.run_dir), "-"))
        except OSError as exc:
            table.append(("Output directory writable", f"NO ({exc})",
                          "Run aborted"))
            ok = False
        synced_markers = ("icloud", "mobile documents", "dropbox",
                          "google drive", "onedrive", "cloudstorage")
        lowered = str(ctx.run_dir).lower()
        if any(marker in lowered for marker in synced_markers):
            table.append(("Cloud-synced output path", "LIKELY",
                          "Large CSVs will churn the sync client; consider "
                          "--output-dir on a local disk"))
        user_count = ctx.manifest["meta"].get("user_count", 0)
        if not user_count:
            # Order-of-magnitude only; refined after the users module runs.
            user_count = 100
        estimate = sum(DISK_COST_PER_USER.get(m["tier"], 0) * user_count
                       for m in modules)
        try:
            free = shutil.disk_usage(ctx.run_dir).free
            verdict = "-"
            if estimate > free:
                verdict = "Estimated output exceeds free space; run aborted"
                ok = False
            table.append(("Disk space",
                          f"~{estimate // 1_000_000} MB estimated, "
                          f"{free // 1_000_000} MB free", verdict))
        except OSError:
            table.append(("Disk space", "could not measure", "-"))

    ctx.manifest["preflight"] = [list(row) for row in table]
    ctx.save()

    print_header("PREFLIGHT")
    width = max(len(row[0]) for row in table) + 2
    for check, result, consequence in table:
        line = f"{check:<{width}} {result}"
        if consequence and consequence != "-":
            line += f"  -> {consequence}"
        _emit('info', line)
    return ok


###############################################################################
# COLLECT
###############################################################################

def active_users(ctx: RunContext) -> List[str]:
    rows = ctx.rows("users")
    return [col(r, "primaryEmail") for r in rows
            if col(r, "primaryEmail") and not truthy(col(r, "suspended"))]


def suspended_users(ctx: RunContext) -> List[str]:
    rows = ctx.rows("users")
    return [col(r, "primaryEmail") for r in rows
            if col(r, "primaryEmail") and truthy(col(r, "suspended"))]


def audited_users(ctx: RunContext) -> List[str]:
    users = active_users(ctx)
    if ctx.args.include_suspended:
        users += suspended_users(ctx)
    return users


PER_USER_TIMEOUT_SECONDS = 10   # per mailbox, for whole-tenant `all users` scans


def module_timeout(ctx: RunContext, mod: Dict, default: int) -> int:
    """Module timeout, scaled by tenant size for whole-tenant scans.

    `gam all users print ...` walks every mailbox inside one process, so a
    flat 900s is ample at 40 users and kills the module outright on a larger
    tenant - losing every row, not just the slow ones (reported by Kim
    Nilsson, 2026-08-17). A timeout is a ceiling, not a budget: raising it
    costs nothing on a tenant that finishes early.
    """
    base = mod.get("timeout", default)
    args = mod.get("args") or []
    if [a.lower() for a in args[:2]] != ["all", "users"]:
        return base
    users = ctx.manifest["meta"].get("user_count", 0)
    return max(base, users * PER_USER_TIMEOUT_SECONDS)


AUTO_BATCH_MIN = 10   # users in one command before GAM forks it into a batch
SCAN_THREADS = 20     # GAM processes per batch; gam.cfg default is 5
NEVER_LOGGED_IN = ("", "never", "1970-01-01t00:00:00.000z")


def scan_user_list(ctx: RunContext) -> Optional[Path]:
    """Write the mailbox list for the per-user scans, or None to use `all users`.

    Returns None when users.csv has not been collected yet, so a lone
    `--only sendas` still works.
    """
    if not ctx.rows("users"):
        return None
    wanted = set(audited_users(ctx))
    emails = []
    skipped_never = 0
    for row in ctx.rows("users"):
        email = col(row, "primaryEmail")
        if email not in wanted:
            continue
        last = col(row, "lastLoginTime").strip().lower()
        if ctx.args.skip_never_logged_in and last[:24] in NEVER_LOGGED_IN:
            skipped_never += 1
            continue
        emails.append(email)
    if not emails:
        # Not None: None means "use `all users`", which would scan every
        # mailbox in the tenant - the opposite of what the filters asked.
        raise LookupError("no users left to scan after the selection filters")
    path = ctx.run_dir / "_scan_users.csv"
    write_rows(path, [{"primaryEmail": e} for e in emails])
    ctx.manifest["meta"]["scanned_users"] = len(emails)
    ctx.manifest["meta"]["skipped_never_logged_in"] = skipped_never
    return path


def user_scan_args(ctx: RunContext, mod: Dict) -> Tuple[List[str], Optional[Path]]:
    """Rewrite an `all users` command into a parallel batch over a user list.

    Three changes, all needed together:
      - `csvfile <list>:primaryEmail` replaces `all users`, so the scan covers
        the accounts we chose rather than every mailbox in the tenant.
      - `config auto_batch_min/num_threads` makes GAM fork the scan. Left at
        the gam.cfg defaults (0 and 5) a multi-user print runs sequentially in
        one process: 3000 mailboxes at ~0.9s each is 45 minutes.
      - `redirect csv <file> multiprocess` collects the children's output.
        Without `multiprocess` the parent redirect does not follow the forks
        and the file comes back empty; without the redirect at all, a timeout
        throws away every row collected so far.

    The redirect path must be absolute - GAM resolves a relative one against
    drive_dir, not the working directory.
    """
    args = list(mod["args"])
    if [a.lower() for a in args[:2]] != ["all", "users"]:
        return args, None
    listing = scan_user_list(ctx)
    if listing is None:
        return args, None
    out_path = ctx.csv_path(mod["key"]).resolve()
    return (["config", "auto_batch_min", str(AUTO_BATCH_MIN),
             "num_threads", str(SCAN_THREADS),
             "redirect", "csv", str(out_path), "multiprocess",
             "csvfile", f"{listing.resolve()}:primaryEmail"] + args[2:],
            out_path)


def collect_simple(ctx: RunContext, mod: Dict) -> Tuple[str, int, str]:
    try:
        args, out_path = user_scan_args(ctx, mod)
    except LookupError as exc:
        return "skipped", 0, str(exc)
    rc, out, err = run_gam(args,
                           timeout=module_timeout(ctx, mod, 900),
                           dry_run=ctx.args.dry_run)
    ctx.stderr_log(mod["key"], err)
    if ctx.args.dry_run:
        return "dry-run", 0, ""
    target = ctx.csv_path(mod["key"])
    if out_path is not None and out_path.exists():
        # GAM wrote the CSV itself (redirect). Count it in place: a large
        # tenant's tokens.csv runs to hundreds of MB, and reading it back only
        # to write the same bytes again was four copies of it in memory.
        rows = csv_data_rows(out_path)
        header_only = rows == 0
    else:
        rows = csv_data_rows(out)
        header_only = is_header_only(out)
    # GAM reports a skipped mailbox on stderr; searching the CSV as well made
    # a signature containing "Does not exist" flip a clean module to partial.
    per_user_skips = any(marker in err for marker in PER_USER_SKIP_MARKERS)
    no_service = no_service_only(err) if per_user_skips else None

    def keep():
        if out_path is None or not out_path.exists():
            target.write_text(out, encoding="utf-8")

    if rc == 0 or (rc == 60 and header_only):
        # Exit 60 with a header-only CSV is GAM for "no rows", not a failure.
        keep()
        if no_service:
            return _no_service_result(rows, no_service)
        if per_user_skips:
            # A batched scan exits 0 even when a mailbox failed: the failure
            # happened in a child process. Only stderr carries it, so without
            # this the module reports full coverage over a short result.
            note = [ln for ln in err.strip().splitlines()
                    if any(m in ln for m in PER_USER_SKIP_MARKERS)]
            return "partial", rows, f"some users failed - {note[-1].strip()}"
        return ("empty" if rows == 0 else "ok"), rows, ""
    if mod["key"] == "caalevels" and CAALEVELS_AUTH_ERROR in (out + err):
        return "skipped", 0, ("not authorised: service account needs the "
                              "Access Context Manager Editor role in GCP")
    if mod["key"] == "browsers" and BROWSERS_AUTH_ERROR in (out + err):
        return "skipped", 0, ("not authorised: Chrome browser management "
                              "access is missing for this admin/API")
    if header_only and per_user_skips:
        # Some users were skipped and the rest simply had nothing to report:
        # partial coverage over an empty result, not a module failure.
        keep()
        if no_service:
            return _no_service_result(0, no_service)
        note = err.strip().splitlines()[-1:] or [""]
        return "partial", 0, f"some users failed - exit {rc}: {note[0]}"
    if not header_only:
        # An `all users` print exits non-zero when ANY user fails (e.g. exit
        # 73 for a user with Gmail disabled) but still emits every other
        # user's rows. Discarding those rows would lose good data; keep them
        # and say plainly that coverage is partial.
        keep()
        if no_service:
            return _no_service_result(rows, no_service)
        note = (err or out).strip().splitlines()[-1:] or ["unknown error"]
        return "partial", rows, f"some users failed - exit {rc}: {note[0]}"
    note = (err or out).strip().splitlines()[-1:] or ["unknown error"]
    return "error", 0, f"exit {rc}: {note[0]}"


def collect_backupcodes_args(ctx: RunContext, mod: Dict) -> List[str]:
    """The user list and an explicit no-fork, no-redirect command.

    Two things this module must not do, both for the same reason - GAM writing
    this CSV itself would put live backup codes on disk:
      - no `redirect csv`, so the output stays on stdout where only the count
        is kept;
      - and therefore no fork, because each child writes its own CSV header to
        stdout and nothing merges them. Four mailboxes came back as seven rows
        on the dev tenant (2026-08-17) before this was pinned to 0.
    """
    args, _ = user_scan_args(ctx, mod)
    if "redirect" in args:
        cut = args.index("redirect")
        args = args[:cut] + args[cut + 4:]   # redirect csv <path> multiprocess
    if "auto_batch_min" in args:
        args[args.index("auto_batch_min") + 1] = "0"
    if "num_threads" in args:
        # Meaningless without a fork; dropped so the intent reads at a glance.
        cut = args.index("num_threads")
        args = args[:cut] + args[cut + 2:]
    return args


def collect_backupcodes(ctx: RunContext, mod: Dict) -> Tuple[str, int, str]:
    """Backup codes come back as LIVE codes; only the count may touch disk.

    Takes the user list and threading from user_scan_args but never its
    redirect: GAM writing this CSV itself would put live codes on disk.
    """
    try:
        args = collect_backupcodes_args(ctx, mod)
    except LookupError as exc:
        return "skipped", 0, str(exc)
    rc, out, err = run_gam(args, timeout=module_timeout(ctx, mod, 900),
                           dry_run=ctx.args.dry_run)
    ctx.stderr_log(mod["key"], err)
    if ctx.args.dry_run:
        return "dry-run", 0, ""
    failed = not (rc == 0 or (rc == 60 and is_header_only(out)))
    if failed and is_header_only(out):
        note = (err or out).strip().splitlines()[-1:] or ["unknown error"]
        return "error", 0, f"exit {rc}: {note[0]}"
    reduced = []
    for row in csv.DictReader(io.StringIO(out)):
        count = ""
        for key, value in row.items():
            if key and "count" in key.lower():
                count = value
                break
        reduced.append({"User": col(row, "User"),
                        "verificationCodesCount": count})
    write_rows(ctx.csv_path(mod["key"]), reduced)
    no_service = no_service_only(err) if failed else None
    if no_service:
        return _no_service_result(len(reduced), no_service)
    if failed:
        # One mailbox failing (Gmail off, deleted mid-run) used to blank the
        # whole finding; the other users' counts are still good data.
        note = (err or out).strip().splitlines()[-1:] or ["unknown error"]
        return "partial", len(reduced), f"some users failed - exit {rc}: {note[0]}"
    return ("empty" if not reduced else "ok"), len(reduced), ""


def _batched_filelist(ctx: RunContext, mod: Dict, tail: List[str],
                      row_filter=None) -> Tuple[str, int, str]:
    """Run one `all users print filelist ...` through the batch machinery.

    One gam process per user cost ~2s of start-up per mailbox before a single
    file was listed, serially: the same shape the tier-2 modules had before
    1.4.0 and the same fix. user_scan_args turns this into a forked scan over
    the audited user list with a multiprocess redirect.

    row_filter, when given, is applied to the collected CSV afterwards - for
    the sweep where the externality test must run in Python because gam's pm
    filters cannot see the deciding field.
    """
    if not ctx.rows("users"):
        return "skipped", 0, "users module has no rows; run it first"
    if not ctx.internal_domains:
        return "skipped", 0, "domains module has no rows; run it first"
    scan = dict(mod, args=["all", "users", "print", "filelist"] + tail)
    status, rows, note = _collect_scan(ctx, scan)
    if row_filter is None or status not in ("ok", "partial", "empty"):
        return status, rows, note
    kept = [r for r in read_csv_rows(ctx.csv_path(mod["key"])) if row_filter(r)]
    write_rows(ctx.csv_path(mod["key"]), kept)
    if status == "ok" and not kept:
        status = "empty"
    return status, len(kept), note


def _collect_scan(ctx: RunContext, mod: Dict) -> Tuple[str, int, str]:
    """collect_simple with the Drive scan's longer per-user allowance.

    module_timeout's 10s per mailbox is sized for a Gmail-settings call; a
    Drive listing is bounded by file count, not user count, so the module's
    own ceiling stays the floor and the per-user term is tripled.
    """
    users = ctx.manifest["meta"].get("user_count", 0)
    scan = dict(mod, timeout=max(mod.get("timeout", 3600),
                                 users * PER_USER_TIMEOUT_SECONDS * 3))
    return collect_simple(ctx, scan)


def collect_mydrive_external(ctx: RunContext, mod: Dict) -> Tuple[str, int, str]:
    return _batched_filelist(
        ctx, mod, ["fields", "id,name,mimeType,owners.emailAddress,"
                   "basicpermissions"] + external_pm_args(ctx.internal_domains))


def collect_sites(ctx: RunContext, mod: Dict) -> Tuple[str, int, str]:
    return _batched_filelist(
        ctx, mod, ["showmimetype", "gsite", "fields",
                   "id,name,owners.emailAddress"])


def collect_swm_external(ctx: RunContext, mod: Dict) -> Tuple[str, int, str]:
    # No pm filter here: the recipient of an externally-owned file sees NO
    # permissions array at all (verified on dev 2026-08-15 - basicpermissions
    # came back empty on the planted inbound fixture), so any pm filter
    # silently excludes every genuinely external file. Externality must be
    # decided from owners.0.emailAddress in Python instead.
    internal = {d.lower() for d in ctx.internal_domains}

    def is_external(row):
        owner = col(row, "owners.0.emailAddress").lower()
        return "@" in owner and owner.rsplit("@", 1)[1] not in internal

    return _batched_filelist(
        ctx, mod, ["fullquery", "sharedWithMe and not 'me' in owners",
                   "fields", "id,name,owners.emailAddress,sharedWithMeTime"],
        row_filter=is_external)


def collect_sd_external(ctx: RunContext, mod: Dict) -> Tuple[str, int, str]:
    """Scan each Shared Drive for external ACLs.

    filelist has NO adminaccess option, so running it as a non-member of the
    drive returns zero rows and looks clean. Each drive is therefore listed
    AS one of its own members, impersonated through domain-wide delegation:
    the auditing admin when they are a member, otherwise an active member
    from shareddriveacls, organizers first. Nobody's access changes. A member
    sees what membership shows them, so a limited-access folder they are
    kept out of is not covered.

    Only when no member can list the drive (none active, or each one fails,
    e.g. no Drive licence) does --grant-temp-access apply: the admin is
    added as organizer via admin access, the drive is scanned, and the
    grant is removed again - the one write in the whole script. Without the
    flag such drives are reported UNSCANNED.
    """
    drives = ctx.rows("shareddrives")
    if not drives:
        return "skipped", 0, "shareddrives module has no rows; run it first"
    if not ctx.internal_domains:
        return "skipped", 0, "domains module has no rows; run it first"
    if not ctx.admin:
        return "skipped", 0, "--admin required for Shared Drive scans"
    admin_lower = ctx.admin.lower()
    active = {col(u, "primaryEmail").lower() for u in ctx.rows("users")
              if col(u, "suspended").lower() != "true"}
    rank = {"organizer": 0, "fileorganizer": 1, "writer": 2,
            "commenter": 3, "reader": 4}
    members: Dict[str, List[Tuple[int, str]]] = {}
    for acl in ctx.rows("shareddriveacls"):
        email = col(acl, "permission.emailAddress", "emailAddress").lower()
        if col(acl, "permission.type", "type").lower() != "user":
            continue
        if email != admin_lower and email not in active:
            continue
        role = rank.get(col(acl, "permission.role", "role").lower(), 5)
        # The admin goes first: the run already proved it can use them.
        members.setdefault(col(acl, "id"), []).append(
            (-1 if email == admin_lower else role, email))

    pm = external_pm_args(ctx.internal_domains)
    rows: List[Dict[str, str]] = []
    unscanned: List[str] = []
    failed: List[str] = []
    grant_errors: List[str] = []
    cleanup_failed: List[Dict[str, str]] = []
    attempted: Set[str] = set()
    errors = 0

    def listed(args: List[str]) -> Tuple[bool, str, str]:
        """One filelist call: (ok, csv text, why it failed)."""
        rc, out, err = run_gam(args, timeout=mod.get("timeout", 3600),
                               dry_run=ctx.args.dry_run)
        ctx.stderr_log(mod["key"], err)
        if ctx.args.dry_run:
            return True, "", ""
        # A member whose Drive is off gets exit 60 and a header-only CSV,
        # the same shape as an empty drive; only stderr tells them apart.
        # Without this check the drive reads as scanned and clean.
        skipped = any(m in err for m in PER_USER_SKIP_MARKERS)
        if not skipped and (rc == 0 or (rc == 60 and is_header_only(out))):
            return True, out, ""
        return False, "", (err.strip().splitlines()[-1] if err.strip()
                           else f"exit {rc}")

    def scan(drive_id: str, drive_name: str, as_user: str) -> Tuple[bool, str]:
        """List one drive as one user; rows are kept only on success.

        The Drive API returns no permissions for Shared Drive files in a
        list, so asking for them makes GAM fetch each file's ACL with its
        own call: 5,000 files took 35 minutes. Instead the drive is listed
        with hasAugmentedPermissions (true when a file has permissions of
        its own, beyond the drive's members), and ACLs are fetched only for
        those files. Drive members are checked separately from
        shareddriveacls.

        Files inside a folder shared outside inherit that sharing and are
        NOT flagged themselves (verified on dev 2026-10-07), so a flagged
        folder is listed with everything under it: per-file calls are spent
        only on the contents of folders shared outside."""
        ok, out, why = listed(
            ["user", as_user, "print", "filelist",
             "select", "shareddriveid", drive_id, "fields",
             "id,name,mimeType,hasaugmentedpermissions"])
        if not ok:
            return False, why
        listing = list(csv.DictReader(io.StringIO(out)))
        ctx.manifest["meta"].setdefault("shared_drive_file_counts", {})[
            drive_id] = len(listing)
        flagged = [r for r in listing
                   if truthy(col(r, "hasAugmentedPermissions"))]
        if not flagged and not ctx.args.dry_run:
            return True, ""
        is_folder = lambda r: col(r, "mimeType") == FOLDER_MIME
        seen = set()
        for kind, picked, extra in (
                ("files", [r for r in flagged if not is_folder(r)],
                 ["norecursion"]),
                ("folders", [r for r in flagged if is_folder(r)],
                 ["showparent"])):
            if not picked and not ctx.args.dry_run:
                continue
            id_file = ctx.run_dir / f"_sd_flagged_{kind}_{drive_id}.csv"
            write_rows(id_file, [{"id": r["id"]} for r in picked])
            ok, out, why = listed(
                ["user", as_user, "print", "filelist",
                 "select", "csvfile", f"{id_file}:id"] + extra
                + ["fields", "id,name,mimeType,basicpermissions"] + pm)
            if not ok:
                return False, why
            for row in csv.DictReader(io.StringIO(out)):
                # A flagged file inside a flagged folder comes back twice.
                key = (row.get("id"), row.get("permission.id"))
                if key in seen:
                    continue
                seen.add(key)
                row["shareddrive.id"] = drive_id
                row["shareddrive.name"] = drive_name
                row["shareddrive.scannedAs"] = as_user
                rows.append(row)
        return True, ""

    for drive in drives:
        if shutdown_requested:
            return "error", len(rows), "interrupted"
        drive_id = col(drive, "id")
        drive_name = col(drive, "name")
        if not drive_id:
            continue
        # Three members tried per drive, then the grant fallback.
        candidates = [e for _, e in sorted(members.get(drive_id, []))][:3]
        done = False
        for as_user in candidates:
            done, _ = scan(drive_id, drive_name, as_user)
            if done:
                break
        if done:
            continue
        if candidates and candidates[0] == admin_lower:
            # The admin is a member and still failed: a scan failure, which
            # a grant would not fix.
            errors += 1
            failed.append(f"{drive_name} ({drive_id})")
            unscanned.append(f"{drive_name} ({drive_id}) - scan failed")
            continue
        if not ctx.args.grant_temp_access:
            unscanned.append(f"{drive_name} ({drive_id})")
            continue
        rc, out, err = run_gam(
            ["user", ctx.admin, "add", "drivefileacl", drive_id,
             "user", ctx.admin, "role", "organizer", "adminaccess"],
            timeout=120, dry_run=ctx.args.dry_run)
        ctx.stderr_log(mod["key"], err)
        if not ctx.args.dry_run and rc != 0:
            unscanned.append(f"{drive_name} ({drive_id}) - temp grant failed")
            grant_errors.append(err.strip().splitlines()[-1] if err.strip() else f"exit {rc}")
            errors += 1
            continue
        try:
            ok, _ = scan(drive_id, drive_name, ctx.admin)
            if not ok:
                errors += 1
                failed.append(f"{drive_name} ({drive_id})")
                unscanned.append(f"{drive_name} ({drive_id}) - scan failed")
        finally:
            # Remove the temporary grant even when the scan itself failed.
            rc, out, err = run_gam(
                ["user", ctx.admin, "delete", "drivefileacl", drive_id,
                 ctx.admin, "adminaccess"],
                timeout=120, dry_run=ctx.args.dry_run)
            ctx.stderr_log(mod["key"], err)
            attempted.add(drive_id)
            if not ctx.args.dry_run and rc != 0:
                cleanup_failed.append({"drive": drive_name, "id": drive_id,
                                       "admin": ctx.admin})
                print_error(
                    f"Could not remove the temporary organizer grant on "
                    f"Shared Drive {drive_name} ({drive_id}). Remove "
                    f"{ctx.admin} manually in the Admin console.")
    if ctx.args.dry_run:
        return "dry-run", 0, ""
    write_rows(ctx.csv_path(mod["key"]), rows)
    ctx.manifest["meta"]["unscanned_shared_drives"] = unscanned
    # A failure from an earlier attempt stays listed until a later attempt
    # removes that drive's grant: the leftover organizer is still there.
    ctx.manifest["meta"]["temp_grant_cleanup_failed"] = [
        e for e in ctx.manifest["meta"].get("temp_grant_cleanup_failed", [])
        if e["id"] not in attempted] + cleanup_failed
    note = ""
    not_member = len(unscanned) - len(failed) - len(grant_errors)
    if grant_errors:
        # Kept apart from not_member: re-running with the flag cannot fix
        # these (an unlicensed admin cannot be made organizer), so the note
        # must not ask for that, and must not carry the UNSCANNED marker
        # that makes a resume retry them.
        note = (f"{len(grant_errors)} drive(s) not scanned, temp grant "
                f"failed: {grant_errors[0]}")
    if not_member:
        note = (note + "; " if note else "")
        note += (f"{not_member} drive(s) UNSCANNED (no member could list it; "
                 f"re-run with --grant-temp-access to cover them)")
    if failed:
        # Name them: a timed-out drive contributes nothing and the operator
        # has to know which one to re-run.
        note = (note + "; " if note else "") + \
            f"{len(failed)} drive(s) FAILED mid-scan: {', '.join(failed)}"
    if cleanup_failed:
        note = (note + "; " if note else "") + (
            "temporary organizer grant NOT removed from "
            + ", ".join(f"{e['drive']} ({e['id']})" for e in cleanup_failed)
            + f"; remove {ctx.admin} from their members manually")
    # Partial when any drive went unscanned, so the gate holds the report and
    # the checks do not call Shared Drives clean. A resume re-runs it only on
    # the UNSCANNED marker in the note (see _needs_run), never for the others.
    status = "partial" if unscanned else ("empty" if not rows else "ok")
    return status, len(rows), note


# ---- DNS ----

def tamingdns_check(check: str, domain: str, timeout: int = 25,
                    extra_args: Optional[Dict] = None) -> Optional[Dict]:
    """One stateless JSON-RPC tools/call POST; the response is already shaped
    as findings (severity, explanation, remediation, grade, provider)."""
    arguments = {"domain": domain}
    arguments.update(extra_args or {})
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": check, "arguments": arguments},
    }).encode("utf-8")
    req = urllib.request.Request(
        TAMINGDNS_MCP_URL, data=payload,
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream",
                 "User-Agent": "tenant_scope.py"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    # The endpoint may answer as plain JSON or as a single SSE data: frame.
    if body.lstrip().startswith("event:") or "\ndata:" in body or body.lstrip().startswith("data:"):
        frames = [ln[5:].strip() for ln in body.splitlines()
                  if ln.startswith("data:")]
        body = frames[-1] if frames else body
    data = json.loads(body)
    result = data.get("result", {})
    content = result.get("content") or []
    if content and isinstance(content, list) and "text" in content[0]:
        try:
            return json.loads(content[0]["text"])
        except (json.JSONDecodeError, TypeError):
            return {"raw": content[0]["text"]}
    return result or None


def doh_query(name: str, rtype: str, timeout: int = 10) -> List[str]:
    url = f"{DOH_URL}?name={urllib.parse.quote(name)}&type={rtype}"
    req = urllib.request.Request(url, headers={"User-Agent": "tenant_scope.py"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    return [answer.get("data", "").strip('"')
            for answer in data.get("Answer", [])]


def doh_fallback(domain: str) -> Dict:
    """Minimal presence/policy checks when tamingdns.com is unreachable."""
    result = {"path": "doh", "checks": {}}
    try:
        mx = doh_query(domain, "MX")
        result["checks"]["mx"] = {"present": bool(mx), "records": mx}
    except Exception as exc:
        result["checks"]["mx"] = {"error": str(exc)}
    try:
        txt = doh_query(domain, "TXT")
        spf = [t for t in txt if t.replace('" "', '').startswith("v=spf1")]
        result["checks"]["spf"] = {"present": bool(spf), "records": spf}
    except Exception as exc:
        result["checks"]["spf"] = {"error": str(exc)}
    try:
        dkim = doh_query(f"google._domainkey.{domain}", "TXT")
        result["checks"]["dkim"] = {"present": bool(dkim),
                                    "selector": "google"}
    except Exception as exc:
        result["checks"]["dkim"] = {"error": str(exc)}
    try:
        dmarc = doh_query(f"_dmarc.{domain}", "TXT")
        dmarc = [t for t in dmarc if "v=DMARC1" in t]
        result["checks"]["dmarc"] = {"present": bool(dmarc), "records": dmarc}
    except Exception as exc:
        result["checks"]["dmarc"] = {"error": str(exc)}
    return result


DNS_WORKERS = 4   # domains checked at once; tamingdns rate limits are unknown


def _dns_domain(domain: str, use_fallback: bool) -> Dict:
    """All four checks for one domain, tamingdns first, DoH if every one failed."""
    if use_fallback:
        return doh_fallback(domain)
    entry: Dict = {"path": "tamingdns", "checks": {}}
    for check in ("check_mx", "check_spf", "check_dkim", "check_dmarc"):
        try:
            extra = {"selector": "google"} if check == "check_dkim" else None
            entry["checks"][check.replace("check_", "")] = tamingdns_check(
                check, domain, extra_args=extra)
        except Exception as exc:
            entry["checks"][check.replace("check_", "")] = {
                "error": f"{type(exc).__name__}: {exc}"}
    if all("error" in (v or {}) for v in entry["checks"].values()):
        entry = doh_fallback(domain)
    return entry


def collect_dns(ctx: RunContext, mod: Dict) -> Tuple[str, int, str]:
    # Google's *.test-google-a.com alias exists on many tenants and is not a
    # mail domain; checking its DNS only adds noise to the report.
    domains = [d for d in ctx.internal_domains
               if not d.endswith("test-google-a.com")]
    if not domains:
        return "skipped", 0, "domains module has no rows; run it first"
    if ctx.args.dry_run:
        return "dry-run", 0, ""
    use_fallback = bool(ctx.manifest["meta"].get("dns_fallback"))
    results: Dict[str, Dict] = {}
    # Four HTTP checks per domain at up to 25s each: a dozen domains took
    # minutes in series and the calls share nothing, so run them together.
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        futures = {pool.submit(_dns_domain, d, use_fallback): d for d in domains}
        for idx, fut in enumerate(as_completed(futures), 1):
            domain = futures[fut]
            results[domain] = fut.result()
            print_info(f"dns: {domain} done ({idx}/{len(domains)})")
    results = {d: results[d] for d in domains}   # report order = domain order
    (ctx.run_dir / "dns.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")
    dead = [d for d, e in results.items()
            if e.get("checks") and all("error" in (v or {})
                                       for v in e["checks"].values())]
    if len(dead) == len(domains):
        return "error", 0, "every DNS check failed on both paths"
    if dead:
        return "partial", len(results), f"checks failed for {', '.join(dead)}"
    return "ok", len(results), ""


def collect_classroom(ctx: RunContext, mod: Dict) -> Tuple[str, int, str]:
    """A Classroom print, only on a tenant holding an Education SKU. Runs
    after the tenant-level pool (a non-simple collector lands in the heavy
    pass), so licenses.csv is on disk by then."""
    if not education_skus_held(ctx):
        # "n/a", not "skipped": nothing failed, so it must not turn a
        # complete run into exit 2 on every non-Education tenant.
        return "n/a", 0, "no Education licence held; Classroom not audited"
    status, rows, note = collect_simple(ctx, mod)
    if status not in ("ok", "empty") or ctx.args.dry_run:
        return status, rows, note
    return _strip_to_header(ctx.csv_path(mod["key"]), mod["csv_header"],
                            status, rows, note)


def _strip_to_header(path: Path, header: str, status: str, rows: int,
                     note: str) -> Tuple[str, int, str]:
    """Drop anything GAM printed to stdout ahead of the CSV header.

    `print classroominvitations` writes one "Course: X, Print N Classroom
    Invitations" line per course to stdout before the header (seen live
    2026-10-01). Left in, the csv reader takes the first of them as the
    header, no real column matches, and every invitation reads as having no
    email, so an outside invitation is never flagged. A file with no header
    at all is an error, never a zero."""
    if not path.exists():
        return status, rows, note
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    start = next((i for i, ln in enumerate(lines) if ln.startswith(header)),
                 None)
    if start is None:
        return "error", 0, f"no CSV header starting {header!r} in GAM output"
    if start:
        path.write_text("".join(lines[start:]), encoding="utf-8")
    rows = csv_data_rows(path)
    return ("empty" if rows == 0 else "ok"), rows, note


COLLECTORS = {
    "simple": collect_simple,
    "backupcodes": collect_backupcodes,
    "mydrive_external": collect_mydrive_external,
    "sd_external": collect_sd_external,
    "swm_external": collect_swm_external,
    "sites": collect_sites,
    "dns": collect_dns,
    "classroom": collect_classroom,
}


def derive_internal_domains(ctx: RunContext):
    """The internal-domain list feeds every external-share recipe. domains
    includes aliases via the type column; domainaliases adds any stragglers."""
    domains = set()
    for row in ctx.rows("domains"):
        name = col(row, "domainName", "domain")
        if name:
            domains.add(name.lower())
    for row in ctx.rows("domainaliases"):
        name = col(row, "domainAliasName", "domainAlias", "domainName")
        if name:
            domains.add(name.lower())
    if domains:
        ctx.internal_domains = sorted(domains)
        ctx.save()


FIRST_MODULES = ("domains", "domainaliases", "users")
LIGHT_WORKERS = 4   # tenant-level gam prints run at once


def _is_batch(mod: Dict) -> bool:
    return [a.lower() for a in (mod.get("args") or [])[:2]] == ["all", "users"]


def _needs_run(ctx: RunContext, mod: Dict) -> bool:
    """Resume and scope gating, decided on the main thread."""
    key = mod["key"]
    status = ctx.module_status(key)
    note = ctx.manifest["modules"].get(key, {}).get("note", "")
    # A partial module is re-run only when it was cut short by a timeout;
    # partial because one mailbox has Gmail off would re-scan the whole
    # tenant on every resume and end partial again.
    # A Shared Drive scan that left drives UNSCANNED is re-run: a resume may
    # add --grant-temp-access, and runs from before member scanning skipped
    # every drive the admin was not in.
    rescan = "UNSCANNED" in note
    if not rescan and (status in ("ok", "empty") or
                       (status == "partial" and "Timed out" not in note)):
        print_info(f"{key}: already collected, skipping (resume)")
        return False
    if ctx.failed_scopes and set(mod.get("scopes", [])) & set(ctx.failed_scopes):
        ctx.set_module(key, "skipped", 0, "not authorised: DWD scope "
                       "missing (see preflight)")
        print_warning(f"{key}: skipped, DWD scope not authorised")
        return False
    return True


def _run_collector(ctx: RunContext, mod: Dict) -> Tuple[str, int, str, float]:
    started = time.time()
    status, rows, note = COLLECTORS[mod.get("collector", "simple")](ctx, mod)
    return status, rows, note, time.time() - started


def _record(ctx: RunContext, mod: Dict, status: str, rows: int, note: str,
            elapsed: float):
    """Manifest write, console line and the post-module hooks. Main thread
    only: manifest.json is one file and save() is not atomic."""
    key = mod["key"]
    if status != "dry-run":
        ctx.set_module(key, status, rows, note)
    label = f"{key}: {status}, {rows} row(s) in {elapsed:.0f}s"
    if note:
        label += f" - {note}"
    if status in ("ok", "empty", "dry-run"):
        print_success(label)
    elif status == "n/a":
        print_info(label)
    elif status in ("skipped", "partial"):
        print_warning(label)
    else:
        print_error(label)
    if key in ("domains", "domainaliases"):
        derive_internal_domains(ctx)
    if key == "users":
        ctx.manifest["meta"]["user_count"] = rows
        ctx.save()


def collect(ctx: RunContext, modules: List[Dict]):
    """Three passes: the modules everything depends on, then every
    tenant-level print together, then the per-mailbox and Drive scans one
    at a time.

    The per-mailbox modules already fork SCAN_THREADS gam processes each;
    two of those at once is forty processes for no quota headroom. The
    tenant-level prints are one process and a few seconds apiece, and the
    long ones (report users, tokens) hide the rest when they overlap.
    """
    print_header("STAGE 1 - COLLECT")
    ctx.manifest["meta"]["include_suspended"] = bool(ctx.args.include_suspended)
    ctx.manifest["meta"].setdefault(
        "collected_at", datetime.now().strftime("%Y-%m-%d %H:%M"))
    first = [m for m in modules if m["key"] in FIRST_MODULES]
    rest = [m for m in modules if m["key"] not in FIRST_MODULES]
    light = [m for m in rest
             if m.get("collector", "simple") in ("simple", "dns")
             and not _is_batch(m)]
    heavy = sorted([m for m in rest if m not in light],
                   key=lambda m: m["tier"])

    def stop() -> bool:
        if shutdown_requested:
            print_warning("Stopping; resume this run with --run-dir "
                          + str(ctx.run_dir))
        return shutdown_requested

    for mod in first:
        if stop():
            return
        if _needs_run(ctx, mod):
            _record(ctx, mod, *_run_collector(ctx, mod))

    pending = [m for m in light if _needs_run(ctx, m)]
    if pending and not stop():
        with ThreadPoolExecutor(max_workers=LIGHT_WORKERS) as pool:
            futures = {pool.submit(_run_collector, ctx, m): m for m in pending}
            for fut in as_completed(futures):
                _record(ctx, futures[fut], *fut.result())
                if shutdown_requested:
                    # Running gam processes finish (they are in their own
                    # group); queued modules are dropped for the resume.
                    pool.shutdown(wait=False, cancel_futures=True)
                    break

    for mod in heavy:
        if stop():
            return
        if _needs_run(ctx, mod):
            _record(ctx, mod, *_run_collector(ctx, mod))


###############################################################################
# CHECK - FINDINGS ENGINE
###############################################################################

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]


class Finding:
    """One report finding: fixed client-facing copy plus evidence rows.

    id_field names the evidence column that identifies a row across runs, so
    the month-to-month comparison can say which accounts or files were fixed,
    not just that the count went down. Without it the row's first column is
    used, which is the account, file, group or org unit in nearly every
    finding."""

    def __init__(self, fid: str, severity: str, title: str, meaning: str,
                 remediation: str, evidence: List[Dict[str, str]],
                 source: str, count: Optional[int] = None,
                 id_field: Optional[str] = None):
        self.fid = fid
        self.severity = severity
        self.title = title
        self.meaning = meaning
        self.remediation = remediation
        self.evidence = evidence[:EVIDENCE_ROWS]
        # The full list: the HTML shows a sample, findings_evidence.csv
        # carries every row so two runs can be diffed by who was named.
        self.all_evidence = evidence
        self.count = count if count is not None else len(evidence)
        self.source = source
        self.id_field = id_field
        self.modules: List[str] = []
        # new / persisting / first_run / not_compared, set by the comparison.
        self.change = ""
        self.row_changes: Dict[str, str] = {}


def _evidence_id(finding: Finding, row: Dict[str, str]) -> str:
    """Stable identity of one evidence row: the finding id plus the row's
    identifying column, or a short hash of its non-empty cells when it has
    none. The column comes from this run's rows, never from a row read back
    from findings_evidence.csv, whose columns are the union of every finding's
    and so in a different order."""
    field = finding.id_field
    if not field and finding.all_evidence:
        field = next(iter(finding.all_evidence[0]), "")
    key = str(row.get(field, "") or "")
    if not key:
        cells = {k: str(v) for k, v in row.items() if v not in (None, "")}
        key = hashlib.sha1(json.dumps(cells, sort_keys=True).encode()
                           ).hexdigest()[:12]
    return f"{finding.fid}:{key.lower()}"


def _module_usable(ctx: RunContext, key: str) -> bool:
    usable = ctx.module_status(key) in ("ok", "empty", "partial")
    # Recorded so run_checks can tell "ran and found nothing" from "had no
    # data to look at" when it builds the checked-and-clean list.
    ctx.consulted.append((key, usable))
    return usable


def _super_admins(ctx: RunContext) -> List[Dict[str, str]]:
    return [r for r in ctx.rows("users") if truthy(col(r, "isAdmin"))
            and not truthy(col(r, "suspended"))]


def _admin_role(row: Dict[str, str]) -> str:
    """'super admin', 'delegated admin' or '' for a users.csv row."""
    if truthy(col(row, "isAdmin")):
        return "super admin"
    if truthy(col(row, "isDelegatedAdmin")):
        return "delegated admin"
    return ""


def _live_users(ctx: RunContext) -> List[Dict[str, str]]:
    """Accounts that can sign in: neither suspended nor archived. Archived
    accounts cannot authenticate, so counting them as unenrolled or dormant
    pads every people-centric finding."""
    return [r for r in ctx.rows("users")
            if not (truthy(col(r, "suspended")) or truthy(col(r, "archived")))]


def _risky_scope_labels(row: Dict[str, str]) -> List[str]:
    """Labels of RISKY_SCOPES present in a tokens.csv row. Scopes sit
    space-separated in one cell; match whole tokens so .../auth/drive does
    not also swallow .../auth/drive.readonly."""
    scopes = set(col(row, "scopes").split())
    return [label for url, label in RISKY_SCOPES.items() if url in scopes]


def check_public_files(ctx: RunContext) -> List[Finding]:
    findings = []
    for key, where in (("mydrive_external", "My Drive"),
                       ("shareddrive_external", "Shared Drives")):
        if not _module_usable(ctx, key):
            continue
        public = []
        linked = []
        for row in ctx.rows(key):
            if col(row, "permission.type") == "anyone":
                entry = {"File": col(row, "name"),
                         "Owner": col(row, "owners.0.emailAddress",
                                      "owners.emailAddress",
                                      "shareddrive.name"),
                         "File ID": col(row, "id")}
                if truthy(col(row, "permission.allowFileDiscovery")):
                    public.append(entry)
                else:
                    linked.append(entry)
        if public:
            findings.append(Finding(
                f"public-files-{key}", "CRITICAL",
                f"Files in {where} are public on the web",
                "These files are shared with \"anyone\" and marked "
                "discoverable, which means search engines can index them and "
                "anyone on the internet can open them without signing in.",
                "Open each file's sharing settings and change access to "
                "specific people, or at minimum switch off \"anyone can "
                "find\" so the link is required.",
                public, f"{key}.csv"))
        if len(linked) >= ANYONE_LINK_SCALE:
            findings.append(Finding(
                f"anyone-link-{key}", "HIGH",
                f"Large number of \"anyone with the link\" files in {where}",
                f"{len(linked)} files can be opened by anyone who has the "
                "link, with no sign-in. Links leak: they get forwarded, "
                "pasted into tickets and indexed from public pages.",
                "Review the list and restrict sharing to named people or "
                "groups where the open link is not deliberate.",
                linked, f"{key}.csv"))
    return findings


def check_external_file_shares(ctx: RunContext) -> List[Finding]:
    """Files shared to specific external people/groups or whole external
    domains, and external-owned files shared into the tenant.

    check_public_files only covers anyone-type ACLs; these named-target
    external shares were collected but surfaced nowhere until the 2026-08-15
    round-3 fixtures exposed the gap.
    """
    findings = []
    internal = {d.lower() for d in ctx.internal_domains}
    named, domains = [], []
    audiences: Dict[str, List[Dict[str, str]]] = {}
    for key, where in (("mydrive_external", "My Drive"),
                       ("shareddrive_external", "Shared Drives")):
        if not _module_usable(ctx, key):
            continue
        for row in ctx.rows(key):
            ptype = col(row, "permission.type")
            entry = {"File": col(row, "name"),
                     "Where": where,
                     "Owner": col(row, "owners.0.emailAddress",
                                  "owners.emailAddress", "shareddrive.name"),
                     "Role": col(row, "permission.role"),
                     "File ID": col(row, "id")}
            if ptype in ("user", "group"):
                addr = col(row, "permission.emailAddress")
                if addr and email_domain(addr) not in internal:
                    entry["Shared with"] = addr
                    named.append(entry)
            elif ptype == "domain":
                dom = col(row, "permission.domain").lower()
                # A target audience comes back as type=domain with
                # <id>.audience.googledomains.com. It can belong to another
                # organisation (verified 2026-10-05) and no API lists a
                # tenant's own audiences, so these are listed for the admin
                # to match by hand rather than judged here.
                if dom.endswith(".audience.googledomains.com"):
                    audiences.setdefault(dom.split(".", 1)[0], []).append(entry)
                    continue
                if dom and dom not in internal:
                    entry["Shared with"] = f"everyone at {dom}"
                    domains.append(entry)
    if domains:
        findings.append(Finding(
            "external-domain-shares", "HIGH",
            "Files shared with an entire external domain",
            "These files are open to every account in another organisation's "
            "domain, not to named people. Anyone that organisation hires "
            "gains access automatically.",
            "Replace the domain-wide share with the specific external people "
            "who need the file.",
            domains, "mydrive_external.csv"))
    if named:
        findings.append(Finding(
            "external-user-shares", "MEDIUM",
            "Files shared with people outside the organisation",
            "These files are shared to named external addresses. Individual "
            "external shares are often legitimate, but each one outlives the "
            "conversation it was created for and keeps working after the "
            "recipient changes role or employer.",
            "Review the list; remove shares whose purpose has passed, and "
            "prefer expiring access for the rest.",
            named, "mydrive_external.csv"))
    if audiences:
        findings.append(Finding(
            "target-audience-shares", "INFO",
            "Files shared with target audiences: confirm each one is yours",
            "These files are shared with a target audience. An audience from "
            "another organisation can be added to a file the same way as your "
            "own, gives that organisation's members access, and looks the "
            "same in Drive. Google offers no way to list your own audiences, "
            "so the audit cannot tell them apart.",
            "In the Admin console, open Directory > Target audiences and open "
            "each audience: its ID is the last part of the page address. Any "
            "ID below that is not in your list belongs to another "
            "organisation; remove that share from the files listed.",
            [{"Audience ID": aid, "Files": str(len(rows)),
              "Example file": rows[0]["File"], "Owner": rows[0]["Owner"]}
             for aid, rows in sorted(audiences.items())],
            "mydrive_external.csv"))
    if _module_usable(ctx, "sharedwithme_external"):
        inbound = [{"File": col(r, "name"),
                    "External owner": col(r, "owners.0.emailAddress"),
                    "Shared with": col(r, "Owner"),
                    "Shared on": col(r, "sharedWithMeTime")}
                   for r in ctx.rows("sharedwithme_external")]
        if inbound:
            findings.append(Finding(
                "external-inbound-shares", "INFO",
                "Files owned outside the organisation shared into it",
                "Staff have externally-owned files in their \"Shared with "
                "me\". The data lives in someone else's tenant: the owner "
                "controls access and can withdraw or change it at any time.",
                "No action needed unless business data is being kept in "
                "externally-owned files; anything critical should be copied "
                "into a drive the organisation owns.",
                inbound, "sharedwithme_external.csv"))
    return findings


def check_super_admin_count(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "users"):
        return []
    admins = _super_admins(ctx)
    if len(admins) >= 2:
        return []
    evidence = [{"Super admin": col(r, "primaryEmail")} for r in admins]
    return [Finding(
        "few-super-admins", "CRITICAL",
        "Fewer than two super admin accounts",
        "With only one super admin, losing that one account (departure, "
        "lockout, compromise) locks the organisation out of its own "
        "Google Workspace tenant.",
        "Create a second super admin account (ideally a dedicated "
        "break-glass account with strong 2-step verification), and store "
        "its credentials securely.",
        evidence, "users.csv", count=len(admins))]


def check_admin_2sv(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "users"):
        return []
    weak = [r for r in _super_admins(ctx)
            if not truthy(col(r, "isEnrolledIn2Sv"))]
    if not weak:
        return []
    evidence = [{"Super admin": col(r, "primaryEmail"),
                 "Last login": col(r, "lastLoginTime")} for r in weak]
    return [Finding(
        "admin-no-2sv", "CRITICAL",
        "Super admin accounts without 2-step verification",
        "A super admin password on its own is the single key to the whole "
        "tenant. These accounts are not enrolled in 2-step verification, so "
        "one phished or reused password is enough to take over everything.",
        "Enrol every super admin in 2-step verification now, preferring "
        "security keys or passkeys, and then enforce 2SV for admins via "
        "policy.",
        evidence, "users.csv")]


def _asp_rows(ctx: RunContext) -> List[Dict[str, str]]:
    """Rows in asps.csv that are an actual app password.

    `gam all users print asps` emits one row per user with an `asps` count
    column when that user has none - a clean tenant yields 37 rows of
    `user,0`. Counting rows therefore flags everybody. Real app passwords
    carry a codeId.
    """
    real = []
    for row in ctx.rows("asps"):
        if col(row, "codeId", "codeid"):
            real.append(row)
            continue
        count = col(row, "asps")
        if count and count.strip().isdigit() and int(count) > 0:
            real.append(row)
    return real


def check_admin_asps(ctx: RunContext) -> List[Finding]:
    if not (_module_usable(ctx, "users") and _module_usable(ctx, "asps")):
        return []
    # Delegated admins too: an app password bypasses 2SV on any account that
    # can reset passwords or read audit logs, not only on a super admin.
    admins = {col(r, "primaryEmail").lower(): _admin_role(r)
              for r in _live_users(ctx) if _admin_role(r)}
    hits = [r for r in _asp_rows(ctx) if col(r, "User").lower() in admins]
    if not hits:
        return []
    evidence = [{"Admin": col(r, "User"),
                 "Role": admins[col(r, "User").lower()],
                 "App password name": col(r, "name"),
                 "Created": col(r, "creationTime")} for r in hits]
    return [Finding(
        "admin-asps", "HIGH",
        "Admin accounts using app passwords",
        "An app password cannot sign in to the browser or the Admin console, "
        "but it lets an older mail, calendar or contacts app (IMAP, POP, "
        "SMTP) into the account with no second factor. Anyone holding it can "
        "read and send the admin's mail, including password reset and "
        "security alert messages.",
        "Identify what each app password is for, replace it with modern "
        "OAuth sign-in, and revoke the app passwords on all admin accounts.",
        evidence, "asps.csv")]


def check_external_forwarding(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "forwards"):
        return []
    internal = set(ctx.internal_domains)
    hits = []
    for row in ctx.rows("forwards"):
        # GAM7 emits User,forwardEnabled,forwardTo,disposition (verified on
        # the dev tenant). The older name is kept for gam builds that used it.
        if not truthy(col(row, "forwardEnabled", "forwardingEnabled", "enabled")):
            continue
        target = col(row, "forwardTo", "emailAddress", "forwardingAddress")
        if target and email_domain(target) not in internal:
            hits.append({"User": col(row, "User"),
                         "Forwards to": target})
    if not hits:
        return []
    return [Finding(
        "external-forwarding", "CRITICAL",
        "Mailboxes forwarding to addresses outside the organisation",
        "All mail arriving in these mailboxes is being copied or moved to an "
        "external address. This is a common way company data quietly leaves "
        "the organisation, and one of the first things attackers set up "
        "after compromising an account.",
        "Confirm with each user whether the forward is legitimate business "
        "use. Remove any that are not, and review the account's recent "
        "sign-in activity if the forward was not set up knowingly.",
        hits, "forwards.csv")]


def check_orphaned_shared_drives(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "shareddriveorganizers"):
        return []
    hits = []
    for row in ctx.rows("shareddriveorganizers"):
        if not col(row, "organizers"):
            hits.append({"Shared Drive": col(row, "name"),
                         "Drive ID": col(row, "id")})
    if not hits:
        return []
    return [Finding(
        "orphaned-shared-drives", "CRITICAL",
        "Shared Drives with no manager",
        "Nobody can manage membership, sharing or deletion on these drives - "
        "typically because every manager has left the organisation. The "
        "content is live but unowned, and access can no longer be corrected "
        "by the people using it.",
        "Have an admin appoint a new manager on each drive (Admin console > "
        "Apps > Google Workspace > Drive and Docs > Manage shared drives).",
        hits, "shareddriveorganizers.csv")]


def check_shared_drive_external(ctx: RunContext) -> List[Finding]:
    findings = []
    internal = set(ctx.internal_domains)
    if _module_usable(ctx, "shareddriveacls"):
        hits = []
        # From the Shared Drive scan's first pass; every file in the drive
        # is open to these members, so the count is the exposure.
        file_counts = {k: str(v) for k, v in ctx.manifest["meta"].get(
            "shared_drive_file_counts", {}).items()}
        for row in ctx.rows("shareddriveacls"):
            if truthy(col(row, "permission.deleted")):
                continue
            addr = col(row, "permission.emailAddress", "emailAddress")
            # A whole outside domain can be a member too. The per-file scan
            # used to surface it through every file; since v1.7.0 the scan
            # skips inherited access, so it is reported here.
            dom = col(row, "permission.domain").lower()
            if col(row, "permission.type", "type").lower() == "domain" \
                    and dom and dom not in internal:
                addr = f"everyone at {dom}"
            elif not (addr and email_domain(addr) not in internal):
                continue
            hits.append({"Shared Drive": col(row, "name"),
                         "External member": addr,
                         "Role": col(row, "permission.role", "role"),
                         "Files in drive": file_counts.get(
                             col(row, "id"), "not scanned")})
        if hits:
            findings.append(Finding(
                "sd-external-members", "HIGH",
                "Shared Drives with members from outside the organisation",
                "External people are full members of these Shared Drives and "
                "see everything in them, now and in future - membership "
                "outlives the project it was granted for. Every file in "
                "the drive is open to them, so the files are not listed "
                "one by one.",
                "Review each external member: still needed? If yes, confirm "
                "the drive holds nothing beyond their remit; if not, remove "
                "them.",
                hits, "shareddriveacls.csv"))
    if _module_usable(ctx, "shareddrives"):
        open_drives = []
        for row in ctx.rows("shareddrives"):
            domain_only = col(row, "restrictions.domainUsersOnly")
            members_only = col(row, "restrictions.driveMembersOnly")
            if domain_only and not truthy(domain_only):
                open_drives.append({
                    "Shared Drive": col(row, "name"),
                    "External sharing allowed": "yes",
                    "Non-members can open files":
                        "yes" if members_only and not truthy(members_only)
                        else "members only"})
        if open_drives:
            findings.append(Finding(
                "sd-open-settings", "HIGH",
                "Shared Drives configured to allow external sharing",
                "These drives permit files to be shared to people outside "
                "the organisation. That may be intentional for "
                "client-facing drives, but on internal drives it widens the "
                "blast radius of a single careless share.",
                "For drives that should stay internal, tick \"only people "
                "in the organisation\" in the shared drive's settings.",
                open_drives, "shareddrives.csv"))
    return findings


def check_group_exposure(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "groups"):
        return []
    findings = []
    open_join, ext_members, open_post = [], [], []
    public_archive, discoverable = [], []
    for row in ctx.rows("groups"):
        entry = {"Group": col(row, "email"), "Name": col(row, "name")}
        if col(row, "whoCanJoin").upper() == "ANYONE_CAN_JOIN":
            open_join.append(entry)
        if truthy(col(row, "allowExternalMembers")):
            ext_members.append(entry)
        if col(row, "whoCanPostMessage").upper() == "ANYONE_CAN_POST":
            open_post.append(entry)
        if col(row, "whoCanViewGroup").upper() == "ANYONE_CAN_VIEW":
            public_archive.append(entry)
        if col(row, "whoCanDiscoverGroup").upper() == "ANYONE_CAN_DISCOVER":
            discoverable.append(entry)
    if public_archive:
        findings.append(Finding(
            "groups-public-archive", "HIGH",
            "Groups whose message archive anyone on the internet can read",
            "Every message ever posted to these groups is readable without "
            "signing in. Internal discussion lists set this way publish "
            "their whole history.",
            "Set \"who can view conversations\" to group members or "
            "organisation users on each of these groups.",
            public_archive, "groups.csv"))
    if discoverable:
        findings.append(Finding(
            "groups-discoverable", "INFO",
            "Groups anyone on the internet can find",
            "These groups are listed publicly, so their names and addresses "
            "are visible outside the organisation. Not a leak in itself, "
            "but an address list for spam and phishing.",
            "Set \"who can see the group\" to organisation users unless the "
            "group is a deliberate public contact point.",
            discoverable, "groups.csv"))
    if open_join:
        findings.append(Finding(
            "groups-anyone-join", "HIGH",
            "Groups anyone on the internet can join",
            "Joining one of these groups requires no approval and no "
            "organisation account. Whatever the group can access - shared "
            "files, mail history, calendar invites - is open to whoever "
            "joins.",
            "Change \"who can join\" to invited or organisation users only "
            "on each of these groups.",
            open_join, "groups.csv"))
    if ext_members:
        findings.append(Finding(
            "groups-external-members", "HIGH",
            "Groups that allow members from outside the organisation",
            "External addresses can be members of these groups. Any file or "
            "resource shared to the group is then shared outside the "
            "organisation, which is easy to miss when sharing \"to the "
            "team\".",
            "Where external membership is not deliberate, switch off "
            "\"allow external members\" and remove any outside addresses.",
            ext_members, "groups.csv"))
    if open_post:
        findings.append(Finding(
            "groups-anyone-post", "HIGH",
            "Groups anyone on the internet can post to",
            "Anyone can send mail into these groups without being a member. "
            "That makes them a spam and phishing delivery route straight "
            "into staff inboxes.",
            "Restrict posting to organisation users or members on each "
            "group, unless the address is a deliberate public contact "
            "point.",
            open_post, "groups.csv"))
    return findings


def check_filter_forwarding(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "filters"):
        return []
    internal = set(ctx.internal_domains)
    hits = []
    for row in ctx.rows("filters"):
        # GAM writes the action verb into the cell ("forward user@x.com"),
        # so the address has to come off the end of the value.
        target = col(row, "forward").removeprefix("forward").strip()
        if target and email_domain(target) not in internal:
            hits.append({"User": col(row, "User", "user"),
                         "Filter forwards to": target})
    if not hits:
        return []
    return [Finding(
        "filter-external-forwarding", "HIGH",
        "Gmail filters forwarding mail to external addresses",
        "These filters quietly send matching mail to an outside address. "
        "Unlike account-level forwarding they are easy to miss, and "
        "attackers use them to keep receiving a victim's mail after a "
        "password reset.",
        "Review each filter with the user; delete any that are not known, "
        "deliberate business arrangements, and review those accounts' "
        "recent sign-in activity.",
        hits, "filters.csv")]


# Labels and words seen in business email compromise. Same lists as
# m365_scope.py (BEC_FOLDERS, BEC_WORDS) so both reports flag the same
# patterns; change both together.
BEC_FOLDERS = ("rss feeds", "rss subscriptions", "conversation history",
               "archive", "junk email", "deleted items", "notes")
BEC_WORDS = ("invoice", "payment", "bank", "banking", "remittance", "wire",
             "transfer", "statement", "eft", "proof of payment", "account",
             "urgent", "ceo", "password")
_BEC_WORD_RE = re.compile(
    r"\b(" + "|".join(re.escape(w) for w in BEC_WORDS) + r")\b")


def suspicious_filter(row: Dict[str, str], internal: Iterable[str]
                      ) -> Optional[str]:
    """Why a Gmail filter looks like business email compromise, or None.

    An attacker in a mailbox hides the replies to their fraud: mail about
    payments sent to trash, archived or marked read, or everything from the
    one outside address they are impersonating. Archiving a single sender
    alone is how people file newsletters, so a sender needs trash or
    mark-as-read as well. GAM7 writes each criterion and action as its own
    column, the value prefixed with its name ("subject invoice", "label X")."""
    def value(name: str) -> str:
        return col(row, name).removeprefix(name).strip()
    trash, archive = bool(col(row, "trash")), bool(col(row, "archive"))
    markread = bool(col(row, "markread"))
    if not (trash or archive or markread):
        return None
    text = " ".join(value(c) for c in ("subject", "query")).lower()
    word = _BEC_WORD_RE.search(text)
    if word:
        return f"hides mail about '{word.group(1)}'"
    sender = value("from")
    if (trash or markread) and re.fullmatch(r"[^\s@,|()]+@[^\s@,|()]+",
                                            sender) \
            and email_domain(sender) not in internal:
        return f"hides mail from {sender}"
    label = value("label").lower()
    if label and (label in BEC_FOLDERS or label in ("rss", "..", ".")
                  or (len(label) <= 2 and not label.isalnum())):
        return f"files mail out of sight under the label '{value('label')}'"
    return None


def check_filter_bec(ctx: RunContext) -> List[Finding]:
    """Filters that hide mail the way a mailbox takeover does."""
    if not _module_usable(ctx, "filters"):
        return []
    internal = {d.lower() for d in ctx.internal_domains}
    hits = []
    for row in ctx.rows("filters"):
        why = suspicious_filter(row, internal)
        if not why:
            continue
        actions = [a for a in ("trash", "archive", "markread")
                   if col(row, a)]
        hits.append({"User": col(row, "User", "user"),
                     "Filter ID": col(row, "id"),
                     "Why": why, "Actions": ", ".join(actions)})
    if not hits:
        return []
    scope = ""
    if ctx.module_status("filters") == "partial":
        scope = (" Filters could only be read for some users on this run "
                 "(see Coverage gaps), so this list may not be complete.")
    return [Finding(
        "filter-bec-patterns", "HIGH",
        "Gmail filters that hide payment mail or a single sender",
        "Someone who takes over a mailbox sets filters like these so the "
        "real owner never sees the replies to their fraud: mail about "
        "invoices or payments sent to trash, archived or marked read, or "
        "everything from one outside address hidden. Some will be "
        "legitimate, but each needs the owner to confirm they made it."
        + scope,
        "Ask each user whether they created the filter. Delete any they do "
        "not recognise, reset that account's password, sign it out of all "
        "sessions and review its recent sign-ins and sent mail.",
        hits, "filters.csv", id_field="Filter ID")]


def check_unmanaged_accounts(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "userinvitations"):
        return []
    rows = ctx.rows("userinvitations")
    if not rows:
        return []
    evidence = [{"Email": col(r, "email"),
                 "State": col(r, "state")} for r in rows]
    return [Finding(
        "unmanaged-accounts", "HIGH",
        "Personal Google accounts using company email addresses",
        "People have created personal (unmanaged) Google accounts on the "
        "organisation's own domain. Those accounts, and any company data in "
        "them, sit outside admin control: the organisation cannot enforce a "
        "password policy or 2-step verification on them, and cannot close "
        "them when the person leaves.",
        "Send invitations to convert these into managed accounts (Admin "
        "console > Directory > User invitations), and chase the holdouts.",
        evidence, "userinvitations.csv")]


def check_dns_findings(ctx: RunContext) -> List[Finding]:
    dns_path = ctx.run_dir / "dns.json"
    if not (_module_usable(ctx, "dns") and dns_path.is_file()):
        return []
    try:
        results = json.loads(dns_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(results, dict):
        return []
    findings = []
    for check, fid, severity, title, meaning, remediation in DNS_FINDINGS:
        hits = []
        for domain, entry in results.items():
            result = (entry.get("checks") or {}).get(check) or {}
            if _dns_check_failed(result):
                via = "dns.google" if "present" in result else "tamingdns.com"
                hits.append({"Domain": domain, "Checked via": via})
        if hits:
            findings.append(Finding(fid, severity, title, meaning,
                                    remediation, hits, "dns.json"))
    return findings


def _dns_check_failed(result: Dict) -> bool:
    """One tamingdns or DoH check result: does it say the record is missing
    or broken? Trusts the checker's own verdict: a fail status, a grade of
    F, a not_configured verdict, or any finding it grades critical/high.
    Info/warn findings (deprecated tags, org-domain inheritance) are not
    failures. A missing SPF record on the dev tenant (2026-08-15) came back
    as status info, grade F, verdict not_configured, with an info-severity
    finding: status alone never fired."""
    if "present" in result:                     # DoH fallback shape
        return not result["present"]
    if "error" in result:
        return False
    status = str(result.get("status", "")).lower()
    grade = str(result.get("grade", "")).upper()
    verdict = str(result.get("verdict", "")).lower()
    worst = {str(f.get("severity", "")).lower()
             for f in result.get("findings", []) if isinstance(f, dict)}
    return (status in ("fail", "error") or grade == "F"
            or verdict in ("not_configured", "missing", "invalid")
            or bool(worst & {"critical", "high"}))


# (dns.json check key, finding id, severity, title, meaning, remediation).
DNS_FINDINGS = [
    ("dmarc", "dmarc-missing", "HIGH",
     "Domains without a working DMARC record",
     "Without DMARC, anyone can send mail that claims to be from these "
     "domains and receiving servers have no instruction to reject it. "
     "That enables convincing invoice fraud and phishing in the "
     "organisation's name.",
     "Publish a DMARC record for each domain, starting at p=none to "
     "observe, then move to quarantine/reject once legitimate senders "
     "are aligned. Full per-domain detail is in the DNS section below."),
    ("spf", "spf-missing", "HIGH",
     "Domains without a working SPF record",
     "SPF names the servers allowed to send mail for the domain. Without "
     "it, or with a broken record, receiving servers cannot tell the "
     "organisation's mail from a forgery, and DMARC has nothing to align "
     "against.",
     "Publish one SPF record per domain listing Google and every other "
     "legitimate sender, ending in ~all or -all. Detail per domain is in "
     "the DNS section below."),
    ("dkim", "dkim-missing", "MEDIUM",
     "Domains without DKIM signing for Google",
     "Mail from these domains is not signed, so a receiving server cannot "
     "verify it was not altered in transit, and DMARC alignment has to "
     "rely on SPF alone, which breaks when mail is forwarded.",
     "Generate and publish the Google DKIM key in Admin console > Apps > "
     "Google Workspace > Gmail > Authenticate email, then start "
     "authentication."),
    ("mx", "mx-problem", "MEDIUM",
     "Domains with mail delivery (MX) problems",
     "The checker found the domain's MX records missing, broken or not "
     "pointing where mail is actually handled. Mail for these domains may "
     "bounce or land somewhere nobody is watching.",
     "Compare the MX records against what Google Workspace expects and fix "
     "the ones that differ. Detail per domain is in the DNS section below."),
]


def check_2sv_enrolment(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "users"):
        return []
    users = _live_users(ctx)
    if not users:
        return []
    unenrolled = [r for r in users if not truthy(col(r, "isEnrolledIn2Sv"))]
    if not unenrolled:
        return []
    pct = round(100 * (len(users) - len(unenrolled)) / len(users))
    evidence = [{"User": col(r, "primaryEmail"),
                 "Last login": col(r, "lastLoginTime")} for r in unenrolled]
    return [Finding(
        "2sv-enrolment", "MEDIUM",
        f"2-step verification enrolment is at {pct}%",
        f"{len(unenrolled)} of {len(users)} active accounts sign in with a "
        "password alone. A guessed or phished password on any of them gives "
        "an attacker the whole account.",
        "Run an enrolment campaign, then enforce 2-step verification by "
        "organisational unit once enrolment is high enough not to lock "
        "people out.",
        evidence, "users.csv", count=len(unenrolled))]


def check_pop_imap(ctx: RunContext) -> List[Finding]:
    findings = []
    for key, proto in (("imap", "IMAP"), ("pop", "POP")):
        if not _module_usable(ctx, key):
            continue
        hits = [{"User": col(r, "User", "user")} for r in ctx.rows(key)
                if truthy(col(r, "enabled"))]
        if hits:
            findings.append(Finding(
                f"{proto.lower()}-enabled", "MEDIUM",
                f"{proto} access is enabled on {len(hits)} mailbox(es)",
                f"{proto} lets older mail apps download the whole mailbox "
                "with just a password (or an app password). That sidesteps "
                "modern sign-in protections and leaves a full copy of the "
                "mail on whatever device connects.",
                f"Where no legacy mail client genuinely needs it, turn "
                f"{proto} off for the user - or disable it tenant-wide in "
                "Gmail settings if nobody does.",
                hits, f"{key}.csv"))
    return findings


GAM_NEVER_LOGIN = "Never"


def _paid_licences(row: Dict[str, str]) -> str:
    """The user's licence display string with free Cloud Identity stripped.

    Cloud Identity (non-Premium) auto-assigns and costs nothing, so an
    account holding only that is unlicensed for every costs-money finding.
    Cloud Identity Premium is a paid SKU and stays.
    """
    licences = col(row, "LicensesDisplay", "Licenses", "licenses")
    stripped = re.sub(r"Cloud Identity(?! Premium)( Free)?", "",
                      licences).strip()
    return licences if stripped else ""


def _never_logged_in(last: str) -> bool:
    # GAM prints "Never" or a 1970 epoch stamp for an account with no login.
    return not last or last == GAM_NEVER_LOGIN or last.startswith("1970-")


def _dormant_login(last: str, days: int = DORMANT_DAYS) -> bool:
    """True when the lastLoginTime string is absent, epoch, or older than
    `days`. Unparseable stamps count as NOT dormant - a formatting change in
    GAM must not flag the whole tenant."""
    if _never_logged_in(last):
        return True
    try:
        stamp = datetime.fromisoformat(last.replace("Z", "+00:00"))
    except ValueError:
        return False
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp < datetime.now(timezone.utc) - timedelta(days=days)


def _break_glass(ctx: RunContext, email: str) -> bool:
    """True for an emergency account listed in tenants.json. Such an account
    is deliberately never used, so dormancy checks skip it; the report names
    every one it skipped so the exclusion is never silent."""
    email = email.lower()
    if email not in ctx.manifest["meta"].get("break_glass", []):
        return False
    seen = ctx.manifest["meta"].setdefault("break_glass_seen", [])
    if email not in seen:
        seen.append(email)
    return True


def check_dormant_accounts(ctx: RunContext) -> List[Finding]:
    """Dormancy in three tiers: dormant admins (HIGH, licence irrelevant),
    licensed accounts that have never signed in, and licensed accounts idle
    past the cutoff."""
    if not _module_usable(ctx, "users"):
        return []
    admin_hits, never_hits, idle_hits = [], [], []
    for row in _live_users(ctx):
        last = col(row, "lastLoginTime")
        if not _dormant_login(last) \
                or _break_glass(ctx, col(row, "primaryEmail")):
            continue
        paid = _paid_licences(row)
        entry = {"User": col(row, "primaryEmail"),
                 "Last login": "never" if _never_logged_in(last) else last,
                 "Licences": paid or "none"}
        role = _admin_role(row)
        if role:
            entry["Admin role"] = role
            admin_hits.append(entry)
        elif not paid:
            continue
        elif _never_logged_in(last):
            never_hits.append(entry)
        else:
            idle_hits.append(entry)
    findings = []
    if admin_hits:
        findings.append(Finding(
            "dormant-admin", "HIGH",
            "Admin accounts nobody has signed into for months",
            "These accounts hold admin rights but show no recent sign-in. "
            "An account with tenant-level power that nobody is watching is "
            "the one an attacker can use longest without being noticed.",
            "Confirm each account is still needed. Remove admin rights from "
            "accounts that no longer need them, and sign in periodically to "
            "the ones kept as break-glass access so activity is expected "
            "and monitored.",
            admin_hits, "users.csv"))
    if never_hits:
        findings.append(Finding(
            "never-logged-in", "MEDIUM",
            "Licensed accounts that have never been signed into",
            "These accounts were created, given a paid licence, and never "
            "used. They cost money every month and usually mean an "
            "onboarding that never happened or a leaver created in error.",
            "Confirm each account's purpose; delete or unlicense the ones "
            "that were never needed.",
            never_hits, "users.csv"))
    if idle_hits:
        findings.append(Finding(
            "dormant-licensed", "MEDIUM",
            f"Licensed accounts with no sign-in for over {DORMANT_DAYS} days",
            "These accounts hold paid licences but nobody has signed in for "
            "months. They cost money every month, and because nobody is "
            "watching them, a break-in there can go unnoticed for a long "
            "time.",
            "Confirm each account's purpose. Offboard leavers properly, "
            "convert genuine service accounts to unlicensed alternatives "
            "where possible, and reclaim the licences.",
            idle_hits, "users.csv"))
    return findings


def check_mailbox_delegation(ctx: RunContext) -> List[Finding]:
    """Who can read whose mail. Gmail delegates are internal-only, so there
    is no external-delegate case; the risk tiers are delegates on admin
    mailboxes and delegation nobody is watching.

    Caveat: the delegates module iterates ACTIVE users, so a suspended
    DELEGATOR's grants are invisible unless suspended users were included in
    the collection run."""
    if not (_module_usable(ctx, "delegates") and _module_usable(ctx, "users")):
        return []
    users = {col(r, "primaryEmail").lower(): r for r in ctx.rows("users")}
    admin_hits, watch_hits, table = [], [], []
    for row in ctx.rows("delegates"):
        delegator = col(row, "User", "user").lower()
        delegate = col(row, "delegateAddress", "delegateEmail",
                       "delegate").lower()
        if not delegate:
            continue
        table.append({"Mailbox": delegator, "Delegate": delegate,
                      "Status": col(row, "delegationStatus", "status")})
        entry = {"Mailbox": delegator, "Delegate": delegate}
        d_row = users.get(delegator)
        g_row = users.get(delegate)
        if d_row is not None and (truthy(col(d_row, "isAdmin"))
                                  or truthy(col(d_row, "isDelegatedAdmin"))):
            entry["Admin role"] = ("super admin"
                                   if truthy(col(d_row, "isAdmin"))
                                   else "delegated admin")
            admin_hits.append(entry)
        concerns = []
        for label, urow in (("mailbox owner", d_row), ("delegate", g_row)):
            if urow is None:
                continue
            if truthy(col(urow, "suspended")):
                concerns.append(f"{label} suspended")
            elif _dormant_login(col(urow, "lastLoginTime")):
                concerns.append(f"{label} dormant")
        if concerns:
            watch_hits.append(dict(entry, **{"Why": ", ".join(concerns)}))
    findings = []
    if admin_hits:
        findings.append(Finding(
            "delegates-on-admin-mailbox", "HIGH",
            "Admin mailboxes with delegates",
            "Someone else can read and send mail as an admin. Admin "
            "mailboxes receive password resets, security alerts and "
            "recovery mail - a delegate there can intercept all of it "
            "without ever knowing the admin's password.",
            "Remove delegation from admin mailboxes. If shared visibility "
            "of admin notifications is needed, route the alerts to a group "
            "instead.",
            admin_hits, "delegates.csv"))
    if watch_hits:
        findings.append(Finding(
            "delegation-unwatched", "MEDIUM",
            "Mailbox delegation involving suspended or dormant accounts",
            "These delegations involve an account that is suspended or has "
            "not signed in for months. Access that nobody is actively "
            "using or watching tends to be forgotten - and forgotten "
            "access is what turns up in incident reports.",
            "Remove delegations that are no longer in use, and re-point "
            "the ones that still serve a purpose at active accounts.",
            watch_hits, "delegates.csv"))
    if table:
        findings.append(Finding(
            "delegation-map", "INFO",
            "Who can read whose mailbox (delegation map)",
            "Every mailbox delegation in the tenant. Each row means the "
            "delegate can read, send and delete mail in that mailbox "
            "without the owner's password.",
            "No action needed; review the list for surprises.",
            table, "delegates.csv"))
    return findings


def check_at_risk_accounts(ctx: RunContext) -> List[Finding]:
    """One table per person instead of six separate lists: accounts scoring
    two or more independent risk factors."""
    if not _module_usable(ctx, "users"):
        return []
    internal = {d.lower() for d in ctx.internal_domains}
    asp_users = set()
    if _module_usable(ctx, "asps"):
        asp_users = {col(r, "User").lower() for r in _asp_rows(ctx)}
    risky_users = set()
    if _module_usable(ctx, "tokens"):
        risky_users = {col(r, "user").lower() for r in ctx.rows("tokens")
                       if _risky_scope_labels(r)}
    hits = []
    admin_flagged = False
    for row in _live_users(ctx):
        email = col(row, "primaryEmail").lower()
        admin = bool(_admin_role(row))
        reasons = []
        if not truthy(col(row, "isEnrolledIn2Sv")):
            reasons.append("no 2-step verification")
        recovery = col(row, "recoveryEmail")
        # A missing recovery email is not a factor, for anyone. Scoring both
        # "none" and "personal" left only an internal address as safe, so
        # every account carried one factor and any company-wide app grant
        # pushed nearly the whole tenant over the line (37 of 47 on a live
        # tenant, 2026-10-01).
        if recovery and email_domain(recovery) not in internal:
            reasons.append("personal recovery email")
        if email in asp_users:
            reasons.append("app-specific passwords")
        if email in risky_users:
            reasons.append("app with full mail/Drive access")
        # Holding an admin role is not itself a factor: an admin without 2SV
        # already has a CRITICAL finding of its own and appeared here a third
        # time. It still raises the severity when an admin does qualify.
        if _dormant_login(col(row, "lastLoginTime")) \
                and not _break_glass(ctx, email):
            reasons.append(f"no sign-in in {DORMANT_DAYS}+ days")
        if len(reasons) >= 2:
            admin_flagged = admin_flagged or admin
            hits.append({"User": col(row, "primaryEmail"),
                         "Risk factors": ", ".join(reasons)})
    if not hits:
        return []
    return [Finding(
        "at-risk-accounts", "HIGH" if admin_flagged else "MEDIUM",
        f"{len(hits)} account(s) carrying multiple risk factors",
        "Each account here combines at least two separate weaknesses - for "
        "example no 2-step verification plus a personal recovery address. "
        "Risk factors multiply: any one alone is survivable, together they "
        "make an account both easier to break into and harder to recover.",
        "Work through the list per person: enrol 2-step verification, "
        "point recovery details at organisation-controlled addresses, and "
        "revoke app passwords and over-broad app grants that are no longer "
        "needed.",
        hits, "users.csv")]


def check_suspended_holding_data(ctx: RunContext) -> List[Finding]:
    """Offboarding debt: suspended accounts that still cost money or still
    hold data nobody can reach."""
    if not _module_usable(ctx, "users"):
        return []
    suspended = {col(r, "primaryEmail").lower(): r for r in ctx.rows("users")
                 if truthy(col(r, "suspended"))}
    if not suspended:
        return []
    findings = []
    licensed = [{"User": email, "Licences": _paid_licences(row)}
                for email, row in sorted(suspended.items())
                if _paid_licences(row)]
    if licensed:
        findings.append(Finding(
            "suspended-licensed", "MEDIUM",
            f"{len(licensed)} suspended account(s) still holding a licence",
            "These accounts are suspended - typically leavers - but still "
            "hold paid licences. The organisation is paying every month "
            "for accounts nobody can sign into.",
            "Finish the offboarding: transfer any data that is still "
            "needed, then remove the licence (or delete the account once "
            "its data is safe).",
            licensed, "users.csv"))
    data_rows = []
    if _module_usable(ctx, "report_users"):
        for row in ctx.rows("report_users"):
            email = col(row, "email", "userEmail", "User").lower()
            if email not in suspended:
                continue
            gmail_mb = col(row, "accounts:gmail_used_quota_in_mb")
            drive_mb = col(row, "accounts:drive_used_quota_in_mb")
            if any(v not in ("", "0") for v in (gmail_mb, drive_mb)):
                data_rows.append({"User": email,
                                  "Gmail (MB)": gmail_mb or "0",
                                  "Drive (MB)": drive_mb or "0",
                                  "Holds": "mailbox/Drive data"})
    if _module_usable(ctx, "shareddriveacls"):
        for row in ctx.rows("shareddriveacls"):
            if truthy(col(row, "permission.deleted")):
                continue
            addr = col(row, "permission.emailAddress", "emailAddress").lower()
            role = col(row, "permission.role", "role")
            if addr in suspended and role in ("organizer", "fileOrganizer"):
                data_rows.append({"User": addr, "Gmail (MB)": "",
                                  "Drive (MB)": "",
                                  "Holds": f"manager of Shared Drive "
                                           f"\"{col(row, 'name')}\""})
    if data_rows:
        findings.append(Finding(
            "suspended-holding-data", "INFO",
            "Suspended accounts still holding data or drive roles",
            "These suspended accounts still hold mailbox or Drive data, or "
            "a manager role on a Shared Drive. The data is frozen with "
            "them: colleagues cannot reach it, and a drive whose only "
            "manager is suspended cannot be administered by its users. "
            "Usage figures lag about two days behind live state.",
            "Fold this into the offboarding plan: transfer mail and files "
            "to a successor, and re-point Shared Drive manager roles at "
            "active staff.",
            data_rows, "report_users.csv"))
    return findings


# Read-only scopes are here on purpose: an app that can read every mail or
# file can copy every mail or file, which is the exposure being scored.
RISKY_SCOPES = {
    "https://mail.google.com/": "full Gmail access",
    "https://www.googleapis.com/auth/gmail.modify": "read and change Gmail",
    "https://www.googleapis.com/auth/gmail.readonly": "read all Gmail",
    "https://www.googleapis.com/auth/drive": "full Drive access",
    "https://www.googleapis.com/auth/drive.readonly": "read all of Drive",
    "https://www.googleapis.com/auth/admin.directory.user":
        "manage user accounts",
}


def check_risky_oauth(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "tokens"):
        return []
    apps: Dict[str, Dict] = {}
    for row in ctx.rows("tokens"):
        matched = _risky_scope_labels(row)
        if not matched:
            continue
        client = col(row, "displayText") or col(row, "clientId")
        app = apps.setdefault(client, {"users": set(), "access": set()})
        app["users"].add(col(row, "user"))
        app["access"].update(matched)
    if not apps:
        return []
    ranked = sorted(apps.items(), key=lambda kv: -len(kv[1]["users"]))
    evidence = [{"App": name,
                 "Users": str(len(data["users"])),
                 "Access": ", ".join(sorted(data["access"]))}
                for name, data in ranked]
    return [Finding(
        "risky-oauth-apps", "MEDIUM",
        "Third-party apps holding full mailbox or Drive access",
        "These apps have been granted the widest Gmail or Drive scopes - "
        "they can read, change and delete everything in the accounts that "
        "authorised them. A breach at any one of these vendors becomes a "
        "breach of that data.",
        "Review each app: still in use, and does it genuinely need full "
        "access? Revoke the rest, and consider restricting future grants "
        "with app access control in the Admin console.",
        evidence, "tokens.csv", count=len(apps))]


def check_admin_recovery(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "users"):
        return []
    internal = set(ctx.internal_domains)
    hits = []
    for row in _super_admins(ctx):
        recovery = col(row, "recoveryEmail")
        phone = col(row, "recoveryPhone")
        entry = {"Super admin": col(row, "primaryEmail"),
                 "Recovery email": "", "Recovery phone": ""}
        if recovery and email_domain(recovery) not in internal:
            entry["Recovery email"] = recovery
        if phone:
            # A phone number is always a personal channel and the SIM-swap
            # path; shown masked, the client knows whose it is.
            entry["Recovery phone"] = "..." + phone[-4:]
        if entry["Recovery email"] or entry["Recovery phone"]:
            hits.append(entry)
    if not hits:
        return []
    return [Finding(
        "admin-personal-recovery", "MEDIUM",
        "Super admin accounts with personal recovery details",
        "Account recovery for these admin accounts routes through a "
        "personal mailbox or phone number the organisation does not "
        "control. Whoever controls or compromises that mailbox, or moves "
        "that number to another SIM, can reset the admin password, and "
        "with super admin self-recovery switched on needs nobody else.",
        "Point admin recovery details at organisation-controlled "
        "addresses, or remove them and rely on a second super admin for "
        "recovery.",
        hits, "users.csv")]


def check_admin_backup_codes(ctx: RunContext) -> List[Finding]:
    """Super admins holding no backup verification codes. A super admin
    missing from backupcodes.csv was not read (partial module, or the
    account was out of scan scope) and is left out rather than counted as
    zero."""
    if not (_module_usable(ctx, "users") and _module_usable(ctx, "backupcodes")):
        return []
    counts = {col(r, "User").lower(): col(r, "verificationCodesCount").strip()
              for r in ctx.rows("backupcodes")}
    hits = []
    for row in _live_users(ctx):
        email = col(row, "primaryEmail")
        count = counts.get(email.lower())
        if not truthy(col(row, "isAdmin")) or count is None:
            continue
        if count in ("", "0"):
            hits.append({"Super admin": email, "Backup codes": count or "0"})
    if not hits:
        return []
    return [Finding(
        "admin-no-backup-codes", "MEDIUM",
        "Super admins with no backup verification codes",
        "These super admins have never generated backup codes. If their phone "
        "or security key is lost, the only way back in is another super admin "
        "or Google's recovery process, which asks for billing details and a "
        "DNS change on the domain.",
        "Have each super admin generate backup codes (myaccount.google.com > "
        "Security > 2-Step Verification > Backup codes) and store them "
        "offline, somewhere the account itself is not needed to reach.",
        hits, "backupcodes.csv")]


def check_licensed_super_admins(ctx: RunContext) -> List[Finding]:
    """Super admins holding a paid licence. INFO, not a defect: a backup
    tool may need a licensed super admin (Acronis needs Business Standard to
    discover Shared drives), so this is a decision to record."""
    if not _module_usable(ctx, "users"):
        return []
    hits = [{"Super admin": col(r, "primaryEmail"),
             "Licence": _paid_licences(r)}
            for r in _live_users(ctx)
            if truthy(col(r, "isAdmin")) and _paid_licences(r)]
    if not hits:
        return []
    return [Finding(
        "licensed-super-admins", "INFO",
        "Super admin accounts that also hold a paid licence",
        "These super admins have a mailbox and a Drive, so they receive "
        "phishing mail and open shared files with the most powerful account "
        "in the tenant. An unlicensed super admin can only sign in, and costs "
        "nothing.",
        "Consider a separate unlicensed admin account for each person who "
        "needs super admin, used only for admin work, and remove admin rights "
        "from their everyday licensed account. Keep the licence where a tool "
        "such as a backup service needs it.",
        hits, "users.csv", count=len(hits))]


def check_public_calendars(ctx: RunContext) -> List[Finding]:
    if not _module_usable(ctx, "calendaracls"):
        return []
    hits = []
    for row in ctx.rows("calendaracls"):
        # scope.type "default" is the public grant. A domain-wide reader row
        # is the tenant default and is NOT a finding.
        if col(row, "scope.type") == "default":
            hits.append({"User": col(row, "primaryEmail", "User"),
                         "Public role": col(row, "role")})
    if not hits:
        return []
    return [Finding(
        "public-calendars", "MEDIUM",
        "Primary calendars visible to anyone on the internet",
        "These calendars are shared with the public. Meeting titles, "
        "attendees and locations reveal a lot: who the organisation deals "
        "with, and when people are away.",
        "Have each user (or an admin) set the calendar's public sharing "
        "back to off; sharing inside the organisation is unaffected.",
        hits, "calendaracls.csv")]


def check_sendas(ctx: RunContext) -> List[Finding]:
    """Send-as addresses outside the organisation. A user sending as an
    external address puts company mail under an identity the tenant does
    not control; an unverified one is a setup someone abandoned or is
    still trying to complete."""
    if not _module_usable(ctx, "sendas"):
        return []
    internal = set(ctx.internal_domains)
    hits = []
    for row in ctx.rows("sendas"):
        addr = col(row, "sendAsEmail")
        if truthy(col(row, "isPrimary")) or not addr:
            continue
        if email_domain(addr) not in internal:
            hits.append({"User": col(row, "User"), "Sends as": addr,
                         "Verified": col(row, "verificationStatus") or "?",
                         "Reply-to": col(row, "replyToAddress")})
    if not hits:
        return []
    return [Finding(
        "sendas-external", "MEDIUM",
        "Mailboxes that can send as an address outside the organisation",
        "These users can send mail that appears to come from an external "
        "address. Replies then go to that address, outside the tenant's "
        "logs, retention and offboarding. A pending verification is an "
        "external mailbox someone tried to attach.",
        "Confirm each send-as address with the user; remove any that are not "
        "a known business arrangement, and the pending ones.",
        hits, "sendas.csv")]


def check_forwarding_addresses(ctx: RunContext) -> List[Finding]:
    """External forwarding addresses on file, whether or not forwarding is
    switched on. An accepted address stays valid after forwarding is turned
    off, so it can be switched back on with one click and no confirmation."""
    if not _module_usable(ctx, "forwardingaddresses"):
        return []
    internal = set(ctx.internal_domains)
    hits = [{"User": col(r, "User"),
             "Forwarding address": col(r, "forwardingEmail"),
             "Status": col(r, "verificationStatus") or "?"}
            for r in ctx.rows("forwardingaddresses")
            if col(r, "forwardingEmail")
            and email_domain(col(r, "forwardingEmail")) not in internal]
    if not hits:
        return []
    return [Finding(
        "forwarding-addresses-external", "MEDIUM",
        "External forwarding addresses on file",
        "These mailboxes have an outside address registered as a forwarding "
        "destination. Forwarding may be off today, but an accepted address "
        "needs no new confirmation to switch on, and a pending one shows "
        "someone tried. The forwarding finding above lists what is active "
        "now; this is the door left unlocked.",
        "Remove forwarding addresses that are not a known business "
        "arrangement (Gmail settings > Forwarding and POP/IMAP, or via GAM).",
        hits, "forwardingaddresses.csv")]


def check_group_members(ctx: RunContext) -> List[Finding]:
    """Group membership hygiene from group_members.csv: external members
    actually present (the groups check reports the setting that allows
    them), groups with no owner, and owners who are suspended."""
    if not _module_usable(ctx, "group_members"):
        return []
    internal = set(ctx.internal_domains)
    users = {col(r, "primaryEmail").lower(): r for r in ctx.rows("users")}
    external, suspended_owner = [], []
    owners: Dict[str, int] = {}
    for row in ctx.rows("group_members"):
        group = col(row, "group")
        member = col(row, "email")
        role = col(row, "role").upper()
        if role == "OWNER":
            owners[group] = owners.get(group, 0) + 1
            urow = users.get(member.lower())
            if urow is not None and truthy(col(urow, "suspended")):
                suspended_owner.append({"Group": group, "Owner": member})
        if member and col(row, "type").upper() != "CUSTOMER" \
                and email_domain(member) not in internal:
            external.append({"Group": group, "External member": member,
                             "Role": role.lower()})
    findings = []
    if external:
        findings.append(Finding(
            "groups-external-members-present", "HIGH",
            "Groups with members from outside the organisation",
            "These addresses belong to other organisations or personal "
            "accounts and receive everything sent to the group, and can open "
            "anything shared with it.",
            "Review each external member: still needed, and is the group "
            "used only for what they should see? Remove the rest.",
            external, "group_members.csv"))
    ownerless = []
    if _module_usable(ctx, "groups"):
        # Classroom creates classroom_teachers@ itself and manages it
        # without an owner; flagging it is noise on every school tenant.
        ownerless = [{"Group": col(g, "email"), "Name": col(g, "name")}
                     for g in ctx.rows("groups")
                     if col(g, "email") and not owners.get(col(g, "email"))
                     and not col(g, "email").lower().startswith(
                         CLASSROOM_TEACHERS_LOCAL + "@")]
    if ownerless:
        findings.append(Finding(
            "groups-no-owner", "MEDIUM",
            "Groups with no owner",
            "Nobody but an admin can manage membership or settings on these "
            "groups. Membership drifts, leavers stay on the list, and "
            "nobody is accountable for what the group can access.",
            "Assign an owner to each group, or delete groups nobody claims.",
            ownerless, "group_members.csv"))
    if suspended_owner:
        findings.append(Finding(
            "groups-suspended-owner", "MEDIUM",
            "Groups owned by suspended accounts",
            "The owner of these groups is suspended, typically a leaver. The "
            "group keeps working but nobody active can manage it.",
            "Transfer ownership to active staff as part of finishing the "
            "offboarding.",
            suspended_owner, "group_members.csv"))
    return findings


def check_vacation(ctx: RunContext) -> List[Finding]:
    """Out-of-office responders that answer anyone, not just contacts or
    the domain. Collected only with --full."""
    if not _module_usable(ctx, "vacation"):
        return []
    hits = [{"User": col(r, "User"), "Subject": col(r, "subject"),
             "Ends": col(r, "enddate") or "no end date"}
            for r in ctx.rows("vacation")
            if truthy(col(r, "enabled"))
            and not truthy(col(r, "domainonly"))
            and not truthy(col(r, "contactsonly"))]
    if not hits:
        return []
    return [Finding(
        "vacation-replies-to-anyone", "INFO",
        "Out-of-office replies sent to anyone who writes in",
        "These auto-replies answer every sender, including spammers and "
        "attackers, confirming the address is live and often naming who is "
        "covering and until when. A responder with no end date is usually "
        "a leaver's.",
        "Ask users to limit auto-replies to contacts or the organisation, and "
        "clear responders on accounts that are being offboarded.",
        hits, "vacation.csv")]


def check_vault_exports(ctx: RunContext) -> List[Finding]:
    """Vault exports on record. An export is a copy of mail or files that
    left the tenant's controls; each one should be accounted for."""
    if not _module_usable(ctx, "vaultexports"):
        return []
    rows = [{"Matter": col(r, "matterName"), "Export": col(r, "name"),
             "Created": col(r, "createTime")}
            for r in ctx.rows("vaultexports")]
    if not rows:
        return []
    return [Finding(
        "vault-exports", "INFO",
        f"{len(rows)} Vault export(s) on record",
        "Each Vault export is a downloadable copy of mailboxes, files or "
        "chats. Exports are legitimate for legal holds and investigations, "
        "and also the cleanest way to take a bulk copy of company data.",
        "Confirm each export against a known matter, and delete exports "
        "whose purpose has passed.",
        rows, "vaultexports.csv")]


def check_google_suspended(ctx: RunContext) -> List[Finding]:
    """Accounts Google suspended, rather than an admin: abuse, compromise
    or investigation. suspensionReason is ADMIN for the ordinary case."""
    if not _module_usable(ctx, "users"):
        return []
    hits = [{"User": col(r, "primaryEmail"),
             "Reason": col(r, "suspensionReason")}
            for r in ctx.rows("users")
            if truthy(col(r, "suspended"))
            and col(r, "suspensionReason").upper() not in ("", "ADMIN")]
    if not hits:
        return []
    return [Finding(
        "google-suspended-accounts", "HIGH",
        "Accounts suspended by Google, not by an admin",
        "Google suspends an account itself when it sees abuse, a compromise "
        "or a policy breach. Each of these is an incident someone should "
        "have looked into, and the reason code says what Google saw.",
        "Open each account in the Admin console, read the suspension notice, "
        "and treat compromise reasons as an incident: reset, review "
        "forwarding, filters, delegates and app tokens before restoring.",
        hits, "users.csv")]


def check_new_accounts(ctx: RunContext) -> List[Finding]:
    """Accounts created in the last ACTIVITY_DAYS days. Context for an
    inherited tenant and a compromise indicator: an attacker with admin
    rights creates a mailbox of their own."""
    if not _module_usable(ctx, "users"):
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=ACTIVITY_DAYS)
    hits = []
    for row in ctx.rows("users"):
        created = col(row, "creationTime")
        try:
            stamp = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            continue
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        if stamp >= cutoff:
            hits.append({"User": col(row, "primaryEmail"), "Created": created,
                         "Org unit": col(row, "orgUnitPath"),
                         "Admin": _admin_role(row) or "-"})
    if not hits:
        return []
    hits.sort(key=lambda h: h["Created"], reverse=True)
    return [Finding(
        "new-accounts", "INFO",
        f"{len(hits)} account(s) created in the last {ACTIVITY_DAYS} days",
        "Recently created accounts. On a tenant you have just taken over, "
        "each one should match a known starter; an account nobody can "
        "explain, especially one holding an admin role, is how a compromised "
        "admin keeps access.",
        "Match each account to a starter or a system that needs it.",
        hits, "users.csv")]


def check_admin_2sv_enforced(ctx: RunContext) -> List[Finding]:
    """Super admins enrolled in 2SV but not under enforcement. Enrolment is
    the user's own setting and can be switched off by the user or by an
    attacker holding the password; enforcement is the admin's control."""
    if not _module_usable(ctx, "users"):
        return []
    hits = [{"Super admin": col(r, "primaryEmail")}
            for r in _super_admins(ctx)
            if truthy(col(r, "isEnrolledIn2Sv"))
            and not truthy(col(r, "isEnforcedIn2Sv"))]
    if not hits:
        return []
    return [Finding(
        "admin-2sv-not-enforced", "MEDIUM",
        "Super admins whose 2-step verification is not enforced by policy",
        "These super admins use 2-step verification today, but nothing "
        "requires it. Anyone holding the password can switch it off in the "
        "account's own settings, and Google's own guidance is to enforce it "
        "for admins.",
        "Put super admins in an organisational unit or group with 2-step "
        "verification enforced (Admin console > Security > Authentication > "
        "2-step verification), with a short enrolment period.",
        hits, "users.csv")]


def check_root_ou_users(ctx: RunContext) -> List[Finding]:
    """Users left in the root OU on a tenant that has other OUs. Policy is
    applied per OU, so accounts in the root get whatever the root says,
    usually the loosest settings."""
    if not (_module_usable(ctx, "users") and _module_usable(ctx, "orgs")):
        return []
    if not ctx.rows("orgs"):
        return []
    hits = [{"User": col(r, "primaryEmail"), "Admin": _admin_role(r) or "-"}
            for r in _live_users(ctx) if col(r, "orgUnitPath") == "/"]
    if not hits:
        return []
    return [Finding(
        "users-in-root-ou", "INFO",
        f"{len(hits)} account(s) in the root organisational unit",
        "The tenant has organisational units, but these accounts sit at the "
        "root, outside all of them. They get the root's settings, which are "
        "usually the loosest, and are missed by any policy set on a "
        "sub-unit. Dedicated admin accounts at the root are conventional.",
        "Move everyday user accounts into the organisational unit that "
        "matches their role.",
        hits, "users.csv")]


def check_shared_drive_download_controls(ctx: RunContext) -> List[Finding]:
    """Per-drive copy and download controls left open. The tenant default
    is in sd-controls-open; this is what each drive actually has."""
    if not _module_usable(ctx, "shareddrives"):
        return []
    hits = []
    for row in ctx.rows("shareddrives"):
        copy_ok = col(row, "restrictions.copyRequiresWriterPermission")
        dl_ok = col(row, "restrictions.downloadRestriction.restrictedForReaders")
        open_bits = []
        if copy_ok and not truthy(copy_ok):
            open_bits.append("viewers can copy, print and download")
        if dl_ok and not truthy(dl_ok):
            open_bits.append("download not restricted for readers")
        if open_bits:
            hits.append({"Shared Drive": col(row, "name"),
                         "Open controls": ", ".join(open_bits)})
    if not hits:
        return []
    return [Finding(
        "sd-download-copy-open", "INFO",
        "Shared Drives where viewers can copy, print or download",
        "Anyone with view access to these drives can take a copy of the "
        "files. That is normal for working drives and worth closing on "
        "drives holding contracts, HR or client data.",
        "Tick \"viewers and commenters cannot download, print or copy\" on "
        "the drives that hold sensitive material.",
        hits, "shareddrives.csv")]


def check_oauth_inventory(ctx: RunContext) -> List[Finding]:
    """Every third-party app holding a token, with user counts. The risky
    check judges scopes; this is the inventory a due-diligence reader wants,
    and it names apps Google could not identify (anonymous)."""
    if not _module_usable(ctx, "tokens"):
        return []
    apps: Dict[str, Dict] = {}
    for row in ctx.rows("tokens"):
        client = col(row, "displayText") or col(row, "clientId")
        app = apps.setdefault(client, {"users": set(), "anonymous": False,
                                       "scopes": 0})
        app["users"].add(col(row, "user"))
        app["anonymous"] = app["anonymous"] or truthy(col(row, "anonymous"))
        app["scopes"] = max(app["scopes"], len(col(row, "scopes").split()))
    if not apps:
        return []
    rows = [{"App": name, "Users": str(len(d["users"])),
             "Scopes": str(d["scopes"]),
             "Unidentified": "yes" if d["anonymous"] else ""}
            for name, d in sorted(apps.items(),
                                  key=lambda kv: (-kv[1]["anonymous"],
                                                  -len(kv[1]["users"])))]
    anon = sum(1 for d in apps.values() if d["anonymous"])
    return [Finding(
        "oauth-app-map", "INFO",
        f"{len(apps)} third-party app(s) hold access to user accounts"
        + (f", {anon} unidentified" if anon else ""),
        "Every app users have authorised, with how many accounts each one "
        "reaches. An unidentified app is one Google could not attribute to a "
        "registered developer.",
        "Review the list for apps nobody recognises, and revoke access to "
        "those; the apps with the widest access are in the finding above.",
        rows, "tokens.csv", count=len(apps))]


def check_user_password_strength(ctx: RunContext) -> List[Finding]:
    """Per-user password findings from the usage report: Google rates each
    password as weak or non-compliant with the tenant's length policy. The
    policy check says what the rule is; this says who is not meeting it."""
    if not _module_usable(ctx, "report_users"):
        return []
    # users only narrows the list to live accounts, so it is read without
    # recording it: its absence must not stop a clean result.
    live = {col(r, "primaryEmail").lower() for r in _live_users(ctx)} \
        if ctx.module_status("users") in ("ok", "empty", "partial") else None
    hits = []
    for row in ctx.rows("report_users"):
        email = col(row, "email", "userEmail").lower()
        if live is not None and email not in live:
            continue
        strength = col(row, "accounts:password_strength").upper()
        length = col(row, "accounts:password_length_compliance").upper()
        problems = []
        if strength == "WEAK":
            problems.append("weak password")
        if length == "NON_COMPLIANT":
            problems.append("shorter than the policy minimum")
        if problems:
            hits.append({"User": email, "Problem": ", ".join(problems)})
    if not hits:
        return []
    return [Finding(
        "weak-user-passwords", "MEDIUM",
        f"{len(hits)} account(s) with a weak or too-short password",
        "Google rates these passwords weak, or shorter than the tenant's own "
        "minimum (a policy raised after the password was set does not "
        "change existing passwords unless enforced at next sign-in). These "
        "are the accounts credential-stuffing finds first.",
        "Tick enforce password policy at next sign-in, and have these users "
        "change their password; 2-step verification limits the damage in "
        "the meantime.",
        hits, "report_users.csv")]


def check_admin_second_factors(ctx: RunContext) -> List[Finding]:
    """Security keys and passkeys held by each super admin, from the usage
    report. Shows how strong the second step on the most powerful accounts
    actually is; the 2SV checks only say whether one exists."""
    if not (_module_usable(ctx, "report_users") and _module_usable(ctx, "users")):
        return []
    report = {col(r, "email", "userEmail").lower(): r
              for r in ctx.rows("report_users")}
    rows = []
    for admin in _super_admins(ctx):
        email = col(admin, "primaryEmail")
        rep = report.get(email.lower())
        if rep is None:
            continue
        rows.append({"Super admin": email,
                     "Security keys": col(rep, "accounts:num_security_keys") or "0",
                     "Passkeys": col(rep, "accounts:num_passkeys_enrolled") or "0",
                     "2SV enrolled": col(admin, "isEnrolledIn2Sv")})
    if not rows:
        return []
    # Admins with no 2SV at all have their own CRITICAL finding; this one is
    # for those whose second step exists but can be phished.
    weak = [{"Super admin": r["Super admin"]} for r in rows
            if truthy(r["2SV enrolled"])
            and r["Security keys"] in ("", "0") and r["Passkeys"] in ("", "0")]
    findings = []
    if weak:
        findings.append(Finding(
            "admins-not-phish-resistant", "MEDIUM",
            "Super admins without a security key or passkey",
            "These super admins use 2-step verification, but only with codes "
            "or prompts. Those stop a stolen password on its own, not a "
            "phishing page that relays the code and takes the session. "
            "Security keys and passkeys cannot be relayed that way. "
            "Usage-report figures lag about two days.",
            "Give every super admin a passkey or security key (two, so one "
            "can be lost), then require security keys for the admin "
            "organisational unit under Security > 2-step verification.",
            weak, "report_users.csv"))
    return findings + [Finding(
        "admin-second-factors", "INFO",
        "Second factors held by each super admin",
        "Security keys and passkeys cannot be phished; codes from an app or "
        "a text message can. A super admin with zero of either is relying "
        "on the weaker methods. Usage-report figures lag about two days.",
        "Issue at least two security keys or passkeys to every super admin "
        "and enforce a phishing-resistant method for the admin "
        "organisational unit.",
        rows, "report_users.csv", count=len(rows))]


def education_skus_held(ctx: RunContext) -> List[str]:
    """Display names of the Education SKUs in licenses.csv, empty on a
    business tenant. Gates everything Classroom so a company is never shown
    school settings.

    Reads the module status directly rather than through _module_usable:
    a business tenant passing this gate must not put the Classroom checks
    on the checked-and-clean list, they did not apply."""
    if ctx.module_status("licenses") not in ("ok", "empty", "partial"):
        return []
    edu = {_SKU_EDU_FUND} | _SKU_EDU_STD | _SKU_EDU_PLUS
    names = {}
    for row in ctx.rows("licenses"):
        sku = col(row, "skuId")
        if sku in edu:
            names[sku] = col(row, "skuDisplay") or sku
    return sorted(names.values())


# Classroom policy types (all seven seen in the 2026-08-15 dev export) and
# the one field per type that matters to a school's security posture.
CLASSROOM_SETTINGS = {
    "classroom.class_membership": "whoCanJoinClasses",
    "classroom.teacher_permissions": "whoCanCreateClasses",
    "classroom.guardian_access": "allowAccess",
    "classroom.api_data_access": "enableApiAccess",
    "classroom.roster_import": "rosterImportOption",
    "classroom.student_unenrollment": "whoCanUnenrollStudents",
    "classroom.originality_reports": "enableOriginalityReportsSchoolMatches",
}


CLASSROOM_TEACHERS_LOCAL = "classroom_teachers"


def _classroom_teachers_count(ctx: RunContext) -> str:
    """Member count of the group Classroom keeps its teachers in, or
    "not read" when groups.csv is missing or has no such group, so a gap
    never prints as 0."""
    if ctx.module_status("groups") not in ("ok", "empty", "partial"):
        return "not read"
    for g in ctx.rows("groups"):
        if col(g, "email").lower().startswith(CLASSROOM_TEACHERS_LOCAL + "@"):
            return col(g, "directMembersCount") or "not read"
    return "no such group"


def check_classroom_settings(ctx: RunContext) -> List[Finding]:
    """Classroom settings, education tenants only. Two values are judged:
    anyone (not just the domain) able to join classes, and anyone in the
    domain able to create them. Every other value is shown raw, because
    the console option behind each enum has only been read back for the
    dev tenant's defaults."""
    editions = education_skus_held(ctx)
    if not editions:
        return []
    rows, open_bits = [], []
    for pol in _policy_settings(ctx):
        field = CLASSROOM_SETTINGS.get(pol["type"])
        if not field:
            continue
        value = str(pol["value"].get(field, "?"))
        ou = pol["ou"] or "/"
        rows.append({"Setting": pol["type"].split(".", 1)[1],
                     "Org unit": ou, field: value,
                     "Value (raw)": json.dumps(pol["value"], sort_keys=True)})
        if field == "whoCanJoinClasses" and value.upper() == "ANYONE":
            open_bits.append({"Org unit": ou,
                              "Setting": "Anyone with a Google Account can "
                                         "join classes"})
        if field == "whoCanCreateClasses" and value.upper() in (
                "ANYONE", "ANYONE_IN_DOMAIN"):
            open_bits.append({"Org unit": ou,
                              "Setting": "Anyone in the domain can create "
                                         "classes, students included"})
        # Google: users pick teacher or student at their first Classroom
        # sign-in, and a self-declared teacher is a PENDING member of the
        # Classroom Teachers group (support.google.com/edu/classroom/answer/
        # 6071551, read 2026-10-01). This option lets them create classes
        # before an admin has verified anyone.
        if field == "whoCanCreateClasses" and \
                value.upper() == "ALL_PENDING_AND_VERIFIED_TEACHERS":
            open_bits.append({"Org unit": ou,
                              "Setting": "Anyone who says they are a teacher "
                                         "can create classes before an admin "
                                         "verifies them (Classroom Teachers "
                                         f"group members: {_classroom_teachers_count(ctx)})"})
    findings = []
    if open_bits:
        findings.append(Finding(
            "classroom-open", "MEDIUM",
            "Classroom lets anyone join or create classes",
            "Classes can be joined from outside the school, or created by any "
            "account in the domain including students. Either one lets "
            "someone outside the teaching staff see or run a class roster.",
            "In Admin console > Apps > Google Workspace > Classroom, limit "
            "class membership to the domain (or allowlisted domains) and "
            "class creation to verified teachers.",
            open_bits, "policies.csv"))
    if rows:
        findings.append(Finding(
            "classroom-settings", "INFO",
            f"Google Classroom settings ({', '.join(editions)})",
            "Classroom settings as the API reports them, shown because the "
            "tenant holds an Education licence. Guardian access, API data "
            "access and roster import each decide who outside the classroom "
            "sees student data.",
            "Review each against school policy; guardian access and API "
            "access are the two that expose student data outside Classroom.",
            rows, "policies.csv", count=len(rows)))
    return findings


def check_courses(ctx: RunContext) -> List[Finding]:
    """Course counts by state, and courses whose owner is deleted or
    suspended: a leaver's classes, Classroom folder and student work with
    nobody accountable for them."""
    if not _module_usable(ctx, "courses"):
        return []
    rows = ctx.rows("courses")
    if not rows:
        return []
    states: Dict[str, int] = {}
    for row in rows:
        state = col(row, "courseState") or "unknown"
        states[state] = states.get(state, 0) + 1
    evidence = [{"State": s, "Courses": str(n)}
                for s, n in sorted(states.items(), key=lambda kv: -kv[1])]
    findings = [Finding(
        "classroom-courses", "INFO",
        f"{len(rows)} Classroom course(s)",
        "Every course in the tenant, counted by state. Active courses are "
        "live rosters of students; archived ones keep their data and their "
        "members until deleted.",
        "Archive courses that have ended, and delete archived ones once the "
        "retention period has passed.",
        evidence, "courses.csv", count=len(rows))]
    # A courses.csv collected without `owneremail` has no such column, and
    # reading its absence as "owner deleted" would flag every course.
    if not any(k.lower() == "owneremail" for k in rows[0]):
        return findings
    users = ({col(u, "primaryEmail").lower(): u for u in ctx.rows("users")}
             if _module_usable(ctx, "users") else {})
    orphaned = []
    for row in rows:
        owner = col(row, "ownerEmail")
        # GAM writes "Unknown user" when the owner account no longer exists
        # (Classroom-Courses wiki, owneremailmatchpattern); not yet seen live.
        if not owner or owner.lower() == "unknown user":
            problem = "Owner account deleted"
        elif truthy(col(users.get(owner.lower(), {}), "suspended")):
            problem = "Owner suspended"
        else:
            continue
        orphaned.append({"Course": col(row, "name"),
                         "State": col(row, "courseState"),
                         "Owner": owner or "-", "Problem": problem})
    if orphaned:
        findings.append(Finding(
            "classroom-orphaned-courses", "MEDIUM",
            "Classes owned by deleted or suspended accounts",
            "The owner of these classes has left or been suspended. Their "
            "students, coursework and the class Drive folder stay in place "
            "with no active teacher accountable for them.",
            "Transfer each class to a current teacher (the new owner must be "
            "a co-teacher first), or archive it. Make Classroom ownership "
            "part of the leaver process.",
            orphaned, "courses.csv"))
    return findings


def check_classroom_outsiders(ctx: RunContext) -> List[Finding]:
    """Teachers or students from outside the organisation on a class roster,
    or invited to one. Either can see the class's students and their work."""
    internal = {d.lower() for d in ctx.internal_domains}
    if not internal:
        return []
    hits, unnamed = [], 0
    if _module_usable(ctx, "course_participants"):
        for row in ctx.rows("course_participants"):
            email = col(row, "profile.emailAddress", "emailAddress")
            if not email:
                unnamed += 1
            elif email_domain(email) not in internal:
                hits.append({"Course": col(row, "courseName"),
                             "Role": col(row, "userRole").lower(),
                             "Member": email, "Status": "on the roster"})
    if _module_usable(ctx, "classroominvitations"):
        for row in ctx.rows("classroominvitations"):
            email = col(row, "userEmail")
            if not email:
                unnamed += 1
            elif email_domain(email) not in internal:
                hits.append({"Course": col(row, "courseName"),
                             "Role": col(row, "role").lower(),
                             "Member": email, "Status": "invited"})
    if not hits:
        return []
    meaning = ("These people are outside the organisation but are teachers "
               "or students in a class, or have been invited to be. A class "
               "member sees the roster and, as a teacher, every student's "
               "work and grades.")
    if unnamed:
        # The API returned no address for these, so they were not judged.
        meaning += (f" {unnamed} roster or invitation row(s) carried no email "
                    "address and could not be checked.")
    return [Finding(
        "classroom-external-members", "HIGH",
        "Classes with members from outside the organisation",
        meaning,
        "Confirm each one is meant to be there; remove the rest. Then set "
        "Admin console > Apps > Google Workspace > Classroom > Class settings "
        "so users can only join classes in the domain (or allowlisted "
        "domains).",
        hits, "course_participants.csv")]


GUARDIAN_INVITE_STALE_DAYS = 30


def check_classroom_guardians(ctx: RunContext) -> List[Finding]:
    """Guardians who receive student summaries, and pending guardian
    invitations. The audit cannot tell a real parent from anyone else, so
    this is a list for the school to review. A pending invitation is a link
    Google's own email says anyone holding it may be able to accept, so the
    old ones are called out."""
    if not _module_usable(ctx, "guardians"):
        return []
    rows = ctx.rows("guardians")
    if not rows:
        return []
    now = datetime.now(timezone.utc)
    evidence, accepted, pending, stale = [], 0, 0, 0
    for row in rows:
        # col() stops at the first column present even when it is empty, and
        # both columns are present on every row, so fall back explicitly.
        guardian = (col(row, "guardianProfile.emailAddress")
                    or col(row, "invitedEmailAddress"))
        # Accepted rows carry a guardianId and no invitation state; pending
        # rows the reverse (seen live 2026-10-01).
        if col(row, "guardianId"):
            accepted += 1
            evidence.append({"Student": col(row, "studentEmail"),
                             "Guardian": guardian, "Status": "accepted",
                             "Age (days)": "-"})
            continue
        pending += 1
        age = "-"
        try:
            stamp = datetime.fromisoformat(
                col(row, "creationTime").replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            days = (now - stamp).days
            age = str(days)
            if days >= GUARDIAN_INVITE_STALE_DAYS:
                stale += 1
        except ValueError:
            pass
        evidence.append({"Student": col(row, "studentEmail"),
                         "Guardian": guardian,
                         "Status": col(row, "state").lower() or "pending",
                         "Age (days)": age})
    title = (f"{accepted} guardian(s) receive student summaries, "
             f"{pending} invitation(s) pending")
    if stale:
        title += f" ({stale} older than {GUARDIAN_INVITE_STALE_DAYS} days)"
    return [Finding(
        "classroom-guardians", "INFO", title,
        "Guardians are outside the organisation and get email summaries of a "
        "student's upcoming and missing work. The audit cannot tell whether "
        "each address belongs to the right parent. A pending invitation can "
        "be accepted by anyone the email is forwarded to.",
        "Check each guardian against the school's records. Cancel pending "
        f"invitations older than {GUARDIAN_INVITE_STALE_DAYS} days and "
        "re-invite if still wanted.",
        evidence, "guardians.csv")]


def check_tenant_shape(ctx: RunContext) -> List[Finding]:
    """The INFO scorecard: tenant shape at a glance."""
    facts = []
    if _module_usable(ctx, "users"):
        rows = ctx.rows("users")
        active = [r for r in rows if not truthy(col(r, "suspended"))]
        facts.append({"Fact": "Users",
                      "Value": f"{len(active)} active, "
                               f"{len(rows) - len(active)} suspended"})
        facts.append({"Fact": "Super admins",
                      "Value": str(len(_super_admins(ctx)))})
    if _module_usable(ctx, "orgs"):
        facts.append({"Fact": "Organisational units (below root)",
                      "Value": str(len(ctx.rows("orgs")))})
    if _module_usable(ctx, "licenses"):
        facts.append({"Fact": "Licence assignments",
                      "Value": str(len(ctx.rows("licenses")))})
    if _module_usable(ctx, "groups"):
        facts.append({"Fact": "Groups", "Value": str(len(ctx.rows("groups")))})
    if _module_usable(ctx, "shareddrives"):
        facts.append({"Fact": "Shared Drives",
                      "Value": str(len(ctx.rows("shareddrives")))})
    if _module_usable(ctx, "mobile"):
        facts.append({"Fact": "Mobile devices",
                      "Value": str(len(ctx.rows("mobile")))})
    if _module_usable(ctx, "cros"):
        facts.append({"Fact": "ChromeOS devices",
                      "Value": str(len(ctx.rows("cros")))})
    if _module_usable(ctx, "sites"):
        facts.append({"Fact": "Google Sites",
                      "Value": str(len(ctx.rows("sites")))})
    if _module_usable(ctx, "vaultmatters"):
        facts.append({"Fact": "Vault matters",
                      "Value": str(len(ctx.rows("vaultmatters")))})
    if _module_usable(ctx, "vaultholds"):
        facts.append({"Fact": "Vault holds",
                      "Value": str(len(ctx.rows("vaultholds")))})
    if _module_usable(ctx, "datatransfers"):
        facts.append({"Fact": "Data transfers on record",
                      "Value": str(len(ctx.rows("datatransfers")))})
    if _module_usable(ctx, "ssoprofiles"):
        count = len(ctx.rows("ssoprofiles"))
        facts.append({"Fact": "Inbound SSO profiles",
                      "Value": str(count) if count else "none"})
    if not facts:
        return []
    return [Finding(
        "tenant-shape", "INFO", "Tenant at a glance",
        "The headline numbers for this tenant, from the collected data. "
        "Usage-report figures (storage per user) lag about two days behind "
        "live state.",
        "No action needed. This is context for the findings above.",
        facts, "multiple", count=len(facts))]


def _policy_settings(ctx: RunContext) -> List[Dict]:
    if ctx._policy_cache is not None:
        # Cache hit still counts as consulting the module, or a policy check
        # that found nothing would be missing from the checked-and-clean list.
        _module_usable(ctx, "policies")
        return ctx._policy_cache
    return _parse_policy_settings(ctx)


def _parse_policy_settings(ctx: RunContext) -> List[Dict]:
    """Parse policies.csv (formatjson: name,JSON) and return the RESOLVED
    settings as a list of {"type", "ou", "value"} dicts, "settings/"
    stripped.

    The Policy API returns every policy that could apply to a target, not
    the one that wins: Google's own defaults (type SYSTEM) sit alongside
    what the administrator set (type ADMIN), plus a licence-scoped copy per
    SKU. A tenant whose admin raised the password minimum still shows the
    SYSTEM default of 8 in its own row, so reading the rows as-is reports a
    weak policy that is not in force.

    Google resolves them with the Max/Merge reducer: for each field, the
    value from the policy with the greatest policyQuery.sortOrder wins
    (docs.cloud.google.com/identity/docs/concepts/policy-api-concepts).
    Admin policies carry a higher sortOrder than system ones (measured on
    a test tenant: an admin-set security.password at 201.00332 against
    three system rows at 101.000x), so merging the values of a
    (setting, OU) group in ascending sortOrder yields the setting actually
    in force.

    Licence filtering is not modelled - a policy scoped to one
    SKU is treated as applying to the whole OU. Where two SKUs in the same
    OU genuinely differ, the higher sortOrder wins and the divergence is
    invisible. Per-user resolution would need each user's licences.

    rule.* rows (DLP rules, system-defined alerts) are lists of rules, not
    reducible settings, so they keep one entry each.

    gam renders a quote inside a policy display name as \\\\" which is invalid
    JSON once the CSV layer has decoded it (seen on DLP rule names); one
    targeted repair recovers those rows, and rows that still fail to parse
    are skipped - on the dev tenant every such row is a rule.dlp or
    system-defined alert, not a settings policy.
    """
    if not _module_usable(ctx, "policies"):
        return []
    rules: List[Dict] = []
    groups: Dict[tuple, List[tuple]] = {}
    seen = set()
    for row in ctx.rows("policies"):
        raw = col(row, "JSON")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            try:
                data = json.loads(raw.replace('\\\\"', '\\"'))
            except json.JSONDecodeError:
                continue
        setting = data.get("setting") or {}
        stype = str(setting.get("type", ""))
        if stype.startswith("settings/"):
            stype = stype[len("settings/"):]
        if not stype:
            continue
        value = setting.get("value") or {}
        query = data.get("policyQuery") or {}
        ou = str(query.get("orgUnitPath", ""))
        if stype.startswith("rule."):
            key = (stype, ou, json.dumps(value, sort_keys=True))
            if key not in seen:
                seen.add(key)
                rules.append({"type": stype, "ou": ou, "value": value})
            continue
        try:
            order = float(query.get("sortOrder", 0))
        except (TypeError, ValueError):
            order = 0.0
        groups.setdefault((stype, ou), []).append((order, value))
    out: List[Dict] = []
    for (stype, ou), entries in groups.items():
        resolved: Dict = {}
        for _, value in sorted(entries, key=lambda e: e[0]):
            if isinstance(value, dict):
                resolved.update(value)
        out.append({"type": stype, "ou": ou, "value": resolved})
    _apply_policy_defaults(out, bool(education_skus_held(ctx)))
    out.extend(rules)
    ctx._policy_cache = out
    return out


def _apply_policy_defaults(settings: List[Dict], education: bool = False):
    """Fill in Google's documented defaults at the root org unit.

    The Policy API does not return a setting, or a field of one, that was
    never changed from Google's default. Without this, a tenant that left
    automatic forwarding or Drive publishing at their default (allowed) was
    never judged on them. Only the root is filled: a child org unit without
    its own row inherits the root's value. Each filled field is recorded in
    "defaulted" so the report can say the value is Google's default."""
    try:
        defaults = json.loads(POLICY_DEFAULTS_FILE.read_text(
            encoding="utf-8")).get("defaults", {})
    except (OSError, json.JSONDecodeError):
        return
    root = {s["type"]: s for s in settings if s["ou"] == "/"}
    if not education:
        # Google: "For K12 customers: ALLOW_NONE, otherwise: ALLOW_ALL". A
        # business tenant is never K12; on an Education tenant the audit
        # cannot tell a school from a university, so it stays unknown.
        defaults = dict(defaults)
        defaults["workspace_marketplace.apps_access_options"] = dict(
            defaults.get("workspace_marketplace.apps_access_options", {}),
            accessLevel="ALLOW_ALL")
    for stype, fields in defaults.items():
        entry = root.get(stype)
        if entry is None:
            entry = {"type": stype, "ou": "/", "value": {}}
            settings.append(entry)
        for field, value in fields.items():
            if field not in entry["value"]:
                entry["value"][field] = value
                entry.setdefault("defaulted", []).append(field)


# Settings checked against the CISA SCuBA Google Workspace baselines, using
# the rules of CISA's ScubaGoggles (v1.0.1, public domain) as the guide for
# what counts as passing. Severity is set for small and medium businesses,
# not US federal agencies, and requirements that only make sense for a
# federal agency are left out. (setting, field, fails(value, whole setting),
# severity, plain-English label, CISA requirement)
_SAFE_CONSEQUENCES = ("SPAM_FOLDER", "QUARANTINE")
_ATTACHMENT_CONSEQUENCES = {
    "enableEncryptedAttachmentProtection": "encryptedAttachmentProtectionConsequence",
    "enableAttachmentWithScriptsProtection": "attachmentWithScriptsProtectionConsequence",
    "enableAnomalousAttachmentProtection": "anomalousAttachmentProtectionConsequence",
}
_SPOOFING_CONSEQUENCES = {
    "detectDomainNameSpoofing": "domainNameSpoofingConsequence",
    "detectEmployeeNameSpoofing": "employeeNameSpoofingConsequence",
    "detectDomainSpoofingFromUnauthenticatedSenders": "domainSpoofingConsequence",
    "detectUnauthenticatedEmails": "unauthenticatedEmailConsequence",
    "detectGroupsSpoofing": "groupsSpoofingConsequence",
}


def _kept_in_inbox(value: Dict, pairs: Dict[str, str]) -> List[str]:
    """Protections that are on but only warn, leaving the mail in the inbox."""
    return [cons for flag, cons in pairs.items()
            if value.get(flag) is True and cons in value
            and value[cons] not in _SAFE_CONSEQUENCES]


POLICY_BASELINE = [
    ("gmail.auto_forwarding", "enableAutoForwarding",
     lambda v, s: v is True, "MEDIUM",
     "Users can set up automatic forwarding to outside addresses",
     "GWS.GMAIL.11.1"),
    ("security.two_step_verification_device_trust", "allowTrustingDevice",
     lambda v, s: v is True, "MEDIUM",
     "Users can skip 2-step verification on a device they mark as trusted",
     "GWS.COMMONCONTROLS.1.5"),
    ("api_controls.internal_apps", "trustInternalApps",
     lambda v, s: v is True, "MEDIUM",
     "Apps built inside the organisation are trusted without review",
     "GWS.COMMONCONTROLS.10.3"),
    ("workspace_marketplace.apps_access_options", "accessLevel",
     lambda v, s: v == "ALLOW_ALL", "MEDIUM",
     "Users can install any Google Workspace Marketplace app",
     "GWS.COMMONCONTROLS.11.1"),
    ("security.less_secure_apps", "allowLessSecureApps",
     lambda v, s: v is True, "MEDIUM",
     "Less secure apps (password-only sign-in) are allowed",
     "GWS.COMMONCONTROLS.10.5"),
    ("drive_and_docs.external_sharing", "allowPublishingFiles",
     lambda v, s: v is True and s.get("externalSharingMode") != "DISALLOWED",
     "MEDIUM", "Users can publish Drive files to the web",
     "GWS.DRIVEDOCS.1.5"),
    ("drive_and_docs.external_sharing", "accessCheckerSuggestions",
     lambda v, s: v == "RECIPIENTS_OR_AUDIENCE_OR_PUBLIC", "MEDIUM",
     "Drive suggests making a file public when sharing it",
     "GWS.DRIVEDOCS.1.6"),
    ("drive_and_docs.general_access_default", "defaultFileAccess",
     lambda v, s: str(v).startswith("PRIMARY_AUDIENCE"), "MEDIUM",
     "New files are open to the whole organisation by default",
     "GWS.DRIVEDOCS.1.8"),
    ("gmail.email_attachment_safety", "attachment protections",
     lambda v, s: bool(_kept_in_inbox(s, _ATTACHMENT_CONSEQUENCES)), "MEDIUM",
     "Risky attachments are flagged but left in the inbox",
     "GWS.GMAIL.5.5"),
    ("gmail.spoofing_and_authentication", "spoofing protections",
     lambda v, s: bool(_kept_in_inbox(s, _SPOOFING_CONSEQUENCES)), "MEDIUM",
     "Spoofed and unauthenticated mail is flagged but left in the inbox",
     "GWS.GMAIL.7.6"),
    ("groups_for_business.groups_sharing", "createGroupsAccessLevel",
     lambda v, s: v == "ANYONE_CAN_CREATE", "MEDIUM",
     "Anyone, including people outside the organisation, can create groups",
     "GWS.GROUPS.2.1"),
    ("drive_and_docs.external_sharing", "allowNonGoogleInvites",
     lambda v, s: v is True and s.get("externalSharingMode") == "ALLOWED",
     "INFO", "Files can be shared with people who have no Google account",
     "GWS.DRIVEDOCS.1.4"),
    ("drive_and_docs.file_security_update", "securityUpdate",
     lambda v, s: v != "APPLY_TO_IMPACTED_FILES"
     or s.get("allowUsersToManageUpdate") is not False, "INFO",
     "Users can opt files out of Drive's link security update",
     "GWS.DRIVEDOCS.3.1"),
    ("drive_and_docs.drive_sdk", "enableDriveSdkApiAccess",
     lambda v, s: v is True, "INFO",
     "Third-party apps can use the Drive SDK to reach users' files",
     "GWS.DRIVEDOCS.4.1"),
    ("groups_for_business.groups_sharing", "createGroupsAccessLevel",
     lambda v, s: v == "USERS_IN_DOMAIN", "INFO",
     "Every user can create groups, not only admins", "GWS.GROUPS.2.1"),
    ("groups_for_business.groups_sharing",
     "ownersCanAllowIncomingMailFromPublic",
     lambda v, s: v is True, "INFO",
     "Group owners can let anyone on the internet post to their group",
     "GWS.GROUPS.1.3"),
    ("calendar.secondary_calendar_max_allowed_external_sharing",
     "maxAllowedExternalSharing",
     lambda v, s: v != "EXTERNAL_FREE_BUSY_ONLY", "INFO",
     "Secondary calendars can show event details to outside people",
     "GWS.CALENDAR.1.2"),
    ("chat.chat_file_sharing", "externalFileSharing",
     lambda v, s: v not in (None, "NO_FILES"), "INFO",
     "Files can be shared in Chat with outside people",
     "GWS.CHAT.2.1"),
    ("gmail.workspace_sync_for_outlook",
     "enableGoogleWorkspaceSyncForMicrosoftOutlook",
     lambda v, s: v is True, "INFO",
     "Google Workspace Sync for Outlook is allowed", "GWS.GMAIL.10.1"),
]


def check_policy_baseline(ctx: RunContext) -> List[Finding]:
    """Tenant settings below the CISA Google Workspace baselines, one row per
    setting and org unit, saying whether the value is Google's default (the
    tenant never changed it) or was set by an admin."""
    by_type: Dict[str, List[Dict]] = {}
    for pol in _policy_settings(ctx):
        by_type.setdefault(pol["type"], []).append(pol)
    rows: Dict[str, List[Dict[str, str]]] = {"MEDIUM": [], "INFO": []}
    for stype, field, fails, sev, label, ref in POLICY_BASELINE:
        for pol in by_type.get(stype, []):
            value = pol["value"]
            current = value.get(field)
            if field in value or " " in field:
                if not fails(current, value):
                    continue
            else:
                continue
            shown = current if current is not None else ", ".join(
                _kept_in_inbox(value, _ATTACHMENT_CONSEQUENCES
                               if "attachment" in field
                               else _SPOOFING_CONSEQUENCES))
            rows[sev].append({
                "Setting": label, "Org unit": pol["ou"] or "/",
                "Value": str(shown),
                "Set by": "Google default" if field in pol.get(
                    "defaulted", []) else "admin",
                "CISA baseline": ref})
    findings = []
    if rows["MEDIUM"]:
        findings.append(Finding(
            "policy-baseline", "MEDIUM",
            "Settings below the CISA Google Workspace baseline",
            "These tenant settings are looser than the CISA (US Cybersecurity "
            "and Infrastructure Security Agency) baseline for Google "
            "Workspace. Each one widens what a phished account or a careless "
            "click can do. \"Google default\" means nobody has changed it.",
            "Review each in the Admin console and tighten it unless the "
            "organisation relies on it; the baseline reference names the "
            "requirement.", rows["MEDIUM"], "policies.csv"))
    if rows["INFO"]:
        findings.append(Finding(
            "policy-baseline-info", "INFO",
            "Other settings the CISA baseline would tighten",
            "Lower-risk settings the CISA baseline recommends changing. Most "
            "organisations leave some of these on deliberately.",
            "Decide on each and record the reason for any left as they are.",
            rows["INFO"], "policies.csv"))
    return findings


def check_password_policy(ctx: RunContext) -> List[Finding]:
    hits = []
    for pol in _policy_settings(ctx):
        if pol["type"] != "security.password":
            continue
        value = pol["value"]
        problems = []
        minlen = value.get("minimumLength")
        if isinstance(minlen, int) and minlen < PASSWORD_MIN_LENGTH:
            problems.append(f"minimum length is {minlen} characters")
        strength = str(value.get("allowedStrength", "")).upper()
        if strength and strength != "STRONG":
            problems.append("weak passwords are allowed")
        if value.get("allowReuse") is True:
            problems.append("password reuse is allowed")
        if value.get("enforceRequirementsAtLogin") is False:
            problems.append("existing passwords are not checked against the "
                            "policy at next sign-in")
        expiry = _duration_seconds(value.get("expirationDuration", ""))
        if expiry:
            problems.append(f"passwords expire every {expiry // 86400} days")
        if problems:
            hits.append({"Org unit": pol["ou"] or "/",
                         "Problem": ", ".join(problems)})
    if not hits:
        return []
    return [Finding(
        "password-policy-weak", "MEDIUM",
        "Password policy permits weak passwords",
        f"The tenant's password rules fall short of current practice (a "
        f"minimum of {PASSWORD_MIN_LENGTH} characters, strong passwords "
        "only, no reuse, checked at next sign-in, no forced expiry). Short or "
        "reused passwords are the ones that fall to guessing and to "
        "credential lists from other sites' breaches, and forced expiry "
        "pushes people towards predictable ones.",
        "Raise the minimum length, disallow reuse, tick enforce password "
        "policy at next sign-in and set passwords to never expire in Admin "
        "console > Security > Authentication > Password management. Pair "
        "this with 2-step verification rather than a forced reset.",
        hits, "policies.csv")]


def _duration_seconds(value: str) -> Optional[int]:
    """Policy durations arrive as strings like \"1209600s\"."""
    match = re.fullmatch(r"(\d+)s", str(value).strip())
    return int(match.group(1)) if match else None


def check_session_policy(ctx: RunContext) -> List[Finding]:
    hits = []
    for pol in _policy_settings(ctx):
        if pol["type"] != "security.session_controls":
            continue
        seconds = _duration_seconds(pol["value"].get("webSessionDuration"))
        if seconds is not None and seconds > SESSION_MAX_SECONDS:
            hits.append({"Org unit": pol["ou"] or "/",
                         "Session length": f"{seconds // 86400} days"})
    if not hits:
        return []
    return [Finding(
        "session-length", "MEDIUM",
        "Web sessions last longer than Google's 14-day default",
        "Signed-in browser sessions stay valid for longer than two weeks. "
        "The longer a session lives, the longer a stolen laptop or hijacked "
        "browser keeps working without ever seeing a password or 2-step "
        "prompt.",
        "Shorten the web session duration in Admin console > Security > "
        "Access and data control > Google session control.",
        hits, "policies.csv")]


def check_2sv_policy(ctx: RunContext) -> List[Finding]:
    """Per-OU 2SV policy. The one clear-cut signal verified on dev is
    allowEnrollment=false - users in that OU cannot switch 2SV on at all.
    Enforcement semantics (what enforcedFrom means when set to epoch) are
    NOT yet verified against a console fixture, so enforcement rows are
    reported as an INFO map rather than judged."""
    blocked, map_rows = [], []
    for pol in _policy_settings(ctx):
        if not pol["type"].startswith("security.two_step_verification"):
            continue
        setting = pol["type"].split(".", 1)[1]
        map_rows.append({"Setting": setting,
                         "Org unit": pol["ou"] or "/",
                         "Value": json.dumps(pol["value"], sort_keys=True)})
        if (setting == "two_step_verification_enrollment"
                and pol["value"].get("allowEnrollment") is False):
            blocked.append({"Org unit": pol["ou"] or "/"})
    findings = []
    if blocked:
        findings.append(Finding(
            "2sv-enrolment-blocked", "HIGH",
            "Organisational units where 2-step verification cannot be "
            "enrolled",
            "Policy in these organisational units stops users from turning "
            "on 2-step verification at all. Every account there is limited "
            "to password-only sign-in by design, whatever the users want.",
            "Allow 2-step verification enrolment for these organisational "
            "units in Admin console > Security > Authentication > 2-step "
            "verification, unless the OU exists precisely to hold such "
            "accounts and that trade-off is documented.",
            blocked, "policies.csv"))
    if map_rows:
        findings.append(Finding(
            "2sv-policy-map", "INFO",
            "2-step verification policy by organisational unit",
            "The tenant's 2-step verification policy settings as the API "
            "reports them, per organisational unit. Rows only appear where "
            "a policy is set.",
            "No action needed; check the enforcement rows match what the "
            "Admin console shows.",
            map_rows, "policies.csv"))
    return findings


def check_sharing_policy(ctx: RunContext) -> List[Finding]:
    hits = []
    for pol in _policy_settings(ctx):
        if pol["type"] != "drive_and_docs.shared_drive_creation":
            continue
        value = pol["value"]
        open_bits = []
        if value.get("allowExternalUserAccess") is True:
            open_bits.append("external people can be members")
        if value.get("allowNonMemberAccess") is True:
            open_bits.append("files can be shared to non-members")
        if open_bits:
            hits.append({"Org unit": pol["ou"] or "/",
                         "New shared drives default": ", ".join(open_bits)})
    if not hits:
        return []
    return [Finding(
        "sd-default-external", "MEDIUM",
        "New Shared Drives allow external sharing by default",
        "Tenant policy lets newly created Shared Drives take external "
        "members and share files beyond their membership. A tenant with no "
        "badly shared files today still scores clean while every future "
        "drive starts open - this is the default the next mistake inherits.",
        "In Admin console > Apps > Google Workspace > Drive and Docs > "
        "Shared drive settings, untick external and non-member access as "
        "the default; deliberately client-facing drives can be opened "
        "per drive.",
        hits, "policies.csv")]


def check_service_status(ctx: RunContext) -> List[Finding]:
    enabled, disabled = 0, []
    for pol in _policy_settings(ctx):
        if not pol["type"].endswith(".service_status"):
            continue
        service = pol["type"].rsplit(".", 1)[0]
        state = str(pol["value"].get("serviceState", ""))
        if state.upper() == "ENABLED":
            enabled += 1
        else:
            disabled.append({"Service": service, "State": state or "?",
                             "Org unit": pol["ou"] or "/"})
    if not enabled and not disabled:
        return []
    return [Finding(
        "service-status", "INFO",
        f"Google services: {enabled} enabled, {len(disabled)} disabled",
        "Which Google services the tenant switches on or off. Most tenants "
        "leave consumer services (Blogger, Photos, YouTube, Takeout) at "
        "their default of enabled without ever deciding to.",
        "No action needed. Worth a deliberate pass: services nobody uses "
        "are attack surface and data-export paths (Takeout in particular) "
        "that cost nothing to turn off.",
        disabled, "policies.csv", count=len(disabled))]


def check_super_admin_self_recovery(ctx: RunContext) -> List[Finding]:
    """Super admin self-recovery ON. Google's admin best-practices page says
    it is off for most new customers but on by default for existing ones
    with fewer than 3 super admins or 500 users, so older small tenants
    usually carry it without anyone choosing it."""
    hits = [{"Org unit": pol["ou"] or "/"}
            for pol in _policy_settings(ctx)
            if pol["type"] == "security.super_admin_account_recovery"
            and pol["value"].get("enableAccountRecovery") is True]
    if not hits:
        return []
    return [Finding(
        "super-admin-self-recovery", "MEDIUM",
        "Super admins can reset their own password by phone or email",
        "Super admin accounts can recover themselves through their recovery "
        "phone or email. Whoever controls that phone number or mailbox can "
        "take over the account with the most power in the tenant, without "
        "another admin being involved.",
        "Turn off super admin account recovery in Admin console > Security > "
        "Authentication > Account recovery, and make sure a second super "
        "admin exists to reset a locked-out one.",
        hits, "policies.csv")]


# Gmail Safety switches that Google's 100+ user security checklist says to
# turn on. Each maps a policy field to the console label it appears under.
# A switch counts as off only when the field is present and False, so a
# setting the API did not return is never reported as off.
GMAIL_PROTECTION_FIELDS = {
    "gmail.enhanced_pre_delivery_message_scanning": {
        "enableImprovedSuspiciousContentDetection":
            "Enhanced pre-delivery message scanning",
    },
    "gmail.email_attachment_safety": {
        "enableEncryptedAttachmentProtection":
            "Protect against encrypted attachments from untrusted senders",
        "enableAttachmentWithScriptsProtection":
            "Protect against attachment with scripts from untrusted senders",
        "enableAnomalousAttachmentProtection":
            "Protect against anomalous attachment types in emails",
        "applyFutureRecommendedSettingsAutomatically":
            "Attachments: apply future recommended settings automatically",
    },
    "gmail.links_and_external_images": {
        "enableShortenerScanning":
            "Identify links behind shortened URLs",
        "enableExternalImageScanning":
            "Scan linked images",
        "enableAggressiveWarningsOnUntrustedLinks":
            "Show warning prompt for any click on links to untrusted domains",
        "applyFutureSettingsAutomatically":
            "Links: apply future recommended settings automatically",
    },
    "gmail.spoofing_and_authentication": {
        "detectDomainNameSpoofing":
            "Protect against domain spoofing based on similar domain names",
        "detectEmployeeNameSpoofing":
            "Protect against spoofing of employee names",
        "detectDomainSpoofingFromUnauthenticatedSenders":
            "Protect against inbound emails spoofing your domain",
        "detectUnauthenticatedEmails":
            "Protect against any unauthenticated emails",
        "detectGroupsSpoofing":
            "Protect Groups from inbound emails spoofing your domain",
        "applyFutureSettingsAutomatically":
            "Spoofing: apply future recommended settings automatically",
    },
}


def check_gmail_protections(ctx: RunContext) -> List[Finding]:
    """Gmail Safety protections switched off, per OU. Google's own defaults
    leave several of these off, so a tenant nobody has hardened shows them
    here - that is the point of the check, not noise."""
    hits = []
    for pol in _policy_settings(ctx):
        labels = GMAIL_PROTECTION_FIELDS.get(pol["type"])
        if not labels:
            continue
        for field, label in labels.items():
            if pol["value"].get(field) is False:
                hits.append({"Org unit": pol["ou"] or "/", "Protection": label})
    if not hits:
        return []
    return [Finding(
        "gmail-protections-off", "MEDIUM",
        "Gmail phishing and malware protections switched off",
        "Gmail scans every message anyway, but these extra checks - for "
        "look-alike domains, spoofed staff names, unauthenticated mail, risky "
        "attachments and disguised links - are off. Several are off in "
        "Google's own defaults, so a tenant nobody has hardened lands here.",
        "Turn each one on in the Admin console under Gmail (the Safety "
        "settings, and the enhanced pre-delivery message scanning setting). "
        "The warning-banner action is a reasonable start on a domain with no "
        "mail history; tick apply future recommended settings too.",
        hits, "policies.csv")]


def check_external_chat(ctx: RunContext) -> List[Finding]:
    """External Chat on for every domain. INFO, not MEDIUM: most small
    businesses chat with clients, so this is a decision to make on purpose
    rather than a defect."""
    hits = [{"Org unit": pol["ou"] or "/"}
            for pol in _policy_settings(ctx)
            if pol["type"] == "chat.chat_external_spaces"
            and pol["value"].get("enabled") is True
            and pol["value"].get("domainAllowlistMode") == "ALL_DOMAINS"]
    if not hits:
        return []
    return [Finding(
        "chat-external-open", "INFO",
        "Google Chat spaces open to people at any outside domain",
        "Users can create or join Chat spaces with people outside the "
        "organisation, from any domain. An outsider added to a space sees "
        "its earlier conversation.",
        "Decide deliberately. Google's security checklist suggests allowing "
        "external Chat only for the people who need it, or only with "
        "allowlisted domains, in Admin console > Apps > Google Workspace > "
        "Google Chat > External Chat settings.",
        hits, "policies.csv", count=len(hits))]


# Checklist settings with no policy type in `gam print policies` (checked
# against a full dev-tenant export, 2026-09-14), so no read can judge them.
CONSOLE_ONLY_SETTINGS = [
    ("Gmail", "Automatic forwarding",
     "Off. The forwards section above shows who forwards today, not whether "
     "the door is open."),
    ("Gmail", "POP and IMAP access",
     "Off unless a named user or a migration needs it."),
    ("Gmail", "Bypass spam filters for internal "
     "senders", "Off."),
    ("Gmail", "Approved senders",
     "Require sender authentication; no whole domains."),
    ("Gmail", "External recipient warning", "On."),
    ("Drive and Docs", "Invitations to non-Google "
     "accounts", "Off: external collaborators sign in with a Google Account."),
    ("Groups for Business", "Group creation and outside "
     "access", "Admins create groups; groups private to the organisation."),
    ("Sites", "Sharing outside the organisation",
     "Off, or warn."),
    ("Drive and Docs", "Sharing outside the organisation",
     "On if needed, with \"visible to anyone with the link\" off and a "
     "warning when sharing outside the domain."),
    ("Drive and Docs", "General access default for new items",
     "Private to the owner."),
    ("Drive and Docs", "Access Checker", "Recipients only."),
    ("Calendar", "External sharing of primary calendars",
     "Free/busy only, with a warning when inviting outside guests."),
    ("Security > Alerts", "Who receives alert emails",
     "An address someone reads; the rule states above do not show this."),
    ("Account settings", "Super admin recovery details",
     "Account creation date, sign-up email, order number and user count "
     "recorded offline, and the registrar login to hand."),
    # No API lists any of the five below, and each one is a tenant-wide
    # access path that never shows in a per-user check.
    ("Security > API controls", "Domain-wide delegation clients",
     "Only service accounts the organisation knows, each with the narrowest "
     "scopes that work. A client here can read every mailbox and Drive "
     "without any user signing in. Grants made in the last 30 days are in "
     "the findings; older ones only show here."),
    ("Apps > Web and mobile apps", "SAML apps",
     "Only apps in use; each one is a sign-in path that inherits the "
     "Google session."),
    ("Apps > Google Workspace Marketplace apps", "Domain-installed apps",
     "Only apps someone can name; a domain install grants every user's "
     "data to the app."),
    ("Apps > LDAP", "Secure LDAP clients",
     "None unless a named system uses it; each client holds a certificate "
     "that authenticates users."),
    ("Gmail > Routing", "Routing, outbound gateway and content compliance "
     "rules",
     "No rule that copies or redirects mail to an outside host without a "
     "written reason; an outbound gateway means all mail leaves through "
     "someone else's server."),
]


def check_console_only_settings(ctx: RunContext) -> List[Finding]:
    """Lists the security-checklist settings this audit cannot read, so the
    report does not imply they were checked. Static, so it is not gated on
    any module: the list is true of every run."""
    rows = [{"Admin console app": page, "Setting": setting,
             "Recommended": advice}
            for page, setting, advice in CONSOLE_ONLY_SETTINGS]
    return [Finding(
        "console-only-settings", "INFO",
        "Security settings to check by hand in the Admin console",
        "Google's security checklist recommends these settings, but the API "
        "this audit reads does not expose them. Nothing in this report "
        "should be taken as a verdict on them.",
        "Open each page in the Admin console and compare against the "
        "recommendation.",
        rows, "policies.csv", count=len(rows))]


def check_alert_rules_off(ctx: RunContext) -> List[Finding]:
    """System-defined alert rules switched off. Google ships several off
    (on dev: User granted Admin privilege, Suspended user made active, User's
    password changed), so an untouched tenant hears about none of them."""
    hits = []
    for pol in _policy_settings(ctx):
        if pol["type"] != "rule.system_defined_alerts":
            continue
        value = pol["value"]
        if str(value.get("state", "")).upper() == "INACTIVE":
            hits.append({"Alert": str(value.get("displayName", "?")),
                         "Description": str(value.get("description", ""))})
    if not hits:
        return []
    hits.sort(key=lambda h: h["Alert"])
    return [Finding(
        "alert-rules-off", "MEDIUM",
        "Security alert rules switched off",
        "Google's built-in alerts for these events are off, so they never "
        "reach Alert Center or an admin's inbox. Several ship off by default, "
        "including an account being granted admin rights and a suspended "
        "account being reactivated - both things you want to hear about the "
        "day they happen.",
        "Switch on the ones that matter on the Admin console's Rules page, "
        "at minimum admin privilege changes and suspended accounts made "
        "active, and set who receives the email.",
        hits, "policies.csv")]


def check_takeout_services(ctx: RunContext) -> List[Finding]:
    """Google Takeout per service. Google's checklist names Takeout as the
    path to switch off for a leaver or a compromised account."""
    rows = []
    for pol in _policy_settings(ctx):
        if pol["type"] == "takeout.service_status" and \
                str(pol["value"].get("serviceState", "")).upper() == "ENABLED":
            rows.append({"Service": "takeout (master switch)",
                         "Org unit": pol["ou"] or "/"})
        elif pol["type"].endswith(".user_takeout") and \
                str(pol["value"].get("takeoutStatus", "")).upper() == "ENABLED":
            rows.append({"Service": pol["type"].rsplit(".", 1)[0],
                         "Org unit": pol["ou"] or "/"})
    if not rows:
        return []
    return [Finding(
        "takeout-enabled", "INFO",
        f"Google Takeout is available for {len(rows)} service(s)",
        "Users can download a full copy of their data from these services "
        "with Google Takeout. That is normal for most staff, and it is also "
        "the quickest way for a departing or compromised account to walk off "
        "with everything.",
        "Keep a Takeout-off organisational unit and move leavers and "
        "suspected-compromised accounts into it, using the Admin console's "
        "Google Takeout settings.",
        rows, "policies.csv", count=len(rows))]


def check_drive_for_desktop(ctx: RunContext) -> List[Finding]:
    """Drive for desktop allowed on any computer. Google's device checklist
    recommends restricting it to company-owned devices; its help page lists
    Business Starter and up as supported, so no edition gate is needed."""
    hits = [{"Org unit": pol["ou"] or "/"}
            for pol in _policy_settings(ctx)
            if pol["type"] == "drive_and_docs.drive_for_desktop"
            and pol["value"].get("allowDriveForDesktop") is True
            and pol["value"].get("restrictToAuthorizedDevices") is False]
    if not hits:
        return []
    return [Finding(
        "drive-desktop-any-device", "INFO",
        "Drive for desktop can sync to any computer",
        "Staff can install Drive for desktop on any Mac or PC, including a "
        "personal one, and keep a synced copy of company files there.",
        "Decide deliberately. If company files should stay on company "
        "machines, restrict Drive for desktop to authorised devices in the "
        "Admin console's Drive and Docs settings; the devices have to be in "
        "the device inventory first.",
        hits, "policies.csv", count=len(hits))]


def check_meet_safety(ctx: RunContext) -> List[Finding]:
    """Meet safety defaults. Not on Google's checklist: an OSH recommendation
    approved 2026-09-14, so it is INFO and says so."""
    rows = []
    for pol in _policy_settings(ctx):
        value, ou = pol["value"], pol["ou"] or "/"
        if pol["type"] == "meet.safety_domain" and \
                value.get("usersAllowedToJoin") == "ALL":
            rows.append({"Org unit": ou,
                         "Setting": "Who can join meetings: ALL"})
        elif pol["type"] == "meet.safety_access" and \
                value.get("meetingsAllowedToJoin") == "ALL":
            rows.append({"Org unit": ou,
                         "Setting": "Meetings users can join: ALL"})
        elif pol["type"] == "meet.safety_host_management" and \
                value.get("enableHostManagement") is False:
            rows.append({"Org unit": ou,
                         "Setting": "Host management is off by default"})
        elif pol["type"] == "meet.safety_external_participants" and \
                value.get("enableExternalLabel") is False:
            rows.append({"Org unit": ou,
                         "Setting": "External participants are not labelled"})
    if not rows:
        return []
    return [Finding(
        "meet-safety-open", "INFO",
        "Google Meet safety settings left at their most open",
        "Meet's join restrictions are at their widest value and host "
        "management is off by default, so hosts start a meeting without "
        "their moderation controls switched on. Values are shown as the API "
        "reports them.",
        "Our recommendation, not Google's checklist: turn host management on "
        "by default and review who can join, in the Admin console's Google "
        "Meet safety settings.",
        rows, "policies.csv", count=len(rows))]


def check_mail_delegation_policy(ctx: RunContext) -> List[Finding]:
    """Whether users may grant mailbox delegation at all: context for the
    per-mailbox delegation findings."""
    hits = [{"Org unit": pol["ou"] or "/"}
            for pol in _policy_settings(ctx)
            if pol["type"] == "gmail.mail_delegation"
            and pol["value"].get("enableMailDelegation") is True]
    if not hits:
        return []
    return [Finding(
        "mail-delegation-allowed", "INFO",
        "Users can give other people access to their mailbox",
        "Mail delegation is switched on, so any user can grant a colleague "
        "full read and send access to their mailbox without an admin. The "
        "delegation findings above show who has done so.",
        "No action needed if delegation is used deliberately; otherwise turn "
        "it off in the Admin console's Gmail settings.",
        hits, "policies.csv", count=len(hits))]


def check_api_controls(ctx: RunContext) -> List[Finding]:
    """Unconfigured third-party app access, reported raw. The meaning of
    ACCESS_LEVEL_UNSPECIFIED (Google's default on dev) is not yet confirmed
    against a console change, so this states the value and does not judge."""
    rows = [{"Org unit": pol["ou"] or "/",
             "Access level (raw)": str(pol["value"].get("accessLevel", "?"))}
            for pol in _policy_settings(ctx)
            if pol["type"] == "api_controls.unconfigured_third_party_apps"]
    if not rows:
        return []
    return [Finding(
        "api-controls-unconfigured", "INFO",
        "Access for third-party apps nobody has reviewed",
        "How the tenant treats apps an admin has not explicitly trusted or "
        "blocked, as the API reports it. This value is shown, not judged: "
        "the mapping from these codes to the Admin console options has not "
        "been verified yet.",
        "Check the Admin console's API controls (third-party app access) and "
        "trust only the apps the organisation uses.",
        rows, "policies.csv", count=len(rows))]


def check_2sv_methods(ctx: RunContext) -> List[Finding]:
    """2SV methods that include text and phone codes. Only the value "ALL"
    is judged: it is what an unhardened dev tenant returns, and the value
    the console's "Any except verification codes via text, phone call"
    option writes has not been read back yet."""
    hits = [{"Org unit": pol["ou"] or "/",
             "Allowed methods (raw)": "ALL"}
            for pol in _policy_settings(ctx)
            if pol["type"] == "security.two_step_verification_enforcement_factor"
            and pol["value"].get("allowedSignInFactorSet") == "ALL"]
    if not hits:
        return []
    return [Finding(
        "2sv-sms-allowed", "MEDIUM",
        "2-step verification accepts codes by text message or phone call",
        "Users can use a code sent by SMS or read out in a phone call as their "
        "second step. Those codes can be phished in real time and stolen by "
        "moving the phone number to another SIM, which is how most 2-step "
        "verification bypasses happen.",
        "In Admin console > Security > Authentication > 2-step verification, "
        "set Methods to \"Any except verification codes via text, phone call\" "
        "once staff have an authenticator app, passkey or security key. Have "
        "them record backup codes at the same time.",
        hits, "policies.csv", count=len(hits))]


def check_shared_drive_controls(ctx: RunContext) -> List[Finding]:
    """Shared drive settings beyond external access (check_sharing_policy
    owns that). Only the values seen on dev are judged; other enum values
    for allowedPartiesForDownloadPrintCopy are not yet mapped."""
    rows = []
    for pol in _policy_settings(ctx):
        if pol["type"] != "drive_and_docs.shared_drive_creation":
            continue
        value, ou = pol["value"], pol["ou"] or "/"
        if value.get("allowSharedDriveCreation") is True:
            rows.append({"Org unit": ou,
                         "Setting": "Anyone can create shared drives"})
        if value.get("allowManagersToOverrideSettings") is True:
            rows.append({"Org unit": ou, "Setting": "Drive managers can "
                         "change a drive's sharing settings"})
        if value.get("allowedPartiesForDownloadPrintCopy") == "ALL":
            rows.append({"Org unit": ou, "Setting": "Viewers and commenters "
                         "can download, print and copy"})
    if not rows:
        return []
    return [Finding(
        "sd-controls-open", "INFO",
        "Shared drive creation and settings left open",
        "Any user in these organisational units can create a shared drive, "
        "and its managers can loosen the organisation's defaults on it. "
        "Every new drive is somewhere files can be shared from that nobody "
        "set up on purpose.",
        "Decide deliberately. The usual build prevents creation at the "
        "organisational unit and allows it for one named group, and stops "
        "managers overriding the defaults, in Admin console > Apps > Google "
        "Workspace > Drive and Docs > Sharing settings > Shared drive "
        "creation.",
        rows, "policies.csv", count=len(rows))]


# Readable settings from Google's checklists whose values are shown, not
# judged: either the right answer depends on the client, or the mapping from
# API value to console option has not been read back on a test tenant.
RAW_POLICY_SETTINGS = {
    "security.advanced_protection_program": "Advanced Protection Program",
    "security.passkeys_restriction": "Passkeys allowed",
    "security.login_challenges": "Login challenge (employee ID)",
    "drive_and_docs.external_file_warning": "Warning on files from outside",
    "sites.sites_creation_and_modification": "Sites creation and editing",
    "chat.chat_apps_access": "Chat apps and webhooks",
    "api_controls.app_approval_requests": "Users may request app approval",
    "gmail.user_email_uploads": "Users may import mail and contacts",
    "gmail.confidential_mode": "Gmail confidential mode",
    "multi_party_approval.require_approvals":
        "Multi-party approval for sensitive admin actions",
    "data_regions.data_at_rest_region": "Data region (at rest)",
    "data_regions.data_processing_region": "Data region (processing)",
    "chat.space_history": "Chat history default",
}


def check_policy_settings_raw(ctx: RunContext) -> List[Finding]:
    """One INFO table of the RAW_POLICY_SETTINGS values, so a reviewer sees
    them beside the judged findings instead of digging in policies.csv."""
    rows = [{"Setting": RAW_POLICY_SETTINGS[pol["type"]],
             "Org unit": pol["ou"] or "/",
             "Value (raw)": json.dumps(pol["value"], sort_keys=True)}
            for pol in _policy_settings(ctx)
            if pol["type"] in RAW_POLICY_SETTINGS]
    if not rows:
        return []
    rows.sort(key=lambda r: (r["Setting"], r["Org unit"]))
    return [Finding(
        "policy-settings-raw", "INFO",
        "Other security settings, as the API reports them",
        "Settings from Google's security checklists that this audit reads but "
        "does not score, either because the right value depends on how the "
        "organisation works or because the raw value has not yet been matched "
        "to its Admin console option.",
        "Review each against the Admin console and record the decision.",
        rows, "policies.csv", count=len(rows))]


# Edition gating from each feature's "Supported editions" line on Google's
# admin help (read 2026-09-14), mapped to SKU ids from GAM7 7.48.01
# GamCommands.txt. Archived-user SKUs are deliberately absent: an archived
# account cannot use any of these.
_SKU_ENT_PLUS, _SKU_ENT_STD = "1010020020", "1010020026"
_SKU_FL_STARTER, _SKU_FL_STD, _SKU_FL_PLUS = \
    "1010020030", "1010020031", "1010020034"
_SKU_BIZ_PLUS = "1010020025"
_SKU_ENT_ESS, _SKU_ENT_ESS_PLUS = "1010060003", "1010060005"
_SKU_EDU_FUND = "1010070001"
_SKU_EDU_STD = {"1010310005", "1010310006", "1010310007"}
_SKU_EDU_PLUS = {"1010310008", "1010310009", "1010310010",
                 "1010310002", "1010310003"}
_SKU_CI_PREMIUM = "1010050001"
EDITION_FEATURES = [
    ("Data loss prevention (DLP)",
     {_SKU_FL_STD, _SKU_FL_PLUS, _SKU_ENT_STD, _SKU_ENT_PLUS, _SKU_EDU_FUND,
      _SKU_ENT_ESS_PLUS} | _SKU_EDU_STD | _SKU_EDU_PLUS),
    ("Context-Aware Access",
     {_SKU_FL_STD, _SKU_FL_PLUS, _SKU_ENT_STD, _SKU_ENT_PLUS,
      _SKU_ENT_ESS_PLUS, _SKU_CI_PREMIUM} | _SKU_EDU_STD | _SKU_EDU_PLUS),
    ("Drive trust rules",
     {_SKU_FL_PLUS, _SKU_ENT_STD, _SKU_ENT_PLUS, _SKU_ENT_ESS_PLUS}
     | _SKU_EDU_STD | _SKU_EDU_PLUS),
    ("Security center",
     {_SKU_FL_STD, _SKU_FL_PLUS, _SKU_ENT_STD, _SKU_ENT_PLUS,
      _SKU_ENT_ESS_PLUS} | _SKU_EDU_STD | _SKU_EDU_PLUS),
    ("Advanced mobile management",
     {_SKU_FL_STARTER, _SKU_FL_STD, _SKU_FL_PLUS, _SKU_BIZ_PLUS, _SKU_ENT_STD,
      _SKU_ENT_PLUS, _SKU_ENT_ESS, _SKU_ENT_ESS_PLUS, _SKU_CI_PREMIUM,
      "1010490001"} | _SKU_EDU_STD | _SKU_EDU_PLUS),
]


# For the upgrade opportunities section: the editions that add each feature
# (in plain words, from the SKU sets above) and why a client would want it.
UPGRADE_NOTES = {
    "Data loss prevention (DLP)": (
        "Enterprise Standard or Plus, Frontline Standard or Plus, "
        "Enterprise Essentials Plus or an Education edition",
        "Warns or blocks when ID numbers, card numbers or other sensitive "
        "data is shared outside the organisation from Drive, Gmail or Chat."),
    "Context-Aware Access": (
        "Enterprise Standard or Plus, Frontline Standard or Plus, "
        "Enterprise Essentials Plus, Education Standard or Plus, or Cloud "
        "Identity Premium",
        "Lets company data be opened only from approved devices or "
        "locations, so a stolen password alone is not enough."),
    "Drive trust rules": (
        "Enterprise Standard or Plus, Frontline Plus, Enterprise Essentials "
        "Plus, or Education Standard or Plus",
        "Controls who each team can share files with, inside and outside the "
        "organisation, instead of one setting for everyone."),
    "Security center": (
        "Enterprise Standard or Plus, Frontline Standard or Plus, Enterprise "
        "Essentials Plus, or Education Standard or Plus",
        "Gives the investigation tool and security dashboard used to trace "
        "and clean up a phishing message or a leaked file across the tenant."),
    "Advanced mobile management": (
        "Business Plus or any Enterprise, Frontline or Education Standard or "
        "Plus edition",
        "Lets the organisation require a screen lock, approve devices and "
        "wipe company data from a lost or departing employee's phone."),
}


def upgrade_opportunities(ctx: RunContext) -> List[Dict[str, str]]:
    """Protections the tenant's editions do not include. Shown in their own
    report section and never scored: a client is not marked down for what
    their licence cannot do."""
    if ctx.module_status("licenses") not in ("ok", "empty", "partial"):
        return []
    held = {col(r, "skuId") for r in ctx.rows("licenses")} - {""}
    if not held:
        return []
    return [{"Protection": feature, "Needs": UPGRADE_NOTES[feature][0],
             "Why it matters": UPGRADE_NOTES[feature][1]}
            for feature, skus in EDITION_FEATURES if not (skus & held)]


def _feature_usage(ctx: RunContext, feature: str) -> Tuple[str, Optional[bool]]:
    """What the collected data says about a gated feature: (text, in_use).
    in_use is None where no API read can tell."""
    if feature.startswith("Data loss"):
        rules = [p for p in _policy_settings(ctx) if p["type"] == "rule.dlp"]
        active = [p for p in rules
                  if str(p["value"].get("state", "")).upper() == "ACTIVE"]
        custom = [p for p in active if not str(
            p["value"].get("displayName", "")).startswith("[Default]")]
        if not _module_usable(ctx, "policies"):
            return "not read (policies module did not run)", None
        return (f"{len(active)} active rule(s), {len(custom)} of them written "
                "for this tenant", bool(active))
    if feature.startswith("Context-Aware"):
        if not _module_usable(ctx, "caalevels"):
            return "not read (run with --full to list access levels)", None
        count = len(ctx.rows("caalevels"))
        return f"{count} access level(s) defined", bool(count)
    return "no API read covers this; check in the Admin console", None


def check_edition_features(ctx: RunContext) -> List[Finding]:
    """Security features the tenant's licences include, and whether the
    collected data shows them in use. Silent on editions that include none,
    so a Business Standard tenant is never told it lacks DLP."""
    if not _module_usable(ctx, "licenses"):
        return []
    held: Dict[str, int] = {}
    names: Dict[str, str] = {}
    for row in ctx.rows("licenses"):
        sku = col(row, "skuId")
        held[sku] = held.get(sku, 0) + 1
        names[sku] = col(row, "skuDisplay") or sku
    rows, unused = [], []
    for feature, skus in EDITION_FEATURES:
        covering = sorted(s for s in skus if s in held)
        if not covering:
            continue
        seats = sum(held[s] for s in covering)
        editions = ", ".join(names[s] for s in covering)
        usage, in_use = _feature_usage(ctx, feature)
        rows.append({"Feature": feature,
                     "Included with": f"{editions} ({seats} user(s))",
                     "What the audit sees": usage})
        if in_use is False:
            unused.append({"Feature": feature, "Included with": editions,
                           "What the audit sees": usage})
    findings = []
    if unused:
        findings.append(Finding(
            "edition-security-unused", "MEDIUM",
            "Paid-for security features that are not switched on",
            "The tenant's licences include these protections, but the "
            "collected data shows them unused. The organisation is paying "
            "for controls that are doing nothing.",
            "Start with a small, specific rule set - for DLP, warn on "
            "external sharing of ID and card numbers; for Context-Aware "
            "Access, an access level for company devices - rather than "
            "trying to cover everything at once.",
            unused, "licenses.csv"))
    if rows:
        findings.append(Finding(
            "edition-security-features", "INFO",
            "Security features included in this tenant's edition",
            "Features Google only offers in some editions, listed because "
            "this tenant's licences include them. Where no API exposes the "
            "configuration, the row says to check the console.",
            "Review each against how the organisation works; the ones marked "
            "check in the Admin console need a look by hand.",
            rows, "licenses.csv", count=len(rows)))
    return findings


# Admin log events worth a line each: settings, roles, security. Other
# events (licence churn, group membership) are counted only.
ADMIN_EVENT_PATTERN = re.compile(
    r"APPLICATION_SETTING|ROLE|TWO_STEP|2SV|SSO|RULE|SECURITY|DOMAIN|"
    r"ALLOWLIST|TRUST|PASSWORD_POLICY|RECOVERY", re.IGNORECASE)


# Link-sharing values that open a file to anyone, from the Reports API Drive
# appendix (change_document_visibility new_value).
PUBLIC_VISIBILITY = {"people_with_link": "anyone with the link",
                     "public_on_the_web": "public on the web"}


def check_drive_sharing_log(ctx: RunContext) -> List[Finding]:
    """New Drive exposure in the last ACTIVITY_DAYS days, from the audit log:
    files opened to anyone, and files shared with outside people, by the
    user who did it. Cheap enough for every monthly run, where the full file
    scans are not."""
    if not _module_usable(ctx, "report_drive_sharing"):
        return []
    internal = {d.lower() for d in ctx.internal_domains}
    public: Dict[str, Dict[str, str]] = {}
    outside: Dict[str, Dict[str, set]] = {}
    for row in ctx.rows("report_drive_sharing"):
        event, actor = col(row, "name"), col(row, "actor.email")
        doc = col(row, "doc_id")
        if event == "change_document_visibility":
            made = PUBLIC_VISIBILITY.get(col(row, "new_value"))
            if made:
                public[doc] = {"User": actor, "File": col(row, "doc_title"),
                               "File ID": doc, "Opened to": made,
                               "When": col(row, "id.time")}
        elif event == "change_user_access":
            target = col(row, "target_user").lower()
            if not target or col(row, "new_value") == "none":
                continue
            # target_user is an address, or a bare domain for a domain share.
            if email_domain(target) in internal or target in internal:
                continue
            entry = outside.setdefault(actor, {"files": set(),
                                               "people": set()})
            entry["files"].add(doc)
            entry["people"].add(target)
    findings = []
    if public:
        rows = sorted(public.values(), key=lambda r: (r["User"], r["File"]))
        findings.append(Finding(
            "drive-made-public-30d", "HIGH",
            f"Files opened to anyone in the last {ACTIVITY_DAYS} days",
            "These files were set so that anyone with the link, or anyone on "
            "the web, can open them. Links get forwarded, pasted into tickets "
            "and indexed, so treat each file as readable by strangers. The "
            "audit log shows the change, not today's setting: some may "
            "since have been closed again.",
            "Ask each person whether the file needs to be open. Switch the "
            "rest to Restricted, and share with named people instead.",
            rows, "report_drive_sharing.csv", id_field="File ID"))
    if outside:
        rows = [{"User": actor or "(unknown)",
                 "Files shared out": str(len(e["files"])),
                 "Outside recipients": ", ".join(sorted(e["people"])[:5])
                 + (" ..." if len(e["people"]) > 5 else "")}
                for actor, e in sorted(outside.items())]
        findings.append(Finding(
            "drive-shared-outside-30d", "MEDIUM",
            f"Files shared with outside people in the last {ACTIVITY_DAYS} days",
            "Who shared Drive files with people or domains outside the "
            "organisation this month. Most of it is normal work; the "
            "pattern to look for is one person sharing many files, or "
            "sharing with personal addresses.",
            "Review the people with the most files shared out, and remove "
            "access that is no longer needed.",
            rows, "report_drive_sharing.csv"))
    return findings


def check_dwd_grants(ctx: RunContext) -> List[Finding]:
    """Domain-wide delegation granted in the last ACTIVITY_DAYS days, from
    the admin log (AUTHORIZE_API_CLIENT_ACCESS). Neither GAM7 nor any Google
    API lists the grants that already exist (checked against GAM7 7.48.22),
    so older grants stay on the check-by-hand list; this catches new ones
    each month."""
    if not _module_usable(ctx, "report_admin"):
        return []
    rows = []
    for row in ctx.rows("report_admin"):
        if col(row, "name") != "AUTHORIZE_API_CLIENT_ACCESS":
            continue
        scopes = [x.strip() for x in col(row, "API_SCOPES").split(",")
                  if x.strip()]
        broad = sorted({RISKY_SCOPES[x] for x in scopes if x in RISKY_SCOPES})
        rows.append({"Client ID": col(row, "API_CLIENT_NAME"),
                     "Granted by": col(row, "actor.email"),
                     "When": col(row, "id.time"),
                     "Scopes": str(len(scopes)),
                     "Broad access": ", ".join(broad) or "none"})
    if not rows:
        return []
    broad_rows = [r for r in rows if r["Broad access"] != "none"]
    return [Finding(
        "dwd-granted-30d", "MEDIUM" if broad_rows else "INFO",
        f"Domain-wide delegation granted in the last {ACTIVITY_DAYS} days",
        "A service account with domain-wide delegation can act as any user "
        "without them signing in, within the scopes granted. Full Gmail or "
        "Drive scopes mean it can read every mailbox or every file. If GAM "
        "itself was set up this month, its own service account appears here "
        "and is expected.",
        "Confirm each client ID belongs to a tool the organisation knows "
        "(Security > API controls > Domain-wide delegation), remove any it "
        "does not, and trim the rest to the scopes they need.",
        rows, "report_admin.csv", id_field="Client ID")]


def check_admin_activity(ctx: RunContext) -> List[Finding]:
    """What admins changed in the last ACTIVITY_DAYS days: the settings and
    role events in full, everything else as counts."""
    if not _module_usable(ctx, "report_admin"):
        return []
    rows = ctx.rows("report_admin")
    if not rows:
        return []
    counts: Dict[str, int] = {}
    detail = []
    for row in rows:
        event = col(row, "name")
        counts[event] = counts.get(event, 0) + 1
        if ADMIN_EVENT_PATTERN.search(event):
            change = col(row, "SETTING_NAME") or col(row, "ROLE_NAME") \
                or col(row, "RULE_NAME")
            old, new = col(row, "OLD_VALUE"), col(row, "NEW_VALUE")
            if old or new:
                change = f"{change}: {old or '-'} -> {new or '-'}"
            detail.append({"Time": col(row, "id.time"),
                           "Admin": col(row, "actor.email") or "system",
                           "Event": event, "Change": change})
    findings = []
    if detail:
        findings.append(Finding(
            "admin-setting-changes", "INFO",
            f"Settings and admin-role changes in the last {ACTIVITY_DAYS} "
            "days",
            "Who changed tenant settings, admin roles or security rules "
            "recently, newest first. On a tenant you have just inherited, "
            "this is how you learn what someone switched off.",
            "Read the list for anything nobody can account for; the full log "
            "is in report_admin.csv and in the Admin console's admin log "
            "events.",
            detail, "report_admin.csv", count=len(detail)))
    summary = [{"Event": e, "Count": str(n)}
               for e, n in sorted(counts.items(), key=lambda kv: -kv[1])]
    findings.append(Finding(
        "admin-activity-summary", "INFO",
        f"Admin activity in the last {ACTIVITY_DAYS} days: {len(rows)} "
        "event(s)",
        "Every admin audit log event in the window, counted by type.",
        "No action needed; context for the settings changes above.",
        summary, "report_admin.csv", count=len(summary)))
    return findings


def check_login_risk(ctx: RunContext) -> List[Finding]:
    """Risky sign-in events, sensitive actions Google blocked, and failed
    sign-ins in the last ACTIVITY_DAYS days."""
    if not _module_usable(ctx, "report_login"):
        return []
    risky, blocked, failures = [], [], {}
    for row in ctx.rows("report_login"):
        event = col(row, "name")
        user = col(row, "actor.email")
        if event in LOGIN_RISK_EVENTS:
            risky.append({"Time": col(row, "id.time"), "User": user,
                          "Event": event, "IP": col(row, "ipAddress"),
                          "Country": col(row, "networkInfo.regionCode")})
        elif event in LOGIN_BLOCKED_EVENTS:
            blocked.append({"Time": col(row, "id.time"), "User": user,
                            "Action": col(row, "sensitive_action_name") or "?",
                            "Challenge": col(row, "login_challenge_method") or "?",
                            "IP": col(row, "ipAddress"),
                            "Country": col(row, "networkInfo.regionCode")})
        elif event in LOGIN_FAILURE_EVENTS:
            failures[user] = failures.get(user, 0) + 1
    findings = []
    if risky:
        findings.append(Finding(
            "login-risk-events", "HIGH",
            f"Google flagged {len(risky)} risky sign-in or account event(s) "
            f"in the last {ACTIVITY_DAYS} days",
            "Google's sign-in log recorded suspicious logins, leaked-password "
            "or hijack account disables, government-backed attack warnings or "
            "mail forwarding to outside addresses. Each one is either "
            "explained by the user or is an incident.",
            "Ask each user about their event; for anything unexplained, reset "
            "the password, sign the user out of all sessions, and review "
            "their forwarding, filters, delegates and app tokens.",
            risky, "report_login.csv"))
    if blocked:
        findings.append(Finding(
            "login-blocked-actions", "MEDIUM",
            f"Google blocked {len(blocked)} sensitive action(s) it judged "
            f"risky in the last {ACTIVITY_DAYS} days",
            "Google refused these actions because the session looked risky "
            "and the user did not pass a re-verification, so none of them "
            "happened. The Action column names what was attempted.",
            "Ask each user whether they tried the named action at that time. "
            "If they did not, treat the account as compromised: reset the "
            "password, sign the user out of all sessions, and review their "
            "app tokens.",
            blocked, "report_login.csv"))
    if failures:
        rows = [{"User": u, "Failed sign-ins": str(n)}
                for u, n in sorted(failures.items(), key=lambda kv: -kv[1])]
        findings.append(Finding(
            "login-failures", "INFO",
            f"Failed sign-ins in the last {ACTIVITY_DAYS} days "
            f"({sum(failures.values())})",
            "Failed sign-ins by account. A handful is forgotten passwords; "
            "hundreds on one account is someone guessing.",
            "Look at the top of the list; an account with many failures and "
            "no 2-step verification is the one to fix first.",
            rows, "report_login.csv", count=len(rows)))
    return findings


def check_security_alerts(ctx: RunContext) -> List[Finding]:
    """Alert Center alerts raised in the last ACTIVITY_DAYS days. Status is
    not trusted: alerts sit at NOT_STARTED forever unless someone triages."""
    if not _module_usable(ctx, "alerts"):
        return []
    rows = ctx.rows("alerts")
    if not rows:
        return []
    evidence = [{"Created": col(row, "createTime"), "Type": col(row, "type"),
                 "Source": col(row, "source"),
                 "Severity": col(row, "metadata.severity") or "?",
                 "Status": col(row, "metadata.status") or "?"}
                for row in rows]
    evidence.sort(key=lambda e: e["Created"], reverse=True)
    high = [e for e in evidence if e["Severity"].upper() == "HIGH"]
    return [Finding(
        "security-alerts", "MEDIUM" if high else "INFO",
        f"{len(rows)} Alert Center alert(s) in the last {ACTIVITY_DAYS} days"
        + (f", {len(high)} high severity" if high else ""),
        "Google's own security alerts for the tenant. Nobody is notified "
        "unless the matching alert rule emails someone, so these are often "
        "read here for the first time.",
        "Open each in the Admin console's Alert center, decide whether it "
        "was expected, and close it.",
        high + [e for e in evidence if e not in high], "alerts.csv",
        count=len(rows))]


def _norm_sku(name: str) -> str:
    """Normalise a SKU name for matching `info domain` seat lines against
    licenses.csv display names ('Google Workspace Enterprise Plus' vs
    'Enterprise Plus')."""
    name = re.sub(r"\(formerly[^)]*\)", "", name.lower())
    # `info domain` prints "Workspace Enterprise Plus Licenses: 50" without
    # the leading "Google"; strip both spellings.
    for junk in ("google workspace", "workspace", "g suite", "licenses",
                 "license"):
        name = name.replace(junk, "")
    return " ".join(name.split())


def parse_owned_licences(text: str) -> Dict[str, int]:
    """Pull per-SKU seat counts out of raw `gam info domain` output
    (lines shaped like 'Google Workspace Enterprise Plus Licenses: 50').
    Unrecognised lines are ignored, so a format change yields no data
    rather than wrong data."""
    owned = {}
    for line in text.splitlines():
        match = re.match(r"\s*(.{3,}?)\s+Licenses:\s*(\d+)\s*$", line,
                         re.IGNORECASE)
        if match:
            owned[match.group(1).strip()] = int(match.group(2))
    return owned


def check_licence_waste(ctx: RunContext) -> List[Finding]:
    """Seats owned (from the preflight's `info domain` output) vs seats
    assigned (licenses.csv). Free Cloud Identity is not a seat."""
    path = ctx.run_dir / "domaininfo.txt"
    # domaininfo.txt always exists (preflight writes it); without the
    # licenses module every SKU would read as 100% unused.
    if not path.is_file() or not _module_usable(ctx, "licenses"):
        return []
    owned = parse_owned_licences(path.read_text(encoding="utf-8"))
    assigned: Dict[str, int] = {}
    for row in ctx.rows("licenses"):
        sku = _norm_sku(col(row, "skuDisplay", "skuId"))
        assigned[sku] = assigned.get(sku, 0) + 1
    hits = []
    for sku_name, seats in sorted(owned.items()):
        if re.search(r"cloud identity(?! premium)", sku_name.lower()):
            continue
        norm = _norm_sku(sku_name)
        if norm in assigned:
            used = assigned[norm]
        else:
            # Substring only as a fallback: on an exact hit it also summed
            # "Enterprise Plus - Archived User" into Enterprise Plus.
            used = sum(count for key, count in assigned.items()
                       if key and norm and (key in norm or norm in key))
        gap = seats - used
        if gap >= LICENCE_WASTE_MIN_GAP and seats \
                and gap / seats >= LICENCE_WASTE_MIN_FRACTION:
            hits.append({"Licence": sku_name, "Seats owned": str(seats),
                         "Assigned": str(used), "Unused": str(gap)})
    if not hits:
        return []
    return [Finding(
        "licence-waste", "MEDIUM",
        "Paying for licences that are not assigned to anyone",
        "The tenant owns more seats of these licences than it has assigned "
        "to users. Unassigned seats do nothing except appear on the "
        "invoice, every month, until someone notices.",
        "Reduce the seat count at the next renewal (or sooner on a "
        "flexible plan), or assign the spare seats where they are "
        "genuinely needed.",
        hits, "domaininfo.txt")]


def check_admin_roles(ctx: RunContext) -> List[Finding]:
    """Role-assignment hygiene from admins.csv: roles held by suspended or
    no-longer-resolvable accounts, how widely admin rights are spread, and
    the full who-holds-what map."""
    if not (_module_usable(ctx, "admins") and _module_usable(ctx, "users")):
        return []
    users = {col(r, "primaryEmail").lower(): r for r in ctx.rows("users")}
    active_count = len(_live_users(ctx))
    map_rows, suspended_hits, unresolved = [], [], []
    holders = set()
    for row in ctx.rows("admins"):
        role = col(row, "role")
        assignee = (col(row, "assignedToUser")
                    or col(row, "assignedToGroup")
                    or col(row, "assignedToServiceAccount"))
        ou = col(row, "orgUnit")
        scope = f"OU {ou}" if ou else col(row, "scopeType")
        map_rows.append({"Assignee": assignee or col(row, "assignedTo"),
                         "Role": role, "Scope": scope})
        if truthy(col(row, "assignedToUnknown")):
            unresolved.append({"Assigned to (ID)": col(row, "assignedTo"),
                               "Role": role})
            continue
        user_row = users.get(assignee.lower()) if assignee else None
        if user_row is not None:
            if truthy(col(user_row, "suspended")):
                suspended_hits.append({"User": assignee, "Role": role})
            else:
                holders.add(assignee.lower())
    findings = []
    if suspended_hits:
        findings.append(Finding(
            "admin-role-suspended-holder", "HIGH",
            "Admin roles still assigned to suspended accounts",
            "These suspended accounts - typically leavers - still hold "
            "admin roles. Reactivating the account, deliberately or "
            "through a compromise of the recovery path, reactivates the "
            "admin rights with it.",
            "Remove the role assignments as part of finishing the "
            "offboarding; the roles can be reassigned to active staff "
            "where the function is still needed.",
            suspended_hits, "admins.csv"))
    if unresolved:
        findings.append(Finding(
            "admin-role-unresolved", "MEDIUM",
            "Admin role assignments pointing at accounts that no longer "
            "resolve",
            "The API cannot resolve who these role assignments belong to - "
            "typically an account that was deleted while still holding the "
            "role. Stale assignments clutter the admin model and hide who "
            "actually holds power in the tenant.",
            "Review each assignment in Admin console > Account > Admin "
            "roles and delete the ones whose holder no longer exists.",
            unresolved, "admins.csv"))
    if (active_count >= ADMIN_SPRAWL_MIN_USERS
            and len(holders) / active_count > ADMIN_SPRAWL_FRACTION):
        pct = round(100 * len(holders) / active_count)
        findings.append(Finding(
            "admin-sprawl", "MEDIUM",
            f"{pct}% of active users hold an admin role",
            f"{len(holders)} of {active_count} active users hold some "
            "admin role. Every admin account is a higher-value target and "
            "a bigger blast radius when phished; rights this widely spread "
            "usually mean roles were granted to solve one ticket and never "
            "taken back.",
            "Review the role map below against who actually performs admin "
            "work, and remove the rest. Prefer narrow delegated roles over "
            "broad ones.",
            [{"User": h} for h in sorted(holders)], "admins.csv",
            count=len(holders)))
    if map_rows:
        findings.append(Finding(
            "admin-role-map", "INFO",
            f"Admin role assignments ({len(holders)} of {active_count} "
            "active users hold a role)",
            "Every admin role assignment in the tenant: who holds which "
            "role, and over what scope.",
            "No action needed; review the list for surprises.",
            map_rows, "admins.csv"))
    return findings


CHECKS = [
    check_public_files,
    check_external_file_shares,
    check_super_admin_count,
    check_admin_2sv,
    check_admin_asps,
    check_external_forwarding,
    check_orphaned_shared_drives,
    check_shared_drive_external,
    check_group_exposure,
    check_filter_forwarding,
    check_filter_bec,
    check_unmanaged_accounts,
    check_dns_findings,
    check_2sv_enrolment,
    check_pop_imap,
    check_dormant_accounts,
    check_mailbox_delegation,
    check_at_risk_accounts,
    check_suspended_holding_data,
    check_risky_oauth,
    check_admin_recovery,
    check_admin_backup_codes,
    check_licensed_super_admins,
    check_public_calendars,
    check_password_policy,
    check_session_policy,
    check_2sv_policy,
    check_sharing_policy,
    check_service_status,
    check_super_admin_self_recovery,
    check_gmail_protections,
    check_external_chat,
    check_console_only_settings,
    check_alert_rules_off,
    check_takeout_services,
    check_drive_for_desktop,
    check_meet_safety,
    check_mail_delegation_policy,
    check_api_controls,
    check_2sv_methods,
    check_shared_drive_controls,
    check_policy_settings_raw,
    check_edition_features,
    check_admin_activity,
    check_drive_sharing_log,
    check_dwd_grants,
    check_policy_baseline,
    check_login_risk,
    check_security_alerts,
    check_licence_waste,
    check_admin_roles,
    check_sendas,
    check_forwarding_addresses,
    check_group_members,
    check_vacation,
    check_vault_exports,
    check_google_suspended,
    check_new_accounts,
    check_admin_2sv_enforced,
    check_root_ou_users,
    check_shared_drive_download_controls,
    check_oauth_inventory,
    check_user_password_strength,
    check_admin_second_factors,
    check_classroom_settings,
    check_courses,
    check_classroom_outsiders,
    check_classroom_guardians,
    check_tenant_shape,
]


# Client-readable name per check, for the "checked and clean" table. A check
# missing from here fails TestCheckTitles, so a new check cannot ship without
# a name a reader can understand.
CHECK_TITLES = {
    "check_public_files": "Files public on the web or open to anyone with the link",
    "check_external_file_shares": "Files shared to external people, domains, or shared in",
    "check_super_admin_count": "At least two super admins",
    "check_admin_2sv": "Super admins enrolled in 2-step verification",
    "check_admin_asps": "App passwords on admin accounts",
    "check_external_forwarding": "Mailboxes forwarding outside the organisation",
    "check_orphaned_shared_drives": "Shared Drives with no manager",
    "check_shared_drive_external": "Shared Drive external members and open settings",
    "check_group_exposure": "Groups open to joining, posting or external members",
    "check_filter_forwarding": "Gmail filters forwarding externally",
    "check_filter_bec": "Gmail filters hiding payment mail or a sender",
    "check_unmanaged_accounts": "Personal Google accounts on company domains",
    "check_dns_findings": "Mail DNS (MX, SPF, DKIM, DMARC)",
    "check_2sv_enrolment": "2-step verification enrolment across users",
    "check_pop_imap": "POP and IMAP enabled on mailboxes",
    "check_dormant_accounts": "Dormant admins and unused licensed accounts",
    "check_mailbox_delegation": "Mailbox delegation",
    "check_at_risk_accounts": "Accounts stacking several risk factors",
    "check_suspended_holding_data": "Suspended accounts holding licences or data",
    "check_risky_oauth": "Third-party apps with wide mailbox or Drive access",
    "check_admin_recovery": "Super admin recovery details",
    "check_admin_backup_codes": "Super admin backup codes",
    "check_licensed_super_admins": "Super admins holding paid licences",
    "check_public_calendars": "Public primary calendars",
    "check_password_policy": "Password policy",
    "check_session_policy": "Web session length",
    "check_2sv_policy": "2-step verification policy per org unit",
    "check_sharing_policy": "New Shared Drive external-sharing defaults",
    "check_service_status": "Google services switched on or off",
    "check_super_admin_self_recovery": "Super admin self-recovery",
    "check_gmail_protections": "Gmail phishing and malware protections",
    "check_external_chat": "External Google Chat",
    "check_console_only_settings": "Settings only the Admin console shows",
    "check_alert_rules_off": "Security alert rules",
    "check_takeout_services": "Google Takeout per service",
    "check_drive_for_desktop": "Drive for desktop device restriction",
    "check_meet_safety": "Google Meet safety settings",
    "check_mail_delegation_policy": "Mail delegation allowed",
    "check_api_controls": "Third-party app access controls",
    "check_2sv_methods": "2-step verification methods allowed",
    "check_shared_drive_controls": "Shared drive creation and manager overrides",
    "check_policy_settings_raw": "Other checklist settings (raw)",
    "check_edition_features": "Edition security features in use",
    "check_admin_activity": "Admin log: settings and role changes",
    "check_drive_sharing_log": "Drive sharing in the last 30 days",
    "check_dwd_grants": "Domain-wide delegation granted in the last 30 days",
    "check_policy_baseline": "Settings against the CISA Google Workspace baseline",
    "check_login_risk": "Risky sign-in events and failed sign-ins",
    "check_security_alerts": "Alert Center alerts",
    "check_licence_waste": "Licences owned but unassigned",
    "check_admin_roles": "Admin role hygiene",
    "check_sendas": "Send-as addresses outside the organisation",
    "check_forwarding_addresses": "External forwarding addresses on file",
    "check_group_members": "Group membership: external members, owners",
    "check_vacation": "Out-of-office replies to anyone",
    "check_vault_exports": "Vault exports on record",
    "check_google_suspended": "Accounts suspended by Google",
    "check_new_accounts": "Accounts created recently",
    "check_admin_2sv_enforced": "Super admin 2-step verification enforced",
    "check_root_ou_users": "Users left in the root org unit",
    "check_shared_drive_download_controls":
        "Shared Drive copy and download controls",
    "check_oauth_inventory": "Third-party app inventory",
    "check_user_password_strength": "Weak or too-short user passwords",
    "check_admin_second_factors": "Super admin second factors",
    "check_classroom_settings": "Google Classroom settings (Education)",
    "check_courses": "Classroom courses (Education)",
    "check_classroom_outsiders": "Classroom members and invitations from outside the organisation",
    "check_classroom_guardians": "Classroom guardians and guardian invitations",
    "check_tenant_shape": "Tenant at a glance",
}


def run_checks(ctx: RunContext) -> List[Finding]:
    print_header("STAGE 2 - CHECK")
    findings: List[Finding] = []
    ctx.clean_checks = []
    ctx.check_errors = []
    ctx.manifest["meta"]["break_glass_seen"] = []
    for check in CHECKS:
        ctx.consulted = []
        try:
            raised = check(ctx)
            # Every module the check read, usable or not: the comparison
            # needs all of them complete in both runs to call a row fixed.
            read = sorted({k for k, _ in ctx.consulted})
            for finding in raised:
                finding.modules = read
            findings.extend(raised)
            # Clean means the check saw all of its data and found nothing.
            # One missing or partly collected module makes it a coverage
            # gap, listed as such elsewhere, not a clean result.
            complete = bool(ctx.consulted) and all(
                ctx.module_status(k) in ("ok", "empty")
                for k, _ in ctx.consulted)
            if not raised and complete:
                modules = sorted({k for k, usable in ctx.consulted if usable})
                ctx.clean_checks.append((CHECK_TITLES[check.__name__],
                                         ", ".join(modules)))
        except Exception as exc:
            # One broken check must not sink the report; surface it instead.
            print_error(f"Check {check.__name__} failed: "
                        f"{type(exc).__name__}: {exc}")
            ctx.check_errors.append(check.__name__)
            findings.append(Finding(
                f"check-error-{check.__name__}", "INFO",
                f"Internal: check {check.__name__} did not run",
                f"The check raised {type(exc).__name__} while reading the "
                "collected data, so its result is unknown rather than "
                "clean.",
                "Report this to the script maintainer with the run log.",
                [], "tenant_scope.log"))
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    for finding in findings:
        # The severity is the line's only tag; print_error and friends would
        # add their own in front of it ("[INFO] [INFO] ...").
        level, colour = {"CRITICAL": ("error", Colours.RED),
                         "HIGH": ("warning", Colours.YELLOW),
                         "MEDIUM": ("warning", Colours.YELLOW),
                         "INFO": ("info", Colours.CYAN)}[finding.severity]
        _emit(level, f"{colour}[{finding.severity}] {finding.title} "
                     f"({finding.count}){Colours.RESET}")
    return findings


###############################################################################
# HISTORY - POSTURE SCORE AND COMPARISON WITH THE PREVIOUS RUN
###############################################################################

SCORE_WEIGHTS = {"CRITICAL": 15, "HIGH": 7, "MEDIUM": 3, "INFO": 0}
SCORE_HALF_POINTS = 70
SCORE_TREND_RUNS = 6


def posture_score(findings: List[Finding]) -> int:
    """Google has no Secure Score, so the report computes one: each finding
    (not each evidence row) costs points by severity and the score halves for
    every SCORE_HALF_POINTS. It never reaches 0, so a badly configured tenant
    still shows progress month to month. Same formula as m365_scope.py; change
    both together."""
    points = sum(SCORE_WEIGHTS[f.severity] for f in findings
                 if not f.fid.startswith("check-error"))
    return max(1, round(100 * 0.5 ** (points / SCORE_HALF_POINTS)))


def _read_manifest(run_dir: Path) -> Dict:
    try:
        return json.loads((run_dir / "manifest.json").read_text(
            encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def earlier_runs(ctx: RunContext) -> List[Path]:
    """Completed earlier runs of the same customer in the same output folder,
    oldest first. An interrupted run or another tenant's folder is never a
    baseline: comparing against it would report fixes that never happened."""
    customer = ctx.manifest["meta"].get("customer_id")
    parent = ctx.run_dir.resolve().parent
    if not customer or not parent.is_dir():
        return []
    current = ctx.run_dir.resolve()
    runs = []
    for d in sorted(parent.iterdir()):
        if not d.is_dir() or d.resolve() == current \
                or d.name > ctx.run_dir.resolve().name:
            continue
        meta = _read_manifest(d).get("meta", {})
        if meta.get("customer_id") == customer and meta.get("complete"):
            runs.append(d)
    return runs


def find_previous_run(ctx: RunContext) -> Optional[Path]:
    """--compare-with wins; otherwise the newest completed earlier run."""
    if getattr(ctx.args, "compare_with", None):
        return Path(ctx.args.compare_with)
    runs = earlier_runs(ctx)
    return runs[-1] if runs else None


def score_trend(ctx: RunContext, score: int) -> List[Tuple[str, int]]:
    """(collected date, score) for up to the last SCORE_TREND_RUNS runs,
    this one included. Runs from before v1.7.0 carry no score and are left
    out rather than recomputed from different checks."""
    points = []
    for d in earlier_runs(ctx):
        meta = _read_manifest(d).get("meta", {})
        if isinstance(meta.get("posture_score"), int):
            points.append((str(meta.get("collected_at", d.name))[:10],
                           meta["posture_score"]))
    points.append((str(ctx.manifest["meta"].get("collected_at", "now"))[:10],
                   score))
    return points[-SCORE_TREND_RUNS:]


def compare_with_previous(ctx: RunContext, findings: List[Finding],
                          prev_dir: Optional[Path]) -> Dict:
    """Mark each finding and evidence row new or persisting against the
    previous run, and list the findings that were resolved. A finding whose
    data was only partly collected in either run is "not compared", never
    resolved: a row missing because a user's scan failed is not a fix."""
    summary: Dict = {"previous": "", "new": [], "persisting": [],
                     "resolved": [], "not_compared": [], "resolved_rows": 0,
                     "prev_counts": {}, "prev_score": None}
    if not prev_dir:
        for f in findings:
            f.change = "first_run"
        return summary
    prev_manifest = _read_manifest(prev_dir)
    prev_modules = prev_manifest.get("modules", {})
    prev_meta = prev_manifest.get("meta", {})
    summary["previous"] = str(prev_meta.get("collected_at", prev_dir.name))
    summary["prev_score"] = prev_meta.get("posture_score")
    prev_f = {r["id"]: r for r in read_csv_rows(prev_dir / "findings.csv")
              if r.get("id")}
    for r in prev_f.values():
        sev = r.get("severity", "")
        summary["prev_counts"][sev] = summary["prev_counts"].get(sev, 0) + 1
    # Rows are re-keyed with this run's id rules rather than trusting a stored
    # evidence_id, so a run from before v1.7.0 still compares row by row.
    prev_rows: Dict[str, List[Dict[str, str]]] = {}
    for r in read_csv_rows(prev_dir / "findings_evidence.csv"):
        row = {k: v for k, v in r.items()
               if k not in ("id", "severity", "evidence_id", "change")
               and v not in (None, "")}
        prev_rows.setdefault(r.get("id", ""), []).append(row)

    def comparable(mods: Iterable[str]) -> bool:
        # A module missing or partial in either run drops rows that were
        # never looked at; reporting those as fixed would be false progress.
        # A module that ran in neither run (tier 4 without --full, Classroom
        # on a non-Education tenant) cost both runs the same rows, so it is
        # left out, and a finding that reads no module compares as it is.
        ran_in_one = [m for m in mods
                      if ctx.module_status(m) not in ("", "n/a")
                      or prev_modules.get(m, {}).get("status", "")
                      not in ("", "n/a")]
        return all(
            ctx.module_status(m) in ("ok", "empty")
            and prev_modules.get(m, {}).get("status") in ("ok", "empty")
            for m in ran_in_one)

    current_ids: Set[str] = set()
    for f in findings:
        current_ids.add(f.fid)
        if not comparable(f.modules):
            f.change = "not_compared"
            summary["not_compared"].append(f)
            continue
        f.change = "persisting" if f.fid in prev_f else "new"
        summary[f.change].append(f)
        before = {_evidence_id(f, r) for r in prev_rows.get(f.fid, [])}
        now = set()
        for row in f.all_evidence:
            eid = _evidence_id(f, row)
            now.add(eid)
            f.row_changes[eid] = "persisting" if eid in before else "new"
        summary["resolved_rows"] += len(before - now)
    for fid, r in prev_f.items():
        if fid in current_ids:
            continue
        # A run from before v1.7.0 has no modules column, so it cannot say.
        mods = [m for m in (r.get("modules") or "").split(";") if m]
        if r.get("modules") is not None and comparable(mods):
            summary["resolved"].append(r)
        else:
            summary["not_compared"].append(r)
    return summary


###############################################################################
# RENDER
###############################################################################

SEVERITY_COLOURS = {"CRITICAL": "#c0392b", "HIGH": "#e67e22",
                    "MEDIUM": "#d4ac0d", "INFO": "#3498db"}

TAMINGDNS_TOOL_LINKS = ("mx", "spf", "dkim", "dmarc")

# Shared with m365_scope.py so the two reports read as one product.
STYLE = """
  :root { --ink:#1f2933; --muted:#5f6b76; --line:#e2e6ea; --bg:#f5f6f8;
          --card:#fff; --head:#14202b; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
         margin:0; color:var(--ink); background:var(--bg); line-height:1.45; }
  .wrap { max-width:980px; margin:0 auto; padding:24px 16px; }
  header.page { background:var(--head); color:#fff; padding:32px 16px; }
  header.page .inner { max-width:980px; margin:0 auto; }
  header.page h1 { margin:0 0 6px; font-size:26px; }
  header.page p { margin:0; color:#b8c4cf; }
  header.page a { color:#fff; }
  h2 { margin:32px 0 12px; font-size:20px; border-bottom:2px solid var(--line);
       padding-bottom:6px; }
  .tiles { display:flex; gap:12px; margin:20px 0; flex-wrap:wrap; }
  .tile { background:var(--card); border-radius:8px; padding:14px 20px;
          min-width:120px; box-shadow:0 1px 3px rgba(0,0,0,.12);
          text-align:center; flex:1; }
  .tile .num { font-size:30px; font-weight:700; }
  .tile .lbl { color:var(--muted); }
  .tile .delta { font-size:12px; color:var(--muted); }
  section.card { background:var(--card); border-radius:8px; padding:16px 20px;
          margin-bottom:14px; box-shadow:0 1px 3px rgba(0,0,0,.12); }
  section.card h3 { margin:0 0 8px; font-size:17px; }
  .sev { color:#fff; font-size:12px; padding:2px 8px; border-radius:4px;
         vertical-align:middle; margin-right:6px; }
  .badge { font-size:11px; padding:1px 6px; border-radius:4px;
           border:1px solid var(--muted); color:var(--muted); margin-left:6px;
           vertical-align:middle; }
  .badge.new { border-color:#c0392b; color:#c0392b; }
  table { border-collapse:collapse; width:100%; font-size:13.5px; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line);
           vertical-align:top; }
  th { background:#f0f2f4; }
  .scroll { overflow-x:auto; }
  .more, .note { color:var(--muted); font-size:13px; }
  .fid { color:#8a96a0; font-size:12px; font-weight:normal; }
  .scores { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:14px; }
  .scores .tile { text-align:left; }
  ol.top li { margin-bottom:6px; }
  footer { color:var(--muted); font-size:13px; padding:24px 16px;
           text-align:center; }
  @media print {
    body { background:#fff; }
    section.card, .tile { box-shadow:none; border:1px solid #ccc;
                          page-break-inside:avoid; }
    a { color:var(--ink); text-decoration:none; }
  }
"""



def _credit_html(element_id: str) -> str:
    """Credit the tool, not the report: anyone may run it for their own
    clients. The URL is printed as the link text because links do not open
    in a sandboxed viewer or on paper."""
    shown = CREDIT_URL.removeprefix("https://")
    return (f"<span id='{element_id}'>Made with the Google Workspace Security "
            f"Audit by {CREDIT_NAME}: <a href='{CREDIT_URL}'>{shown}</a></span>")


def _evidence_table(finding: Finding, show_changes: bool = False) -> str:
    if not finding.evidence:
        return ""
    # Union of keys, not row 0's: evidence built from different joins (the
    # at-risk composite, the delegation map) can carry different columns.
    headers = list(dict.fromkeys(k for r in finding.evidence for k in r))
    # Within a finding that was also there last month, mark the rows that
    # were not, so the reader sees who is new rather than a bare count.
    marked = show_changes and finding.change == "persisting"
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    if marked:
        head += "<th>This month</th>"
    body = ""
    for row in finding.evidence:
        cells = "".join(f"<td>{escape(str(row.get(h, '')))}</td>"
                        for h in headers)
        if marked:
            new = finding.row_changes.get(_evidence_id(finding, row)) == "new"
            cells += ("<td><span class='badge new'>new</span></td>" if new
                      else "<td></td>")
        body += f"<tr>{cells}</tr>"
    more = ""
    if finding.count > len(finding.evidence):
        more = (f"<p class='more'>Showing {len(finding.evidence)} of "
                f"{finding.count} - the full list is in "
                f"<code>{escape(finding.source)}</code> in the run "
                f"directory.</p>")
    return (f"<div class='scroll'><table><thead><tr>{head}</tr></thead>"
            f"<tbody>{body}</tbody></table></div>{more}")


def _delta(now: int, before: Optional[int]) -> str:
    if before is None:
        return "first audit"
    if now == before:
        return "same as last month"
    return f"{'down' if now < before else 'up'} from {before}"


def render_html(ctx: RunContext, findings: List[Finding],
                history: Optional[Dict] = None) -> Path:
    """Write audit_report.html, findings.csv and findings_evidence.csv, after
    comparing with the previous completed run of the same customer."""
    print_header("STAGE 3 - RENDER")
    meta = ctx.manifest["meta"]
    domain = meta.get("primary_domain", "unknown domain")
    if history is None:
        history = compare_with_previous(ctx, findings, find_previous_run(ctx))
    score = posture_score(findings)
    meta["posture_score"] = score
    ctx.save()
    show_changes = bool(history["previous"])
    prev = history["prev_counts"]
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    tiles = "".join(
        f"<div class='tile' style='border-top:6px solid "
        f"{SEVERITY_COLOURS[sev]}'><div class='num'>{counts[sev]}</div>"
        f"<div class='lbl'>{sev.title()}</div><div class='delta'>"
        f"{_delta(counts[sev], prev.get(sev, 0) if show_changes else None)}"
        f"</div></div>"
        for sev in SEVERITY_ORDER)

    trend = score_trend(ctx, score)
    trend_text = " &rarr; ".join(f"{escape(d)}: {v}" for d, v in trend) \
        if len(trend) > 1 else ""
    prev_score = history["prev_score"] if show_changes else None
    scores = f"""
<div class='scores'>
  <div class='tile'><div class='num'>{score}</div>
  <div class='lbl'>Posture score (out of 100)</div>
  <div class='delta'>{_delta(score, prev_score)}. {trend_text}</div>
  <div class='delta'>Findings cost {SCORE_WEIGHTS['CRITICAL']} (critical),
  {SCORE_WEIGHTS['HIGH']} (high) or {SCORE_WEIGHTS['MEDIUM']} (medium) points;
  every {SCORE_HALF_POINTS} points halves the score. Google has no score of
  its own, so this one is calculated from the findings below.</div></div>
</div>"""

    top = [f for f in findings if f.severity != "INFO"][:5]
    top_items = "".join(
        f"<li><strong>{escape(f.title)}</strong>. "
        f"{escape(f.remediation.split('. ')[0].rstrip('.'))}.</li>"
        for f in top)
    top_block = (f"<section class='card'><h3>Top actions</h3>"
                 f"<ol class='top'>{top_items}</ol></section>") if top else ""

    like_for_like = ""
    if show_changes and history["not_compared"]:
        like_for_like = (
            f"<p class='note'>{len(history['not_compared'])} finding(s) could "
            "not be compared with the last run because their data was not "
            "fully collected in one of the two runs, so the changes on the "
            "tiles and the score are not like for like. See \"What changed\" "
            "below.</p>")

    changed = ""
    if show_changes:
        resolved = "".join(
            f"<li>{escape(r.get('title', r.get('id', '')))} "
            f"<span class='note'>({escape(r.get('severity', ''))})</span></li>"
            for r in history["resolved"])
        new = "".join(
            f"<li>{escape(f.title)} <span class='note'>({f.severity})</span>"
            "</li>" for f in history["new"] if f.severity != "INFO")
        changed = f"""
<section class='card'>
  <h3>What changed since {escape(history['previous'])}</h3>
  <p><strong>Resolved:</strong></p><ul>{resolved or '<li>none</li>'}</ul>
  <p><strong>New:</strong></p><ul>{new or '<li>none</li>'}</ul>
  <p class='note'>{len(history['persisting'])} finding(s) carried over;
  {history['resolved_rows']} item(s) within them were fixed (accounts, files
  or settings no longer listed). {len(history['not_compared'])} could not be
  compared because their data was missing or only partly collected in one of
  the two runs, or the earlier run predates comparison.</p>
</section>"""

    def card(finding: Finding) -> str:
        badge = ""
        if show_changes and finding.change == "new":
            badge = "<span class='badge new'>new this month</span>"
        elif show_changes and finding.change == "persisting":
            badge = "<span class='badge'>also last month</span>"
        return f"""
<section class='card'>
  <h3><span class='sev' style='background:{SEVERITY_COLOURS[finding.severity]}'>
  {finding.severity}</span> {escape(finding.title)}{badge}
  <code class='fid'>{escape(finding.fid)}</code></h3>
  <p><strong>What this means:</strong> {escape(finding.meaning)}</p>
  <p><strong>What to do:</strong> {escape(finding.remediation)}</p>
  {_evidence_table(finding, show_changes)}
</section>"""

    sections = "".join(card(f) for f in findings)
    upgrades = upgrade_opportunities(ctx)
    upgrade_block = ""
    if upgrades:
        upgrade_rows = "".join(
            f"<tr><td>{escape(u['Protection'])}</td><td>{escape(u['Needs'])}"
            f"</td><td>{escape(u['Why it matters'])}</td></tr>"
            for u in upgrades)
        upgrade_block = f"""
<section class='card'>
  <h3>Upgrade opportunities</h3>
  <p>These protections are not part of the current licences, so they are
  neither checked nor counted against the score.</p>
  <div class='scroll'><table><thead><tr><th>Protection</th><th>Needs</th>
  <th>Why it matters</th></tr></thead><tbody>{upgrade_rows}</tbody></table>
  </div>
</section>"""

    # Preflight appendix.
    preflight_rows = "".join(
        f"<tr><td>{escape(r[0])}</td><td>{escape(r[1])}</td>"
        f"<td>{escape(r[2])}</td></tr>"
        for r in ctx.manifest.get("preflight", []))

    # Modules that did not produce complete data are ALWAYS listed - a reader
    # must be able to tell "checked and clean" from "not checked", and a
    # partial module from a module that returned nothing at all.
    not_checked = ""
    unscanned = meta.get("unscanned_shared_drives", [])
    for key, entry in sorted(ctx.manifest["modules"].items()):
        # The Shared Drive row below names each drive; this one would repeat it.
        if key == "shareddrive_external" and unscanned:
            continue
        if entry["status"] in ("skipped", "error", "partial"):
            title = MODULE_BY_KEY.get(key, {}).get("title", key)
            note = entry.get("note", "")
            rows_n = entry.get("rows", 0)
            # A partial module WAS checked over the rows it did return; say so
            # and name the CSV, otherwise this table reads as "not audited".
            if entry["status"] == "partial" and rows_n:
                note = (f"{rows_n} row(s) collected and checked "
                        f"({key}.csv); {note}")
            not_checked += (f"<tr><td>{escape(title)}</td>"
                            f"<td>{escape(entry['status'])}</td>"
                            f"<td>{escape(note)}</td></tr>")
    clean_block = ""
    if ctx.clean_checks:
        clean_rows = "".join(
            f"<tr><td>{escape(title)}</td><td>{escape(mods)}</td></tr>"
            for title, mods in ctx.clean_checks)
        clean_block = f"""
<section class='card'>
  <h3>Checked and clean</h3>
  <p>These checks ran over collected data and raised nothing. A check
  absent from both this list and the findings above had no data to look at;
  the coverage gaps below say why.</p>
  <div class='scroll'><table><thead><tr><th>Check</th><th>Data read</th>
  </tr></thead><tbody>{clean_rows}</tbody></table></div>
</section>"""

    if unscanned:
        not_checked += (
            f"<tr><td>Shared Drive external scan</td><td>partial</td>"
            f"<td>{escape('; '.join(unscanned))}</td></tr>")
    not_checked_block = ""
    if not_checked:
        not_checked_block = f"""
<section class='card'>
  <h3>Coverage gaps</h3>
  <p>These areas were not fully audited on this run, for the reason given.
  <strong>skipped</strong> and <strong>error</strong> mean no data at all -
  absence from the findings above does not mean they are clean.
  <strong>partial</strong> means the rows that did come back were collected
  and checked, and the raw rows are in the run folder's CSV; only the users
  named in the reason were missed.</p>
  <div class='scroll'><table><thead><tr><th>Area</th><th>Status</th>
  <th>Reason</th></tr></thead><tbody>{not_checked}</tbody></table></div>
</section>"""

    # DNS appendix with per-domain deep links.
    dns_block = ""
    dns_path = ctx.run_dir / "dns.json"
    if dns_path.is_file():
        try:
            dns_data = json.loads(dns_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            dns_data = {}
        rows = ""
        for dom, entry in dns_data.items():
            path = entry.get("path", "tamingdns")
            checks = entry.get("checks", {})
            summary = []
            for name in TAMINGDNS_TOOL_LINKS:
                value = checks.get(name)
                if value is None:
                    summary.append(f"{name.upper()}: not checked")
                elif "error" in (value or {}):
                    summary.append(f"{name.upper()}: check failed")
                elif "present" in value:
                    summary.append(
                        f"{name.upper()}: "
                        f"{'present' if value['present'] else 'MISSING'}")
                else:
                    grade = value.get("grade") or value.get("status") or "see dns.json"
                    summary.append(f"{name.upper()}: {grade}")
            links = " | ".join(
                f"<a href='https://tamingdns.com/{tool}?domain="
                f"{urllib.parse.quote(dom, safe='')}'>"
                f"{tool.upper()}</a>" for tool in TAMINGDNS_TOOL_LINKS)
            rows += (f"<tr><td>{escape(dom)}</td>"
                     f"<td>{escape(', '.join(summary))}</td>"
                     f"<td>{escape(path)}</td><td>{links}</td></tr>")
        if rows:
            dns_block = f"""
<section class='card'>
  <h3>Mail DNS per domain</h3>
  <p>Checked via tamingdns.com where available (full detail in
  <code>dns.json</code>); "doh" means the fallback path ran with
  presence-only checks.</p>
  <div class='scroll'><table><thead><tr><th>Domain</th><th>Summary</th>
  <th>Checked via</th><th>Re-check</th></tr></thead>
  <tbody>{rows}</tbody></table></div>
</section>"""

    # From the manifest, not the flags: a --render-only re-run carries no
    # --include-suspended and would otherwise describe a sweep it did not do.
    included_suspended = meta.get("include_suspended",
                                  bool(ctx.args.include_suspended))
    coverage_note = ("Suspended users were included in the per-user checks."
                     if included_suspended else
                     "Per-user checks (mail settings, calendars, Drive "
                     "sharing) cover ACTIVE users only; suspended accounts "
                     "were not swept.")
    if ctx.module_status("mydrive_external") in ("ok", "empty", "partial"):
        coverage_note += (" Drive: the full file scan ran, so external "
                          "sharing covers every file, not only recent changes.")
    elif ctx.module_status("report_drive_sharing") in ("ok", "empty"):
        coverage_note += (" Drive: only sharing changes from the last "
                          f"{ACTIVITY_DAYS} days were read (audit log); "
                          "older shares are not in this report.")
    no_service = sorted({u for e in ctx.manifest["modules"].values()
                         if e.get("note", "").startswith(NO_SERVICE_NOTE)
                         for u in e["note"][len(NO_SERVICE_NOTE):].split(", ")
                         if u})
    if no_service:
        coverage_note += (" Accounts with Gmail, Drive or Calendar switched "
                          "off had nothing to read for that service: "
                          f"{', '.join(no_service)}.")
    not_applicable = sorted(
        MODULE_BY_KEY.get(k, {}).get("title", k)
        for k, e in ctx.manifest["modules"].items() if e["status"] == "n/a")
    if not_applicable:
        coverage_note += (" Not applicable to this tenant (no Education "
                          f"licence): {', '.join(not_applicable)}.")
    bg_seen = meta.get("break_glass_seen") or []
    if bg_seen:
        coverage_note += (" Emergency (break-glass) accounts excluded from the "
                          "dormancy checks as configured: "
                          f"{', '.join(sorted(bg_seen))}.")
    never_skipped = ctx.manifest["meta"].get("skipped_never_logged_in", 0)
    if never_skipped:
        coverage_note += (f" {never_skipped} account(s) that have never "
                          "signed in were excluded from those checks "
                          "(--skip-never-logged-in).")

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Workspace Audit - {escape(domain)}</title>
<style>{STYLE}</style>
</head>
<body>
<header class='page'><div class='inner'>
  <h1>Google Workspace Audit - {escape(domain)}</h1>
  <p>Customer {escape(meta.get('customer_id', '?'))} &middot;
     collected {escape(meta.get('collected_at', 'unknown'))} &middot;
     rendered {datetime.now().strftime('%Y-%m-%d %H:%M')} &middot;
     tenant_scope.py v{SCRIPT_VERSION} (read-only audit)</p>
  <p>{_credit_html("osh-credit-head")}</p>
</div></header>
<div class='wrap'>
  <div class='tiles'>{tiles}</div>
  {like_for_like}
  {scores}
  {top_block}
  <section class='card'>
    <h3>How to read this report</h3>
    <p>Findings are ordered by severity. Each one says what was found, why
    it matters, and what to do about it, with a sample of the affected
    items; full lists sit in the CSV files next to this report.
    {escape(coverage_note)}</p>
  </section>
  {changed}
  {sections}
  {upgrade_block}
  {dns_block}
  {clean_block}
  {not_checked_block}
  <section class='card'>
    <h3>Preflight checks</h3>
    <div class='scroll'><table><thead>
    <tr><th>Check</th><th>Result</th><th>Consequence</th></tr></thead>
    <tbody>{preflight_rows}</tbody></table></div>
  </section>
</div>
<footer>{_credit_html("osh-credit-foot")}. tenant_scope.py
v{SCRIPT_VERSION}. Print this page for a PDF copy.
</footer>
</body>
</html>"""
    out_path = ctx.run_dir / "audit_report.html"
    out_path.write_text(html, encoding="utf-8")
    print_success(f"Report written: {out_path}")
    findings_csv = ctx.run_dir / "findings.csv"
    with open(findings_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["severity", "id", "title", "count", "source",
                         "change", "modules"])
        for finding in findings:
            writer.writerow([finding.severity, finding.fid, finding.title,
                             finding.count, finding.source, finding.change,
                             ";".join(finding.modules)])
    print_success(f"Findings CSV written: {findings_csv}")
    evidence_csv = ctx.run_dir / "findings_evidence.csv"
    evidence_rows = []
    for finding in findings:
        for row in finding.all_evidence:
            eid = _evidence_id(finding, row)
            evidence_rows.append(dict(
                {"id": finding.fid, "severity": finding.severity,
                 "evidence_id": eid,
                 "change": finding.row_changes.get(eid, finding.change)},
                **row))
    write_rows(evidence_csv, evidence_rows)
    print_success(f"Evidence CSV written: {evidence_csv}")
    return out_path


###############################################################################
# DELIVERY GATE AND INTERNAL QA REPORT
###############################################################################

def delivery_gate(ctx: RunContext) -> Tuple[bool, List[str]]:
    """Whether the report can go to the client without a person reading it
    first, and if not, why. Same rules as m365_scope.py."""
    reasons = []
    if not ctx.manifest["meta"].get("complete"):
        reasons.append("the run did not finish")
    broken = [k for k in DELIVERY_CRITICAL_MODULES
              if ctx.module_status(k) in ("error", "partial", "skipped")]
    if broken:
        reasons.append("modules behind critical checks did not complete: "
                       + ", ".join(broken))
    if ctx.check_errors:
        reasons.append("checks did not run: " + ", ".join(ctx.check_errors))
    stale = ctx.manifest["meta"].get("temp_grant_cleanup_failed", [])
    if stale:
        reasons.append(
            "temporary organizer grant NOT removed from: "
            + "; ".join(f"{e['drive']} ({e['id']}) for {e['admin']}"
                        for e in stale)
            + ". Remove that admin from each drive's members in the Admin "
            "console (Apps > Google Workspace > Drive and Docs > Manage "
            "shared drives).")
    return not reasons, reasons


def exit_code(ctx: RunContext) -> int:
    """0 complete, 2 complete but some modules could not run, 130 stopped.
    1 (preflight failed) is returned before anything is collected."""
    if shutdown_requested or not ctx.manifest["meta"].get("complete", True):
        return 130
    if (ctx.check_errors
            or ctx.manifest["meta"].get("temp_grant_cleanup_failed")
            or any(e.get("status") in ("error", "partial", "skipped")
                   for e in ctx.manifest["modules"].values())):
        return 2
    return 0


def render_qa(ctx: RunContext, history: Dict,
              gate: Tuple[bool, List[str]]) -> Path:
    """qa_report.html: the delivery verdict and run detail for whoever sends
    the report. Never sent to the client."""
    meta = ctx.manifest["meta"]
    ok, reasons = gate
    verdict = ("<p style='color:#27ae60'><strong>Ready to send.</strong></p>"
               if ok else
               "<p style='color:#c0392b'><strong>Hold for review:</strong>"
               "</p><ul>" + "".join(f"<li>{escape(r)}</li>" for r in reasons)
               + "</ul>")
    mods = "".join(
        f"<tr><td>{escape(k)}</td><td>{escape(e.get('status', ''))}</td>"
        f"<td>{e.get('rows', '')}</td><td>{escape(e.get('note', ''))}</td>"
        "</tr>" for k, e in sorted(ctx.manifest["modules"].items()))
    domain = meta.get("primary_domain", "")
    html = f"""<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>QA - {escape(domain)}</title><style>{STYLE}</style></head>
<body><header class='page'><div class='inner'>
<h1>Internal QA: {escape(meta.get('tenant_name') or domain)}</h1>
<p>Never send this file to the client. Run {escape(ctx.run_dir.name)}
&middot; customer {escape(meta.get('customer_id', '?'))}</p>
</div></header><div class='wrap'>
<h2>Delivery gate</h2><section class='card'>{verdict}</section>
<h2>Comparison</h2><section class='card'><p>Previous run:
{escape(str(history.get('previous') or 'none'))}; new
{len(history.get('new', []))}, persisting {len(history.get('persisting', []))},
resolved {len(history.get('resolved', []))}, not compared
{len(history.get('not_compared', []))}.</p></section>
<h2>Modules</h2><section class='card'><div class='scroll'><table><thead><tr>
<th>Module</th><th>Status</th><th>Rows</th><th>Note</th></tr></thead>
<tbody>{mods}</tbody></table></div></section>
</div></body></html>"""
    out = ctx.run_dir / "qa_report.html"
    out.write_text(html, encoding="utf-8")
    print_success(f"QA report written: {out}")
    return out


def finish(ctx: RunContext) -> Tuple[int, Path]:
    """check, compare, render both reports; returns (exit code, report)."""
    findings = run_checks(ctx)
    history = compare_with_previous(ctx, findings, find_previous_run(ctx))
    report = render_html(ctx, findings, history)
    gate = delivery_gate(ctx)
    ctx.manifest["meta"]["delivery_ready"] = gate[0]
    ctx.save()
    render_qa(ctx, history, gate)
    if gate[0]:
        print_success("Delivery gate: ready to send.")
    else:
        print_warning("Delivery gate: hold for review ("
                      + "; ".join(gate[1]) + "). See qa_report.html.")
    worst = next((f.severity for f in findings
                  if f.severity in ("CRITICAL", "HIGH")), None)
    if worst:
        print_warning(f"Highest severity found: {worst}. "
                      "Open audit_report.html for the detail.")
    else:
        print_success("No critical or high findings. "
                      "Open audit_report.html for the full picture.")
    return exit_code(ctx), report


###############################################################################
# CLI / MAIN
###############################################################################

def _tier_list(value: str) -> List[int]:
    try:
        return [int(t) for t in value.split(",") if t.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError(f"tiers are numbers: {value!r}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only Google Workspace tenant audit "
                    f"(v{SCRIPT_VERSION}). Collects tenant data via GAM7, "
                    "runs a findings engine, renders a client-readable HTML "
                    "report.")
    parser.add_argument("--admin", help="Auditing admin email; used for the "
                        "service-account scope check and the Shared Drive "
                        "scans")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Root folder for run directories "
                        f"(default {OUTPUT_DIRECTORY})")
    parser.add_argument("--run-dir", type=Path, default=None,
                        help="Existing run directory to resume (completed "
                        "modules are skipped)")
    parser.add_argument("--list", action="store_true",
                        help="List the module registry and exit")
    parser.add_argument("--only", help="Comma-separated module keys to run "
                        "(everything else skipped)")
    parser.add_argument("--skip", help="Comma-separated module keys to skip")
    parser.add_argument("--skip-tier", type=_tier_list, default=[],
                        help="Comma-separated tiers to skip, e.g. --skip-tier 3")
    parser.add_argument("--full", action="store_true",
                        help="Include the tier-4 modules (vacation, "
                        "browsers, context-aware access, Gmail profile "
                        "sizes, Drive file counts)")
    parser.add_argument("--no-dns", action="store_true",
                        help="Skip the DNS module")
    parser.add_argument("--include-suspended", action="store_true",
                        help="Include suspended users in the per-user "
                        "modules (default: active users only, stated in the "
                        "report)")
    parser.add_argument("--grant-temp-access", action="store_true",
                        help="THE ONE WRITE: for a Shared Drive none of its "
                        "members can list, temporarily add --admin as "
                        "organizer, scan, then remove the grant. Without "
                        "this, those drives are reported UNSCANNED.")
    parser.add_argument("--tenants", type=Path, default=None,
                        help="tenants.json naming each client's GAM config "
                        "folder, customer ID and break-glass accounts "
                        "(default ~/.osh/workspace-audit/tenants.json)")
    parser.add_argument("--tenant", help="Audit this tenant key from "
                        "tenants.json")
    parser.add_argument("--all", action="store_true",
                        help="Audit every enabled tenant in tenants.json, one "
                        "after another; one tenant failing does not stop the "
                        "rest, and the exit code is the worst of them")
    parser.add_argument("--compare-with", type=Path, default=None,
                        help="Run directory to compare with (default: the "
                        "newest completed earlier run of the same customer "
                        "in the same output folder)")
    parser.add_argument("--render-only", action="store_true",
                        help="Skip collection; re-run checks and render from "
                        "an existing --run-dir")
    parser.add_argument("--skip-never-logged-in", action="store_true",
                        help="Exclude accounts that have never signed in from "
                        "the per-user scans (big tenants carrying thousands "
                        "of placeholder accounts); coverage is stated in the "
                        "report")
    parser.add_argument("--no-open", action="store_true",
                        help="Do not open the finished report in a browser "
                        "(for headless or scheduled runs)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print every GAM command without executing")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the interactive tenant confirmation "
                        "(the tenant identity is still logged)")
    args = parser.parse_args(argv)
    if args.render_only and not args.run_dir:
        # Without this the branch renders a fresh, empty directory: zero
        # findings, no coverage table, exit 0 - the one report that says
        # nothing was checked and reads as clean.
        parser.error("--render-only needs --run-dir")
    if args.grant_temp_access and not args.admin:
        parser.error("--grant-temp-access needs --admin")
    if args.tenant and args.all:
        parser.error("--tenant and --all are alternatives")
    if args.all and (args.run_dir or args.compare_with):
        parser.error("--run-dir and --compare-with name one tenant's runs; "
                     "use --tenant with them")
    args.tenant_entry = None
    return args


def list_modules():
    print(f"tenant_scope.py v{SCRIPT_VERSION} - module registry\n")
    for tier in (1, 2, 3, 4):
        print(f"Tier {tier}:")
        for mod in MODULES:
            if mod["tier"] == tier and mod["key"] != "dns":
                flags = []
                if mod.get("scopes"):
                    flags.append("DWD")
                if mod["tier"] == 4:
                    flags.append("--full only")
                suffix = f"  [{', '.join(flags)}]" if flags else ""
                print(f"  {mod['key']:<24} {mod['title']}{suffix}")
        print()
    print("DNS:")
    print(f"  {'dns':<24} Mail DNS (MX/SPF/DKIM/DMARC) via tamingdns.com, "
          "dns.google fallback")


def open_report(path: Path, args) -> bool:
    """Open the finished report in the default browser.

    A file:// URI, not the bare path: on Linux webbrowser hands a bare path to
    the browser as a relative URL and it 404s. as_uri() needs an absolute
    path, and the default output directory is relative, so resolve first.
    """
    if args.no_open:
        return False
    try:
        opened = webbrowser.open(path.resolve().as_uri())
    except Exception as exc:                       # headless box, no browser
        print_warning(f"Could not open the report automatically: {exc}")
        return False
    if not opened:
        # webbrowser returns False rather than raising when no browser exists.
        print_warning(f"No browser found; open the report by hand: {path}")
    return opened


class ConfigError(Exception):
    pass


def load_tenants(path: Path) -> Dict[str, Dict]:
    """tenants.json -> {key: entry}. Each entry needs the customer ID the
    run must find (the hard stop against auditing the wrong tenant); the GAM
    config folder, name and break-glass list are optional."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read {path}: {exc}")
    tenants = {}
    for key, entry in (data.get("tenants") or {}).items():
        if not entry.get("customer_id"):
            raise ConfigError(f"tenants.{key} has no customer_id")
        entry = dict(entry, key=key)
        entry.setdefault("name", key)
        entry.setdefault("enabled", True)
        entry["break_glass"] = [u.lower() for u in entry.get("break_glass", [])]
        if entry.get("gamcfgdir"):
            entry["gamcfgdir"] = str(Path(entry["gamcfgdir"]).expanduser())
        tenants[key] = entry
    return tenants


def run_tenant(args, tenant: Optional[Dict]) -> int:
    """One audit, start to finish; returns its exit code. With a tenant from
    tenants.json, GAM runs against that tenant's config folder (GAMCFGDIR)
    and its runs live under <output-dir>/<tenant key>/ so each tenant's
    history stays separate."""
    args.tenant_entry = tenant
    if tenant and tenant.get("gamcfgdir"):
        os.environ["GAMCFGDIR"] = tenant["gamcfgdir"]
    if args.run_dir:
        run_dir = args.run_dir
        if not run_dir.is_dir():
            print(f"Run directory not found: {run_dir}")
            return 1
    else:
        root = args.output_dir or OUTPUT_DIRECTORY
        if tenant:
            root = root / tenant["key"]
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = root / f"tenant_audit_{stamp}"
        run_dir.mkdir(parents=True, exist_ok=True)

    setup_logging(run_dir)
    print_header(f"TENANT SCOPING AUDIT v{SCRIPT_VERSION}"
                 + (f": {tenant['name']}" if tenant else ""))
    print_info(f"Run directory: {run_dir}")

    ctx = RunContext(run_dir, args)
    if tenant:
        ctx.manifest["meta"].update(tenant_key=tenant["key"],
                                    tenant_name=tenant["name"],
                                    break_glass=tenant["break_glass"])
    modules = selected_modules(args)

    if args.render_only:
        code, report = finish(ctx)
        open_report(report, args)
        return code

    if not preflight(ctx, modules):
        print_error("Preflight failed; nothing was collected.")
        return 1

    collect(ctx, modules)
    if args.dry_run:
        print_info("Dry run complete - no data collected, no report rendered.")
        return 0
    # Only a run that collected every selected module is a baseline for next
    # month's comparison; set before rendering so a re-render keeps it.
    ctx.manifest["meta"]["complete"] = not shutdown_requested
    ctx.save()
    code, report = finish(ctx)
    if shutdown_requested:
        # A stopped run still renders what it has, but a scheduled --yes run
        # must be able to tell "complete" from "stopped at module 3".
        print_warning("Run was interrupted; the report covers the modules "
                      f"collected so far. Resume with --run-dir {run_dir}")
    open_report(report, args)
    return code


def main(argv=None):
    args = parse_args(argv)
    if args.list:
        list_modules()
        return 0
    if not args.render_only:
        check_for_updates()
    if not (args.tenant or args.all):
        return run_tenant(args, None)

    path = args.tenants or next(
        (c for c in TENANTS_FILE_CANDIDATES if c.is_file()), None)
    if not path:
        print("No tenants.json found. Copy tenants.example.json to "
              "~/.osh/workspace-audit/tenants.json and fill it in, or pass "
              "--tenants.")
        return 1
    try:
        tenants = load_tenants(path)
    except ConfigError as exc:
        print(f"Configuration error: {exc}")
        return 1
    if args.all:
        chosen = [t for t in tenants.values() if t["enabled"]]
    elif args.tenant in tenants:
        chosen = [tenants[args.tenant]]
    else:
        print(f"Tenant '{args.tenant}' is not in {path}. "
              f"Known: {', '.join(sorted(tenants))}")
        return 1
    worst = 0
    saved_cfg = os.environ.get("GAMCFGDIR")
    for tenant in chosen:
        if shutdown_requested:
            break
        try:
            code = run_tenant(args, tenant)
        except Exception as exc:            # one tenant must not stop the rest
            print_error(f"{tenant['key']}: {type(exc).__name__}: {exc}")
            code = 1
        finally:
            # Never let one tenant's GAM config leak into the next.
            if saved_cfg is None:
                os.environ.pop("GAMCFGDIR", None)
            else:
                os.environ["GAMCFGDIR"] = saved_cfg
        if EXIT_PRIORITY.index(code if code in EXIT_PRIORITY else 1) \
                > EXIT_PRIORITY.index(worst):
            worst = code
    return worst


if __name__ == "__main__":
    sys.exit(main())
