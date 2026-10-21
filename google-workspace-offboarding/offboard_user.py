#!/usr/bin/env python3
"""
Google Workspace User Offboarding Script
=============================================================================
Copyright (c) 2026 Paul Ogier, Outsource House (South Africa)
Website: https://osh.co.za | Email: support@osh.co.za
Training provided by Taming.Tech (https://taming.tech)

Google Workspace GAM7 Course on Udemy   https://taming.tech/GAMCourse
Google Workspace Admin Course on Udemy  https://www.taming.tech/GoogleWorkspaceAdmin
Google Workspace End-User Course on Udemy  https://www.taming.tech/TheCompleteWorkspaceCourse

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
This software has been tested in production environments; however, it is
provided "AS IS", without warranty of any kind, express or implied.

The authors (Paul Ogier, Outsource House) and training providers (Taming.Tech)
accept NO RESPONSIBILITY for any damages, data loss, or system issues that
may arise from its use. This exclusion applies regardless of whether the
issue results from defects in the script logic or from user error during
execution (e.g., misconfiguration).

YOU ASSUME ALL RISK ASSOCIATED WITH THE USE OF THIS SOFTWARE.
=============================================================================

Author:       Paul Ogier
Created:      2023-06-22
Updated:      2026-10-21
Version:      5.7.2
Status:       Production
Python:       3.8+
Dependencies: GAM ADV X (GAM7), GYB (optional), rclone (optional)

Verified against GAM7 wiki as of May 2026.
Safe-by-default (DRY RUN), summary-driven, production-friendly.

Features:
- Cross-platform (Windows/macOS/Linux) using Python subprocess
- Robust CSV parsing for GAM outputs (no shell pipelines)
- Clear CLI flags for all operations
- Pre-flight snapshot of user state before changes (audit trail)
- Email backup and migration via GYB with Migrated/<user> labelling
- Drive transfer with organised folder creation
- Drive backup via rclone (optional)
- Shared Drive DETECTION: reports drives the leaver organizes and flags any
  left with no other organizer (content is owned by the drive, not the user,
  so nothing here transfers or backs it up — it must be handled by hand)
- Device wipe and ChromeOS deprovisioning
- Vacation responder, email forwarding, mailbox delegation cleanup
- Calendar transfer / ACL wipe and signature backup
- Already-suspended user detection with optional --unsuspend
- Coloured terminal output
- Startup version check against remote VERSION file (toggleable)

Prerequisites:
- GAM ADV X (GAM7) installed and in PATH (or full path set in CONFIGURATION)
- (Optional) GYB installed for email migration
- (Optional) rclone configured with a Google Drive remote for Drive backup

IMPORTANCE LEGEND:
  [CRITICAL]    - Must execute for security; failure needs immediate attention
  [IMPORTANT]   - Strongly recommended; skip only with good reason
  [RECOMMENDED] - Best practice; safe to skip in some scenarios
  [OPTIONAL]    - Nice to have; purely convenience

Execution order rationale:
  1.  Pre-flight snapshot  - Capture state BEFORE any changes (audit trail)
  2.  Kill switch          - Containment first (OU move, deprovision, password)
  3.  Device management    - Remove mobile/ChromeOS access
  4.  Group removal        - Revoke group-based permissions
  5.  Delegate cleanup     - Remove inbound AND outbound delegates
  6.  Local backups        - Drive (rclone) and mailbox (GYB) archives, if asked for
  7.  Data transfers       - Drive, email, aliases, calendar (licence must still be active)
  8.  Shared Drive check   - Report drives the leaver organizes alone (nothing moves them)
  9.  Email forwarding     - Set up forwarding to successor
  10. Auto-reply           - Inform senders (only useful pre-suspension)
  11. Licence removal      - Free up seats (after transfers; before suspension)
  12. Suspension           - LAST, because many operations fail on suspended users

Default mode: DRY RUN (no changes made). Execution requires explicit --doit flag.

Example usage:
  python offboard_user.py                                          # Dry run
  python offboard_user.py --doit                                   # Execute
  python offboard_user.py --doit --backup-drive --backup-email     # Backup locally
  python offboard_user.py --doit --no-transfer --backup-drive      # Backup, no transfers
  python offboard_user.py --doit --force --user leaver@yourdomain.com \
      --all-transfer-to testoffboard.team@yourdomain.com                              # Non-interactive, one destination
  python offboard_user.py --doit --force --user leaver@yourdomain.com \
      --all-transfer-to testoffboard.team@yourdomain.com \
      --drive-to testoffboard.manager@yourdomain.com                                  # Split: Drive -> manager, rest -> team
  python offboard_user.py --doit --force --scorched-earth          # DELETE user
  python offboard_user.py --help

Transfer destination precedence (Drive, Email, Alias, Calendar, Forward):
  1. Phase-specific flag (--drive-to, --email-to, --alias-to,
     --calendar-to, --forward-to) -- highest priority
  2. --all-transfer-to (fallback default for any unspecified phase)
  3. Interactive prompt (only when --force is NOT set)

  Under --force, every non-skipped transfer phase MUST resolve to a
  destination via (1) or (2), or the run aborts before any change is
  made. Use --no-drive / --no-email / --no-alias / --no-calendar /
  --no-forward to opt phases out of the requirement.

Cross-platform notes:
- Windows: Colours auto-disabled on legacy CMD; works in Windows Terminal
- macOS/Linux: Full colour support in any modern terminal
- Path handling uses pathlib for OS-agnostic paths
- Subprocess calls use shell=False with list args for safety
- Pipe commands use platform-aware shell detection

Changelog
  2023-06-22 - v0.1.0 - Initial commit with basic user suspension logic.
  2023-07-14 - v0.2.0 - Added basic GAM command wrappers.
  2023-08-05 - v0.3.0 - Implemented dry-run safety toggle as default.
  2023-09-12 - v0.4.0 - Added initial GYB email migration support.
  2023-10-30 - v0.5.0 - Replaced os.system with subprocess for security.
  2023-11-18 - v0.6.0 - Added logging to file and console.
  2023-12-20 - v0.7.0 - Fixed paths for Windows cross-platform compatibility.
  2024-02-15 - v1.1.0 - Implemented coloured terminal output.
  2024-03-10 - v1.2.0 - Added mobile and ChromeOS device listing.
  2024-04-22 - v1.3.0 - Added Drive transfer with organised folder creation.
  2024-05-30 - v1.4.0 - Added interactive confirmation prompts for kill switch.
  2024-07-20 - v2.0.0 - Added calendar and alias transfer features.
  2024-08-25 - v2.1.0 - Added progress timers for long-running operations.
  2024-09-30 - v2.2.0 - Added pre-flight validation for destination users.
  2024-10-28 - v3.0.0 - Updated all commands for GAM7 (GAM ADV X) compatibility.
  2024-11-15 - v3.1.0 - Refactored CSV output parsing for GAM7 format changes.
  2025-02-20 - v3.3.0 - Added vacation responder configuration.
  2025-06-10 - v3.5.0 - Added email signature (sendas) capture as part of the pre-flight snapshot.
  2025-11-05 - v3.9.0 - Updated code comments and cleaned up docstrings.
  2026-01-15 - v4.0.0 - Linked code comments to GAM7/GYB KB; reordered deployment for better logic.
  2026-03-08 - v4.1.0 - Added pre-flight snapshot, email forwarding, mailbox delegation, calendar transfer/ACL wipe, --force, --log-dir, exit codes, signal handling, and resilient try/except per phase.
  2026-04-22 - v4.2.0 - Added rclone Drive backup (--backup-drive), already-suspended detection (--unsuspend), GYB backup-only mode (--backup-email).
  2026-05-06 - v4.3.0 - GYB restore applies Migrated/<source-user> label; mailbox/Drive backups moved to dedicated subdirs; fixed calendar ACL syntax (calendaracl -> calendaracls, user <email> -> user:<email>).
  2026-05-07 - v4.4.0 - Added startup version check against remote VERSION file (CHECK_FOR_UPDATES toggle, fail-silent); restored author/contact header with Outsource House copyright and three Udemy course links; aligned in-script licence reference with the repo LICENSE (Apache 2.0) and added a plain-English summary emphasising attribution retention.
  2026-05-13 - v4.5.0 - BREAKING: renamed --transfer-to to --all-transfer-to. Added per-phase destination flags (--drive-to, --email-to, --alias-to, --calendar-to, --forward-to) that override the global default; precedence is phase-specific > --all-transfer-to > interactive prompt. Added upfront destination resolution and validation before any phase runs: under --force, any non-skipped phase without a resolvable destination aborts the run with a clear error instead of half-offboarding.
  2026-05-14 - v4.6.0 - Added end-of-run MANUAL ACTION block surfacing admin-console instructions for durable mail capture (alias / recipient address map / group) since GAM cannot configure recipient address map and Gmail-level forwarding stops on suspension/deletion; new --forward-alias-to flag explicitly nominates the successor printed in the block (falls back to --forward-to then --all-transfer-to), no automated change is made. Guide gains a "Mail capture after suspension" section and the order-of-operations list flags forwarding's suspension limitation.
  2026-10-21 - v5.7.2 - Scorched earth no longer deletes the account when the
                        Shared Drive list cannot be read or parsed; it refuses
                        (exit 2), as it already did for an unreadable drive ACL.
                        A --user given as an alias is resolved to its primary
                        address before any change, so the commands that run
                        after the alias moves no longer reach the successor.
                        A missing or unreadable GYB message database fails
                        backup verification instead of passing as an empty
                        backup, and the check no longer creates the file. The
                        update check reads the GoogleWorkspaceScripts
                        repository. 243 tests.
  2026-09-30 - v5.7.1 - Repository folder renamed from "OffBoarding Google
                        Workspace Users" to google-workspace-offboarding; the
                        startup update check now reads VERSION from the new
                        path. A VERSION copy stays at the old path so earlier
                        releases keep checking. No functional change.
  2026-09-02 - v5.7.0 - Top-to-bottom audit round (docs/2026-09-02-audit-offboard-user.md).
                        CTRL+C SAFETY: every gam call refused to run once Ctrl+C had
                        set the shutdown flag, so the atexit re-suspend guard could
                        never re-suspend (it slept 90s and printed EMERGENCY with the
                        account still active), and a Ctrl+C between kill-switch steps
                        left the user moved to the unenforced OU with their password
                        intact and sessions alive, then exited before the forced
                        suspension. The kill switch, the containment-failure suspend
                        and the guard now run to completion regardless (bypass_shutdown);
                        the restore retry loop and the read-back polls stop promptly
                        instead. HONEST SUMMARY: "Re-suspended (restored original
                        state)" was recorded whether or not the re-suspend verified;
                        a failed `print groups` or device query was reported as "no
                        groups"/"no devices" and the removal skipped; a short GYB
                        backup was restored anyway and reported "Email migrated". All
                        three are now errors, and the migration line carries GYB's
                        resume-DB count against the files on disk. FLAG CONFLICTS are
                        usage errors instead of silent overrides: --scorched-earth with
                        a backup, transfer, --unsuspend or --no-suspend flag;
                        --reuse-email-backup without --email-to or with --no-email;
                        --restore-batch-size 1. Scorched earth keeps the pre-flight
                        snapshot (read-only, the last record of the account). The
                        skipped-messages CSV is always appended (a retry's re-scan
                        truncated the rows the crash-directed pass had written).
                        SPEED: licences are read from the `Licenses:` block that the
                        snapshot's `gam info user` already returns (the separate
                        `print licenses` listed every licence in the tenant, 23s on a
                        50-user tenant); the snapshot's six reads, the two device
                        queries and the three dependency probes run in parallel; the
                        four transfer phases no longer re-validate a destination the
                        preflight already checked; the Drive trash count queries
                        `trashed = true` instead of listing the whole Drive twice.
                        Pre-flight snapshot 40s -> 8s; a full live offboarding of a
                        small account 3m38s on Linux, 3m04s on Windows. STRUCTURE: one
                        streaming reader for GYB, rclone and the Drive transfer; one
                        parser for `info user quick`; one backup-folder picker; one
                        skipped-messages recorder; the restore loop's decision is a
                        pure function; main() is split into main() and
                        run_offboarding() with a phase runner, and an integration
                        suite (test_offboard_main.py) now drives it end to end. Signal
                        handlers and colour detection moved out of import time. Phase
                        headers are un-numbered. Dead: the Python 3.7 check, the
                        stderr-stripping in remove_groups, the inert base non-fatal
                        patterns, the PyYAML mention. Test fixtures are captured GAM
                        7.48.01 output (fixtures/), and the unit suite no longer
                        reaches a real gam binary (two tests did).
  2026-08-31 - v5.6.1 - Scorched earth now refuses when a Shared Drive's membership
                        could not be read, not only when the leaver is its confirmed
                        sole organizer (the other half of issue #9). An unread ACL is
                        reported as unknown, and unknown no longer counts as permission
                        to delete.
  2026-08-31 - v5.6.0 - Closes issues #11 and #9. A Drive backup short by real files
                        now fails the run and holds licence removal; Forms and Sites,
                        which cannot be exported, are an accepted gap. Scorched earth
                        is gated on the Shared Drive check, which runs before the kill
                        switch; --allow-orphaned-shared-drives overrides. Suspension
                        verification waits up to 120s (measured 54s after the kill
                        switch's burst of writes). `print shareddrives` exit 60 on an
                        empty result is no longer a failed read. The migration label
                        is reported as `_Migrated/<user>`, the name GYB creates.
  2026-08-05 - v5.5.0 - Full-script audit round: five silent-swallow fixes and three
                        preflight/runtime improvements.
                        INTERACTIVE DESTINATION GUARDS: destinations typed at the plan
                        prompts now get the same checks as flag-supplied ones — the
                        leaver's own address or alias is refused (self-restore /
                        mail loop), and an email destination without a usable Gmail
                        mailbox is refused BEFORE the multi-hour download.
                        BACKUP VERIFICATION: --backup-email now reconciles msg-db
                        against the .eml files on disk (it never did); a shortfall is
                        classified first — messages in the sibling _quarantined/
                        folder are deliberate exclusions, and only a shortfall beyond
                        those is an error. A genuine shortfall in either backup path
                        is now a summary ERROR, so licence removal is held and the
                        Gmail access a re-download needs survives (was: warning, then
                        "Email migrated" + licences removed on top of a short backup).
                        DRIVE EXIT 56 ZERO MOVED: exit 56 with no per-file transfer
                        confirmations is no longer reported as benign skips — either
                        every item failed or the source owned nothing; the operator is
                        told to verify and licence removal is held.
                        RE-SUSPEND CRASH GUARD: the atexit re-suspend guard is now
                        registered even under --no-suspend; only a run that reaches
                        the suspension phase normally waives it. A crash or Ctrl+C
                        mid-run can no longer leave a previously-suspended account
                        silently active.
                        DISK-SPACE PREFLIGHT: before a GYB download, the mailbox size
                        (estimated from GAM's storage fields) is compared with free
                        space on the backup volume — larger than free aborts, over 80%
                        warns. A 100 GB mailbox no longer fills the disk overnight.
                        ONE DOWNLOAD, TWO PURPOSES: --backup-email plus an email
                        migration in the same run no longer downloads the mailbox
                        twice; the migration's retained backup serves as the archive.
                        DRIVE BACKUP RESUME: --backup-drive re-runs now offer to sync
                        into the newest prior backup folder (rclone only fetches
                        new/changed files), mirroring v5.4.0's mailbox resume,
                        same 30-day --force cap.
                        TERMINAL FAIL-FAST: a restore refused with a terminal
                        400-class error (failedPrecondition, invalid_grant, Mail
                        service not enabled) with nothing restored stops after
                        attempt 1 instead of burning stall-bail-out attempts,
                        each of which re-scanned the whole corpus for quarantine
                        (2026-08-03 dev-round lesson). Throttle markers still
                        retry with batch step-down as before.
  2026-08-03 - v5.4.0 - Admin-account gate (Gavin-X, PR #26 / issue #10): offboarding a user
                        who still holds Super Admin or delegated-admin roles now aborts
                        before any mutation with the exact gam commands to list and remove
                        the role assignments; --allow-admin-account is the deliberate
                        override, and --force does NOT imply it. Plus four field fixes from
                        a client production run and the 2026-08-03 dev round:
                        EMAIL DESTINATION MAILBOX: preflight now probes the email
                        destination's gmailprofile and aborts if Gmail is not enabled —
                        previously an unlicensed destination passed validation and the
                        restore failed with "Mail service not enabled" only AFTER the full
                        mailbox download (hours on a real leaver). The equivalent check in
                        check_restore_destination_ready() also fired only when gam exited 0,
                        but gam exits 73 for mailbox-less users; it now matches the output
                        text regardless of exit status. BACKUP RESUME: the mailbox backup
                        folder is date-stamped, so a re-run on a later day minted a fresh
                        folder and re-downloaded the entire mailbox; when a prior backup
                        folder exists the script now offers to resume into it (interactive
                        prompt showing its age; under --force it auto-resumes folders up
                        to 30 days old and starts fresh beyond that, since an older folder
                        is likely a previous engagement whose restore would resurrect
                        long-deleted mail).
                        DRIVE EXIT 56: gam's transfer drive exits 56 when files the source
                        could access but not own were skipped; that was reported as a hard
                        failure and blocked licence removal behind a transfer that lost
                        nothing (a week on one client ticket) — now a warning naming the count
                        moved, with a verify instruction. HONEST ATTEMPT COUNT: a restore
                        failure summary reported the 20-attempt ceiling even when the stall
                        bail-out stopped after 3; it now reports the attempts actually run.
  2026-07-29 - v5.3.0 - Three state-safety defects reported by Gavin-X (issues #2, #3, #5),
                        all in the same shape: the run ended in a state nobody could see.
                        SUSPENSION STATE: destinations are now validated BEFORE the temporary
                        unsuspend, so a preflight abort can no longer leave an account that
                        started suspended sitting active; the unsuspend itself is verified by
                        read-back (GAM has reported suspension updates that had not taken
                        effect) and an atexit guard re-suspends on every remaining exit path,
                        including an unhandled exception. --unsuspend with --no-suspend is now
                        refused at parse time: they ask for opposite end states.
                        FAILED TRANSFERS: a failed backup or transfer holds licence removal
                        back, because removing the licence kills the Gmail and Drive access the
                        retry needs. Suspension still runs — containment is not the thing worth
                        deferring. No override flag: a skip flag mixable into any combination
                        is a worse trap than the one it removes, and one gam command removes a
                        licence by hand once the data is confirmed safe.
                        CONTAINMENT: execute_kill_switch() returns what it actually achieved
                        instead of returning nothing. A failed password scramble or an
                        unconfirmed sign-out is now a summary ERROR, and it overrides
                        --no-suspend: an account that could not be locked is not left active.
                        Also removed run_shell_pipe(), dead since the alias rewrite and
                        carrying shell=True, and the unread originally_suspended.
  2026-07-28 - v5.2.0 - Restore hardening, from a full test round against a live dev tenant
                        using a 190GB real-world mailbox corpus. DESTINATION PRE-FLIGHT: a
                        restore into a SUSPENDED mailbox fails with a generic backendError that
                        is indistinguishable from rate limiting in the log — GYB backs off up
                        to 60s per attempt, 10 attempts per batch, then gives up quietly, so
                        the run can burn hours and report nothing useful. validate_destination
                        now matches the "Account Suspended: True" FIELD rather than any line
                        containing both words (a user surnamed "Suspended" was a false
                        positive) and fails the phase with an explanatory error. New
                        check_restore_destination_ready() also warns when the backup is larger
                        than the tenant's free POOLED storage, and when the backup contains
                        messages with no usable Date header — Gmail re-stamps those with the
                        restore date, so years-old mail arrives looking new (11 of 170,888 on
                        the migration this was found on; caused by the sender, not fixable in
                        GYB). CRASH-DIRECTED QUARANTINE: new quarantine_gyb_locked_file()
                        parses the .eml path out of GYB's own PermissionError traceback instead
                        of re-scanning the backup after a crash. AV locking is
                        non-deterministic, so a post-crash re-scan races the scanner and often
                        finds the poison file readable — observed live, where one such file
                        killed four consecutive retry attempts. The traceback names the culprit
                        exactly. A named file that reads cleanly now is deliberately LEFT in
                        place (transient block, not a quarantine). RETRY LOOP:
                        MAX_RESTORE_ATTEMPTS 5 -> 20 (poison files cluster; five was observed
                        to be too few), with an early bail-out after three consecutive attempts
                        that neither restore anything nor find anything to quarantine, so a
                        hard failure no longer burns the whole budget in silence. Progress is
                        now measured from GYB's resume DB rather than its stdout, which freezes
                        for long stretches in the tail phase of a large mailbox. THROTTLING
                        LADDER: on a throttling-shaped failure the restore steps its batch size
                        down 100 -> 75 -> 50 -> 25 -> 10, never below 10 (at --batch-size 1 GYB
                        switches to a path that never commits the resume DB mid-run, so a crash
                        at 99% restarts from message 1). An AV crash deliberately does NOT step
                        the ladder. REPORTING: run_gyb gains suppress_summary_error, mirroring
                        run_gam, so recovered intermediate attempts stay out of the end-of-run
                        summary — previously a run that succeeded on attempt 5 finished
                        reporting "Errors (4)" beside its success line and read as a failure.
                        DRIVE COMPLETENESS: rclone exits 0 on an incomplete backup, so
                        verify_drive_backup_complete() now reconciles GAM's file count against
                        the files on disk. Drive is not a filesystem — two files may share a
                        name in one folder, and when both export to the same extension the
                        second overwrites the first ("Untitled document" is the commonest
                        filename there). Forms and Sites cannot be exported at all and are not
                        even listed, and a file owned by the user but parented only in someone
                        else's folder is outside the tree rclone walks. The check names all
                        three causes and reports the leaver's TRASH separately, since rclone
                        does not fetch it and deleting the account destroys it. The comparison
                        queries "trashed = false" and reads GAM's own LAST "Got N" line: it
                        prints one per page, so the first is a page size, not a file count —
                        parsing it that way made a 106-file shortfall read as verified.
                        SHARED DRIVES: check_shared_drives() reports every drive the leaver
                        organizes and escalates the ones with no other organizer, which nothing
                        in an offboarding transfers or backs up. A membership read that FAILS
                        is reported as unknown rather than as proof of sole organizership.
                        SELF-TRANSFER: preflight_destinations() refuses a destination that
                        resolves to the leaver, including via one of their aliases. 2SV: the
                        enforced refusal (GAM exit 50, "required by admin policy") is now
                        recognised. It aborts nothing else in the deprovision bundle — tokens,
                        app passwords, backup codes, sign-out and POP/IMAP all complete — so
                        the run reports containment done and explains that removing the OU
                        policy, not retrying, is what changes the outcome. The plan no longer
                        predicts that refusal from the enforcement flag: enforcement follows
                        the OU and the kill switch moves the user first, so the prediction was
                        made against the OU being left.
  2026-07-22 - v5.1.0 - Configurable backup location + restore that survives AV-locked
                        messages. NEW --backup-dir PATH sets the root for all backup
                        artefacts (snapshots, mailbox, Drive); the BACKUP_DIRECTORY constant
                        can also be edited for a permanent default. Point it OUTSIDE a synced
                        folder (iCloud/Dropbox/Drive): a mailbox backup can be hundreds of GB
                        and a synced folder re-uploads all of it every run. RESTORE
                        AUTO-RECOVERY: endpoint AV can lock a malicious .eml at any moment,
                        non-deterministically (a file can read fine then raise PermissionError
                        moments later), killing GYB mid-restore; one clean pre-scan cannot
                        guarantee a clean restore. The restore now retries (up to 5x),
                        re-quarantining whatever is unreadable on each failure. This is safe
                        because GYB does not de-duplicate but Gmail's servers do — re-importing
                        the same message leaves one copy (GYB maintainer, discussion #446) — so
                        messages already restored before a crash collapse to a single copy on
                        the next pass. NEW --reuse-email-backup PATH restores from an existing
                        GYB backup folder and skips the download, running ONLY the email
                        restore (no containment / transfers / suspension) — use it to resume a
                        restore that died partway without re-downloading a large mailbox. The
                        real root-cause fix remains an on-access-scan exclusion for the backup
                        folder in the endpoint AV policy. RESTORE SPEED + RESUME: the restore
                        now passes --batch-size (default 50, --restore-batch-size to override).
                        GYB defaults restore batch_size to 1, which uploads every message as
                        its own request (serial, days for a large mailbox) AND only commits the
                        resume DB at the end of the run, so any crash restarts from message 1.
                        Batching messages <=1MB makes the restore many times faster and commits
                        the resume DB per batch, so a crash resumes instead of restarting
                        (verified against gyb.py restore source, lines ~2333/2399/2446).
  2026-07-13 - v5.0.0 - Reporting/verification hardening (11 findings, all fixed and
                        regression-tested; every phase live-verified on a dev tenant, with a
                        permanent offline unit-test suite in test_offboard_user.py).
                        BEHAVIOUR CHANGE: --force no longer implies --unsuspend (see below).
                        Failed GAM commands are no longer reported as completed actions:
                        suspend_user, delete_user, kill-switch steps 2/4/6/7 (recovery-info
                        wipe, signout, password scramble, GAL hide), transfer_calendar and
                        set_auto_reply now check the command result before recording success
                        (same bug class as the v4.7.0 migrate_email fix, applied to all
                        remaining callers). Forwarding-address verification now matches the
                        'accepted' status on the target address's own output line, so an
                        unrelated already-accepted forwarding address can no longer
                        false-positive the check; poll failures no longer add one summary
                        error per attempt. --force no longer implies --unsuspend: an
                        already-suspended user is only temporarily unsuspended when the
                        explicit --unsuspend flag is given (interactive prompt unchanged
                        without --force). Fixed pre-logging crash when stdin is closed at
                        the initial user prompt (clean exit 2 instead of a traceback).
                        Licence labels no longer whitespace-split multi-word display names
                        ("Cloud Identity" was rendered as "Cloud (skuId)"); with multiple
                        licences the labels fall back to skuIds. Dry runs no longer create
                        backup directories. Snapshot embeds SCRIPT_VERSION instead of a
                        hardcoded version string. ALIAS DATA-LOSS FIX (found live on the
                        dev tenant): the alias transfer previously piped `gam print aliases`
                        into `gam csv - gam update alias ~Alias user <dest>`; GAM's update
                        alias is delete-then-insert and the insert can race Directory API
                        propagation, failing with "Duplicate" and destroying the alias,
                        while `gam csv` swallows the failure so the run reported success.
                        Aliases are now transferred one-by-one (delete, then create on the
                        destination with retry while the deletion propagates) and reported
                        per alias; any alias that cannot be recreated is a loud error with
                        the manual recovery command. Deprovision drops the popimap token
                        for mailbox-less users (Cloud Identity / Gmail-off), whose POP/IMAP
                        toggle otherwise fails the whole deprovision with exit 73. Suspension
                        is verified by read-back: GAM's 'Updated' response was observed
                        (live, dev tenant) reporting success for a suspension-state change
                        that did not take effect, so the final suspend now re-reads the
                        account state (with retries) and raises a critical error if the
                        account still reads active. Kill-switch step 5 is verify-first:
                        after deprovision already carried turnoff2sv, the explicit
                        turnoff2sv only fires if 2SV still reads enrolled (re-firing on an
                        unenrolled user produced an exit-50 false error in successful
                        runs). The dependency check's 'gam info domain' probe no longer
                        leaks transient failures into the end-of-run error list.
  2026-07-07 - v4.7.0 - Email migration hardened against AV-quarantined messages: a malicious email in the source mailbox can be quarantined on local disk by endpoint antivirus after GYB writes it during backup, and GYB's restore crashes on the unreadable file. A pre-restore scan now probes every backed-up .eml and moves unreadable ones to a sibling <backup>_quarantined/ folder so GYB's own missing-file handling skips them; skipped messages are listed (Gmail message ID + date) in <backup>_skipped-messages.csv next to the backup and flagged in the run summary. Also fixed the restore result being ignored: a failed restore now reports an error with the retained backup path instead of logging "Email migrated".

Planned Features (not yet implemented)
  - Batch processing via CSV file: accept a list of users (e.g. --csv users.csv)
    and iterate the full offboarding flow per row, with per-user logs and a
    consolidated run summary.
  - --manager shortcut flag: auto-resolve the departing user's manager (from
    the directory) as the default --all-transfer-to destination, so common
    cases do not need an explicit address.
  - --wipe-devices flag: opt-in automatic mobile account_wipe and ChromeOS
    deprovision_retiring_device actions, instead of only listing devices and
    printing manual guidance.
  - YAML configuration file support: load defaults (GAM/GYB/rclone paths,
    OFFBOARDING_OU, BACKUP_DIR, default flags) from a config.yaml so the
    CONFIGURATION constants do not need to be edited in-script.
  - JSON output mode (--json): emit a machine-readable run summary (per-phase
    status, counts, errors, paths to artefacts) for automation pipelines, in
    addition to the existing human-readable summary.
  - Dedicated signature backup: write the user's sendas/signature HTML to a
    standalone file in the backup directory (today it is only captured as a
    field inside the pre-flight JSON snapshot).
"""

import argparse
import atexit
import contextlib
import csv
import io
import subprocess
import sys
import os
import re
import json
import logging
import signal
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Dict
import shutil


###############################################################################
# CONFIGURATION SECTION [CRITICAL]
# Customise these settings for your environment before first use.
###############################################################################

# [IMPORTANT] Current local script version. Bumped on each release.
# Compared against the remote VERSION file to detect updates.
SCRIPT_VERSION = "5.7.2"

# [OPTIONAL] Check for a newer script version on startup.
# When True (default), the script makes a single 3-second HTTP request to
# fetch the remote VERSION file and warns if a newer release exists. Set to
# False to disable (e.g. for offline/air-gapped environments or to skip the
# tiny startup delay). The check is fail-silent: any network or parse error
# is ignored so it can never block an offboarding run.
CHECK_FOR_UPDATES = True

# [OPTIONAL] URL of the remote VERSION file used for update checks.
# Points to the raw VERSION file on the main branch of the public repo.
UPDATE_CHECK_URL = (
    "https://raw.githubusercontent.com/PaulOgier/GoogleWorkspaceScripts/main/"
    "google-workspace-offboarding/VERSION"
)

# [CRITICAL] The OU to move the user into during offboarding.
# This OU MUST have NO 2SV enforcement policy, otherwise the script cannot
# disable 2FA on the departing user's account. Create a dedicated OU in your
# Google Workspace admin console (e.g. /Offboarding or /Suspended Users)
# and ensure no 2SV enforcement policies are applied to it.
OFFBOARDING_OU = "/Offboarding"

# [IMPORTANT] The GAM command name or full path.
# On most systems "gam" works if GAM7 is in your PATH.
# On Windows you may need "gam.exe" or the full path, e.g.:
#   r"C:\GAM7\gam.exe"
# On macOS/Linux, the installer typically places it in ~/bin/gam7/gam
GAM_COMMAND = "gam"

# [OPTIONAL] GYB command for email migration.
# Only needed if you want to back up and restore email to another account.
# If GYB is not installed, set this to None or leave as "gyb".
GYB_COMMAND = "gyb"

# [IMPORTANT] Spam and Trash are DELIBERATELY excluded from every backup and
# migration. GYB omits both unless --spam-trash is passed, and this script
# passes neither that nor --search, so the exclusion costs no code and must not
# be "fixed" by a later cleanup pass: a leaver's spam and deleted mail should
# not land in the successor's mailbox or in the archive.
#
# The visible consequence is that the backup is SMALLER than the mailbox size
# shown in the Admin console, which counts spam and trash. Printing it up front
# means the run log answers "why is it smaller?" before anyone has to ask.
# (_estimate_mailbox_bytes reads those same GAM storage fields, so the
# disk-space preflight over-reserves rather than under-reserves. That is the
# safe direction; leave it.)
SPAM_TRASH_NOTE = (
    "Spam and Trash are excluded by design, so this backup will be smaller "
    "than the mailbox size reported in the Admin console."
)

# [IMPORTANT] Root directory for backups, snapshots, and email migration data.
# Snapshots, mailbox GYB backups and Drive downloads are all written in
# subfolders here. Default: an 'offboarding_backups' folder in the current
# working directory (i.e. next to wherever you run the script).
#
# A GYB mailbox backup can be HUNDREDS OF GIGABYTES. If this path sits inside a
# synced folder (iCloud Drive, Dropbox, Google Drive), the sync client tries to
# upload every byte on every run — slow, and it churns the cloud copy. To keep
# backups off a synced folder, either edit the line below to a local path
# (e.g. Path("~/offboarding_backups").expanduser()) or pass --backup-dir at
# run time. Override precedence: --backup-dir > this constant.
BACKUP_DIRECTORY = Path("./offboarding_backups")

# [IMPORTANT] GYB restore batch size (messages per Gmail import HTTP request).
# GYB defaults the RESTORE batch_size to 1 (gyb.py: "if options.batch_size == 0:
# options.batch_size = 1"), which has two bad consequences:
#   1. SPEED: every message — even a 12kb one — is uploaded as its own request
#      (the single-message path fires when size >1MB OR batch_size == 1), so a
#      large mailbox restores serially over days instead of hours.
#   2. RESUME: with batch_size 1 the restored-messages resume DB is only
#      committed at the END of the run (the per-batch sqlconn.commit() is never
#      reached), so a crash — e.g. an AV-locked .eml, which GYB does not catch —
#      loses ALL progress and the restore restarts from message 1.
# Any value >1 batches messages <=1MB (larger ones still go singly) AND commits
# the resume DB after every batch, so a crash resumes instead of restarting.
# 50 is a safe middle; raise toward 100 for speed, drop toward 10 if Gmail
# returns rateLimitExceeded. Override per-run with --restore-batch-size.
RESTORE_BATCH_SIZE = 50

# [OPTIONAL] Auto-reply message set on the departing user's account.
# Customise this with your organisation's standard wording.
AUTO_REPLY_MESSAGE = (
    "This person is no longer with the organisation. "
    "Please contact reception for further assistance."
)

# [OPTIONAL] rclone command name or full path.
# Only needed if you want to back up Drive files locally (--backup-drive).
# rclone must be configured with a Google Drive remote that uses a service
# account for domain-wide delegation (can reuse GAM7's oauth2service.json).
RCLONE_COMMAND = "rclone"

# [OPTIONAL] rclone remote name from 'rclone config'.
# Must support --drive-impersonate for service account access.
RCLONE_REMOTE = "workspace"

# [OPTIONAL] Export formats for Google Docs/Sheets/Slides.
RCLONE_EXPORT_FORMATS = "docx,xlsx,pptx,pdf"


###############################################################################
# COLOUR CODES FOR TERMINAL OUTPUT [OPTIONAL]
# Makes output more readable. Auto-disabled on legacy Windows CMD.
###############################################################################

class Colours:
    """ANSI colour codes for terminal output.

    Uses bright (high-intensity, 90-97) variants in bold for better
    contrast on dark terminal backgrounds. The standard codes (30-37)
    render as dark navy / muddy green on most dark themes and are hard
    to read; the bright variants are the standard accessibility fix.
    """
    RED = '\033[1;91m'      # bright red, bold
    GREEN = '\033[1;92m'    # bright green, bold
    YELLOW = '\033[1;93m'   # bright yellow, bold
    BLUE = '\033[1;94m'     # bright blue, bold — readable on dark bg
    CYAN = '\033[1;96m'     # bright cyan, bold — readable [INFO] colour
    RESET = '\033[0m'

    @staticmethod
    def strip_colours():
        """Disable colours for environments that do not support ANSI codes."""
        Colours.RED = ''
        Colours.GREEN = ''
        Colours.YELLOW = ''
        Colours.BLUE = ''
        Colours.CYAN = ''
        Colours.RESET = ''


# [IMPORTANT] Auto-detect terminal colour support.
# Windows 10+ cmd.exe supports ANSI once virtual-terminal processing is
# enabled via SetConsoleMode; Windows Terminal and modern PowerShell have
# it on by default. On macOS/Linux, colours work whenever stdout is a TTY.
def _enable_windows_ansi() -> bool:
    """Enable ANSI escape processing on the current Windows console.

    Returns True if VT processing is active (or was already), False on
    older Windows where the call fails. Safe to call on non-Windows.
    """
    if os.name != 'nt':
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # STD_OUTPUT_HANDLE = -11; ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def configure_colours() -> None:
    """Strip ANSI codes where they would not render. Called from main(), not
    at import, so importing the module (the tests do) has no side effect and
    output under a test runner does not depend on whether stdout is a TTY."""
    if os.name == 'nt':
        if not (
            os.environ.get('WT_SESSION')
            or os.environ.get('TERM_PROGRAM')
            or _enable_windows_ansi()
        ):
            Colours.strip_colours()
    elif not sys.stdout.isatty():
        Colours.strip_colours()


###############################################################################
# GLOBAL STATE
###############################################################################

# Track timing per phase
phase_timings: List[Tuple[str, float]] = []

# Summary tracking
summary_actions: List[str] = []
summary_skipped: List[str] = []
summary_errors: List[str] = []
summary_warnings: List[str] = []

# Exit code: 0 clean, 1 once any summary error is recorded. Usage and
# preflight aborts exit 2 directly.
exit_code = 0

# Graceful shutdown flag
shutdown_requested = False


###############################################################################
# SIGNAL HANDLING [RECOMMENDED]
# Allows Ctrl+C to exit gracefully with a summary instead of a traceback.
###############################################################################

def signal_handler(_signum, _frame):
    global shutdown_requested
    if shutdown_requested:
        # Second Ctrl+C, force exit
        print(f"\n{Colours.RED}Forced exit.{Colours.RESET}")
        sys.exit(2)
    shutdown_requested = True
    print(f"\n{Colours.YELLOW}[WARN] Ctrl+C received. Finishing current operation, then exiting...{Colours.RESET}")
    print(f"{Colours.YELLOW}[WARN] Press Ctrl+C again to force quit immediately.{Colours.RESET}")


def install_signal_handlers() -> None:
    """Route Ctrl+C (and SIGTERM where it exists) through signal_handler.
    Called from main(): installing at import replaced unittest's own Ctrl+C
    handler in every process that imported this module."""
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)


###############################################################################
# LOGGING SETUP [IMPORTANT]
# Maintains an audit trail of all operations for compliance and debugging.
# Logs go to both console and a timestamped file.
###############################################################################

LOG_FILENAME = ""  # Set in main() after args are parsed


def _force_utf8_console():
    """Make stdout/stderr survive non-ASCII filenames.

    On Windows the console streams default to the ANSI code page (cp1252), so
    logging a Drive filename containing an emoji, CJK, or rclone's encoded
    control characters raises UnicodeEncodeError inside the logging handler.
    The logging module swallows that and the line is LOST — precisely the lines
    naming the files that went missing from a backup. Observed on Windows 11
    ARM64, 2026-07-29, on "Line one␊line two.docx". The FileHandler is
    already explicitly UTF-8, so the audit trail was never at risk; this is the
    console half. errors="replace" because a mangled glyph beats a lost line.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass  # Not a real stream (captured/piped in tests); nothing to do.


def setup_logging(log_dir: Optional[Path] = None, user_email: str = "", timestamp: str = ""):
    """Initialise logging with both file and console handlers."""
    global LOG_FILENAME

    _force_utf8_console()

    if not timestamp:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    prefix = f"{user_email}_{timestamp}" if user_email else f"offboarding_{timestamp}"
    filename = f"{prefix}.log"

    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        LOG_FILENAME = str(log_dir / filename)
    else:
        LOG_FILENAME = filename

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILENAME, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)


logger: Optional[logging.Logger] = None


###############################################################################
# SUMMARY HELPERS
###############################################################################

def summary_action(msg: str):
    summary_actions.append(msg)


def summary_skip(msg: str):
    summary_skipped.append(msg)


def summary_error(msg: str):
    global exit_code
    summary_errors.append(msg)
    if exit_code < 1:
        exit_code = 1


def summary_warning(msg: str):
    summary_warnings.append(msg)


@contextlib.contextmanager
def record_failure(phase: str, failures: List[str]):
    """Append `phase` to `failures` if it records any summary error.

    The data-moving phases report their own failures through summary_error()
    rather than a return value (some fail several files deep and keep going),
    so the growth of that list is the honest signal for "this phase lost
    something". Used to hold licence removal back after a failed transfer.
    """
    before = len(summary_errors)
    try:
        yield
    finally:
        if len(summary_errors) > before and phase not in failures:
            failures.append(phase)


###############################################################################
# DISPLAY HELPERS [OPTIONAL]
###############################################################################

def _emit(level: str, text: str):
    """Route display output through the logger, or plain print before
    setup_logging() has run (e.g. an error at the very first user prompt)."""
    if logger is None:
        print(text)
    elif level == 'error':
        logger.error(text)
    elif level == 'warning':
        logger.warning(text)
    else:
        logger.info(text)


def print_header(title: str):
    width = 60
    _emit('info', "")
    _emit('info', f"{Colours.BLUE}{'=' * width}")
    _emit('info', f"  {title}")
    _emit('info', f"{'=' * width}{Colours.RESET}")


def print_success(msg: str):
    _emit('info', f"{Colours.GREEN}[OK] {msg}{Colours.RESET}")


def print_warning(msg: str):
    _emit('warning', f"{Colours.YELLOW}[WARN] {msg}{Colours.RESET}")


def print_error(msg: str):
    _emit('error', f"{Colours.RED}[ERROR] {msg}{Colours.RESET}")


def print_info(msg: str):
    _emit('info', f"{Colours.CYAN}[INFO] {msg}{Colours.RESET}")


###############################################################################
# UPDATE CHECK [OPTIONAL]
# Fetches the remote VERSION file and warns if the local script is out of
# date. Disabled by setting CHECK_FOR_UPDATES = False in the CONFIGURATION
# section above. Fail-silent on any network or parse error.
###############################################################################

def _parse_version(value: str) -> Tuple[int, ...]:
    """Parse 'X.Y' or 'X.Y.Z' into a tuple of ints for comparison."""
    parts = []
    for piece in value.strip().split("."):
        digits = "".join(c for c in piece if c.isdigit())
        if not digits:
            raise ValueError(f"Non-numeric version segment: {piece!r}")
        parts.append(int(digits))
    if not parts:
        raise ValueError("Empty version string")
    return tuple(parts)


def check_for_updates():
    """Compare SCRIPT_VERSION against the remote VERSION file.

    Prints a warning if a newer version is available, otherwise stays quiet.
    Any error (no network, timeout, malformed response) is swallowed so the
    check can never block an offboarding run.
    """
    if not CHECK_FOR_UPDATES:
        print_info("Update check disabled (CHECK_FOR_UPDATES = False)")
        return

    try:
        # Imported lazily so disabling the check has zero import cost.
        from urllib.request import Request, urlopen
        req = Request(UPDATE_CHECK_URL, headers={"User-Agent": "offboard_user.py"})
        with urlopen(req, timeout=3) as resp:
            remote_raw = resp.read().decode("utf-8", errors="replace")
        remote_version = remote_raw.strip().splitlines()[0].strip()

        local_tuple = _parse_version(SCRIPT_VERSION)
        remote_tuple = _parse_version(remote_version)

        if remote_tuple > local_tuple:
            print_warning(
                f"A newer version is available: v{remote_version} "
                f"(you are running v{SCRIPT_VERSION})"
            )
            print_warning(
                "What changed + download: "
                "https://github.com/PaulOgier/GoogleWorkspaceScripts/releases   "
                "(git pull if you cloned; set CHECK_FOR_UPDATES = False to "
                "silence this check)"
            )
        elif remote_tuple < local_tuple:
            print_info(
                f"Running v{SCRIPT_VERSION} (remote VERSION reports v{remote_version})"
            )
        else:
            print_info(f"Script is up to date (v{SCRIPT_VERSION})")
    except Exception as exc:
        # Fail silent: never let the update check block a run.
        print_info(f"Update check skipped ({type(exc).__name__})")


###############################################################################
# PHASE TIMING [RECOMMENDED]
# Records how long each phase takes for the summary report.
###############################################################################

class PhaseTimer:
    """Context manager to time a phase and record it."""
    def __init__(self, phase_name: str):
        self.phase_name = phase_name
        self.start = 0.0

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        elapsed = time.time() - self.start
        phase_timings.append((self.phase_name, elapsed))


###############################################################################
# COMMAND EXECUTION [CRITICAL]
# All GAM/GYB commands flow through these functions for:
#   - Dry run support (shows what would happen without executing)
#   - Logging of every command and its output
#   - Error capture and reporting
#   - Graceful shutdown checking
###############################################################################

def run_gam(args: List[str], dry_run: bool = True,
            capture_output: bool = False,
            timeout: int = 300,
            non_fatal_patterns: Optional[List[str]] = None,
            stdout_only: bool = False,
            suppress_summary_error: bool = False,
            bypass_shutdown: bool = False) -> Tuple[bool, str]:
    """
    Execute a GAM command with full logging and dry-run support.

    Args:
        args: List of command arguments (GAM_COMMAND is prepended automatically)
        dry_run: If True, command is logged but not executed
        capture_output: If True, return stdout instead of printing it
        timeout: Seconds before the command is killed (default 300)
        non_fatal_patterns: Additional output substrings that should NOT be
            treated as errors (e.g. ["auto-assigned"]). Matched case-insensitively.
        suppress_summary_error: If True, a failed call does NOT record a
            summary_error entry. Use when the caller has a fallback path
            (e.g. probe-as-user, then fall back to probe-as-group) so the
            final summary doesn't list the probe failure as a real error.
        bypass_shutdown: Run even after Ctrl+C set shutdown_requested. For
            the commands that must complete once started: the kill switch,
            the containment-failure suspend and the atexit re-suspend guard.
            Without this the guard could never fire after a Ctrl+C, because
            every gam call it made returned "Shutdown requested" instead of
            running, and the account it promised to re-suspend stayed active.

    Returns:
        Tuple of (success: bool, output: str). Returns (True, output) when a
        non-fatal pattern matches so the caller can inspect output and decide.
    """
    if shutdown_requested and not bypass_shutdown:
        return False, "Shutdown requested"

    full_cmd = [GAM_COMMAND] + args
    cmd_str = " ".join(full_cmd)

    if dry_run:
        print_info(f"DRY RUN: {cmd_str}")
        return True, ""

    logger.info(f"Executing: {cmd_str}")

    try:
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8", errors="replace",
            timeout=timeout
        )

        output = result.stdout.strip()
        if not stdout_only and result.stderr.strip():
            output += "\n" + result.stderr.strip()

        if result.returncode == 0:
            if capture_output:
                return True, output
            if output:
                logger.info(output)
            return True, output
        else:
            # Callers name the outputs that are not really failures (a
            # "Got 0 Shared Drives" exit 60, an "already exists" forwarding
            # address). Every empty print/show the script runs exits 0 on
            # GAM 7.48.01, checked live 2026-09-02, so there is no base list.
            lower = output.lower()
            if any(p.lower() in lower for p in (non_fatal_patterns or [])):
                return True, output
            if suppress_summary_error:
                # Caller flagged this call as a probe with a fallback path
                # (e.g. validate_destination's user-then-group probe), so
                # downgrade the red [ERROR] lines to info to avoid alarming
                # the user about an expected failure. The output is still
                # logged so a real problem remains debuggable.
                logger.info(f"Probe failed (exit {result.returncode}): {cmd_str}")
                if output:
                    logger.info(output)
            else:
                print_error(f"Command failed (exit {result.returncode}): {cmd_str}")
                if output:
                    print_error(output)
                summary_error(f"Failed: {cmd_str}")
            return False, output

    except subprocess.TimeoutExpired:
        print_error(f"Command timed out after {timeout}s: {cmd_str}")
        if not suppress_summary_error:
            summary_error(f"Timeout: {cmd_str}")
        return False, "Timeout"
    except FileNotFoundError:
        print_error(
            f"GAM command not found: {GAM_COMMAND}. "
            f"Ensure GAM7 is installed and in your PATH."
        )
        summary_error("GAM7 not found in PATH")
        return False, "Not found"
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        summary_error(f"Exception: {e}")
        return False, str(e)


def _stream_process(cmd: List[str], on_line, env: Optional[dict] = None) -> int:
    """Run a child process and hand it every output line as it appears.

    GYB (tqdm) and rclone (-P) redraw progress with a bare carriage return,
    so a plain line iterator would show nothing until the phase ends. Reads
    in small chunks and treats both \\r and \\n as separators. Blank lines are
    dropped. On Ctrl+C the child is terminated and the exit code returned is
    whatever it died with. stdin is closed so the child can never hang on a
    prompt; no timeout, because a real backup can legitimately run for hours.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8", errors="replace",
        bufsize=1,
        env=env,
    )
    assert proc.stdout is not None
    buffer = ""
    while True:
        if shutdown_requested:
            proc.terminate()
            break
        chunk = proc.stdout.read(256)
        if not chunk:
            break
        buffer += chunk
        while True:
            idx = -1
            for sep in ("\r", "\n"):
                i = buffer.find(sep)
                if i != -1 and (idx == -1 or i < idx):
                    idx = i
            if idx == -1:
                break
            line = buffer[:idx].rstrip()
            buffer = buffer[idx + 1:]
            if line:
                on_line(line)
    if buffer.strip():
        on_line(buffer.rstrip())
    proc.wait()
    return proc.returncode


def run_gyb(args: List[str], dry_run: bool = True,
            suppress_summary_error: bool = False) -> Tuple[bool, str]:
    """
    Execute a GYB command, streaming output to the log including tqdm
    progress bars.

    suppress_summary_error mirrors run_gam's flag: when True a failed call is
    still logged and printed but does NOT record an entry in the end-of-run
    summary. Used by the restore retry loop, where an intermediate attempt
    failing is an expected, recovered event — without this, a run that
    succeeded on attempt 5 finishes reporting four errors and reads as a
    failure.

    GYB uses tqdm for progress, which writes \\r (carriage return) to
    overwrite the same line. A naive line iterator only yields on \\n,
    so progress updates would stay invisible until GYB prints a real
    newline at phase completion. We read in small chunks and treat both
    \\r and \\n as line separators, then throttle identical-prefix
    progress lines to at most one log entry per second so the log file
    isn't flooded with thousands of bar-redraw frames.

    No overall timeout: a real mailbox backup/restore can legitimately
    run for hours. stdin is closed so GYB never silently hangs waiting
    for interactive input.
    """
    if shutdown_requested:
        return False, "Shutdown requested"

    full_cmd = [GYB_COMMAND] + args + ["--service-account"]
    cmd_str = " ".join(full_cmd)

    if dry_run:
        print_info(f"DRY RUN: {cmd_str}")
        return True, ""

    logger.info(f"Executing: {cmd_str}")

    try:
        # PYTHONUNBUFFERED=1 nudges GYB's child Python to flush stdout
        # promptly so progress updates aren't held in a 4KB block buffer.
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        collected: List[str] = []
        # Throttle repeated progress lines: only log a redraw of the
        # same bar if >=1s has passed since the last identical-prefix
        # line. A bar's "prefix" is the text up to the percentage.
        last_progress_log = 0.0
        last_progress_prefix = ""

        def emit(line: str):
            nonlocal last_progress_log, last_progress_prefix
            # Is this a tqdm-style progress line? They typically contain
            # "%|" or a fraction like " 123/4567 ".
            is_progress = "%|" in line or "it/s" in line
            if is_progress:
                # Prefix = everything before the first digit-percent, used
                # to detect "same bar being redrawn".
                prefix = line.split("%", 1)[0][:40]
                now = time.time()
                if prefix == last_progress_prefix and now - last_progress_log < 1.0:
                    return
                last_progress_prefix = prefix
                last_progress_log = now
            logger.info(line)
            collected.append(line)

        returncode = _stream_process(full_cmd, emit, env=env)
        output = "\n".join(collected)

        if returncode == 0:
            return True, output
        else:
            print_error(f"GYB command failed (exit {returncode}): {cmd_str}")
            if not suppress_summary_error:
                summary_error(f"GYB failed: {cmd_str}")
            return False, output

    except FileNotFoundError:
        print_error(f"GYB command not found: {GYB_COMMAND}")
        summary_error("GYB not found in PATH")
        return False, "Not found"
    except Exception as e:
        print_error(f"GYB exception: {e}")
        summary_error(f"GYB exception: {e}")
        return False, str(e)


def run_gam_parallel(calls: Dict[str, Tuple[List[str], dict]],
                     workers: int = 4) -> Dict[str, Tuple[bool, str]]:
    """Run independent read-only gam commands side by side.

    Every gam launch costs about 2 s of process start-up before the API call
    (measured on the Linux VM, 2026-09-02), so seven sequential snapshot
    reads were 40 s of mostly waiting. Threads over run_gam are enough: the
    commands are reads, none depends on another, and run_gam's only shared
    state is the summary lists, which append atomically. Never use this for
    the kill switch, whose order is the point. Results keep the input order.
    """
    results: Dict[str, Tuple[bool, str]] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {key: pool.submit(run_gam, args, **kwargs)
                   for key, (args, kwargs) in calls.items()}
        for key in calls:
            results[key] = futures[key].result()
    return results


###############################################################################
# DEPENDENCY CHECKS [IMPORTANT]
###############################################################################

def check_dependencies(need_gyb: bool = False, need_rclone: bool = False,
                       user_email: str = "", dry_run: bool = True,
                       skip_disk_check: bool = False) -> bool:
    """
    [IMPORTANT] Check that required tools are available and authorised.

    EDGE CASE: GAM can be installed but not yet authorised (no oauth2.txt).
    We detect this by running 'gam info domain' and checking for auth errors.

    When need_gyb=True and user_email is provided, validates that the GYB
    service account can impersonate the target user via --action quota.
    """
    print_header("DEPENDENCY CHECK")

    # Check GAM7 exists in PATH
    gam_path = shutil.which(GAM_COMMAND)
    if gam_path:
        print_success(f"GAM7 found: {gam_path}")
    else:
        print_error(
            f"GAM7 not found in PATH as '{GAM_COMMAND}'. "
            f"Install from https://github.com/GAM-team/GAM"
        )
        return False

    # The three probes are independent reads, so they run side by side.
    # suppress_summary_error: each probe's failure is handled right here
    # (abort on auth errors, warn-and-continue on transient ones), so it
    # must not also land in the end-of-run error list.
    probes = run_gam_parallel({
        "version": (["version"], dict(dry_run=False, capture_output=True,
                                      suppress_summary_error=True)),
        "domain": (["info", "domain"], dict(dry_run=False, capture_output=True,
                                            timeout=30, suppress_summary_error=True)),
        "ou": (["info", "org", OFFBOARDING_OU],
               dict(dry_run=False, capture_output=True, timeout=30,
                    suppress_summary_error=True)),
    })
    success, output = probes["version"]
    if success and output:
        version_match = re.search(r'GAM\s+(\d+\.\d+\.\d+)', output)
        if version_match:
            print_success(f"GAM7 version: {version_match.group(1)}")
        else:
            print_info(f"GAM7 version output: {output.splitlines()[0]}")

    success, output = probes["domain"]
    if not success:
        if "oauth" in output.lower() or "unauthorized" in output.lower() or "credentials" in output.lower():
            print_error(
                "GAM7 is installed but does not appear to be authorised. "
                "Run 'gam oauth create' and 'gam user admin@domain.com check serviceaccount' first."
            )
            return False
        # Other errors might be transient, warn but continue
        print_warning(f"Could not verify domain info: {output.splitlines()[0] if output else 'no output'}")

    # Verify the offboarding OU exists. Without this, the kill-switch phase
    # silently degrades: GAM rejects `update user ... org /Offboarding`
    # with "Invalid Organizational Unit", the user is never moved into
    # containment, and subsequent OU-dependent steps (e.g. relaxed 2SV
    # enforcement in the offboarding OU) also fail. Catching it here lets
    # the admin create the OU or update OFFBOARDING_OU before any change.
    ou_ok, ou_output = probes["ou"]
    if ou_ok:
        print_success(f"Offboarding OU exists: {OFFBOARDING_OU}")
    else:
        print_error(
            f"Offboarding OU '{OFFBOARDING_OU}' does not exist or is not "
            f"accessible. GAM output: "
            f"{ou_output.splitlines()[0] if ou_output else 'no output'}"
        )
        # Show concrete remediation steps so the admin doesn't have to
        # leave the terminal to fix this. Green = actionable next steps.
        ou_name = OFFBOARDING_OU.lstrip("/")
        print_success("To create the offboarding OU, choose one of:")
        print_success(f"  [GAM]  gam create org \"{ou_name}\" "
                      f"description \"Offboarded users\" parent /")
        print_success("  [Admin Console]  https://admin.google.com/ac/orgunits  "
                      "-> Create organizational unit -> "
                      f"Name: \"{ou_name}\", Parent: /")
        print_success(
            f"Alternatively, edit OFFBOARDING_OU near the top of "
            f"offboard_user.py to point at an existing OU."
        )
        return False

    # Check GYB if needed
    if need_gyb:
        gyb_path = shutil.which(GYB_COMMAND)
        if not gyb_path:
            print_error(
                f"GYB not found in PATH as '{GYB_COMMAND}'. Install it, set "
                f"GYB_COMMAND, or skip email with --no-email."
            )
            return False
        print_success(f"GYB found: {gyb_path}")

        # Validate GYB service account can impersonate the target user
        if user_email:
            print_info(f"Verifying GYB service account access for {user_email}...")
            try:
                result = subprocess.run(
                    [GYB_COMMAND, "--email", user_email, "--action", "quota",
                     "--service-account"],
                    capture_output=True, text=True,
                    encoding="utf-8", errors="replace",
                    stdin=subprocess.DEVNULL, timeout=30
                )
                output = (result.stdout + result.stderr).strip()
                if result.returncode == 0:
                    print_success("GYB service account authorised")
                else:
                    print_error(
                        f"GYB service account cannot access {user_email}. "
                        f"Ensure domain-wide delegation is configured for the "
                        f"GYB service account with the Gmail API scope. "
                        f"Output: {output.splitlines()[0] if output else 'no output'}"
                    )
                    return False
            except subprocess.TimeoutExpired:
                print_error("GYB service account check timed out (30s). "
                            "Check service account configuration.")
                return False
            except Exception as e:
                print_error(f"GYB service account check failed: {e}")
                return False

            # A mailbox backup that outgrows the disk dies hours into an
            # overnight run — the one failure class cheaper to catch here
            # than to resume from. Estimate Gmail bytes from GAM's storage
            # fields and compare with free space on the backup volume.
            # Skipped in restore-only mode: nothing is downloaded there, and
            # a disk that is nearly full BECAUSE the backup is already on it
            # must not block its own restore.
            est = None if skip_disk_check else _estimate_mailbox_bytes(user_email)
            if est is not None:
                probe = BACKUP_DIRECTORY
                while not probe.exists() and probe.parent != probe:
                    probe = probe.parent
                free = shutil.disk_usage(probe).free
                gb = 1024 ** 3
                print_info(
                    f"Mailbox size (estimated): {est / gb:.1f} GB; free on "
                    f"backup volume: {free / gb:.1f} GB."
                )
                if est > free:
                    print_error(
                        f"The mailbox (~{est / gb:.1f} GB) is larger than the "
                        f"free space on the backup volume ({free / gb:.1f} GB "
                        f"at {probe}). The GYB backup WILL fill the disk part "
                        f"way through. Free up space or point --backup-dir at "
                        f"a bigger volume."
                    )
                    return False
                if est > free * 0.8:
                    print_warning(
                        f"The mailbox (~{est / gb:.1f} GB) would use over 80% "
                        f"of the backup volume's free space "
                        f"({free / gb:.1f} GB). Consider a bigger volume "
                        f"before starting a long download."
                    )


    # Check rclone if needed
    if need_rclone:
        rclone_path = shutil.which(RCLONE_COMMAND)
        if rclone_path:
            print_success(f"rclone found: {rclone_path}")
            try:
                result = subprocess.run(
                    [RCLONE_COMMAND, "listremotes"],
                    capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=10
                )
                if result.returncode == 0:
                    remotes = result.stdout.strip().split('\n')
                    if f"{RCLONE_REMOTE}:" in remotes:
                        print_success(f"rclone remote \'{RCLONE_REMOTE}\' configured")
                    else:
                        print_error(
                            f"rclone remote \'{RCLONE_REMOTE}\' not found. "
                            f"Available: {', '.join(remotes)}. "
                            f"Run \'rclone config\' or update RCLONE_REMOTE."
                        )
                        return False
            except Exception as e:
                print_warning(f"Could not verify rclone remotes: {e}")
        else:
            print_error(
                f"rclone not found in PATH. "
                f"Install from https://rclone.org/ or remove --backup-drive."
            )
            return False

    if dry_run:
        # The snapshot still writes here in a dry run (that is its point);
        # everything else waits for --doit.
        print_info(f"Backup directory: {BACKUP_DIRECTORY.resolve()} (snapshot only in dry run)")
        return True
    try:
        BACKUP_DIRECTORY.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print_error(f"Cannot create backup directory {BACKUP_DIRECTORY}: {e}")
        return False
    print_success(f"Backup directory: {BACKUP_DIRECTORY.resolve()}")
    return True


###############################################################################
# DESTINATION VALIDATION [IMPORTANT]
# Resolves every transfer destination up front (phase-specific flag >
# --all-transfer-to > interactive prompt) and verifies each against the
# directory before anything changes.
###############################################################################

def preflight_destinations(args, source: Optional[str] = None) -> Dict[str, Optional[str]]:
    """Resolve destinations for every transfer phase and validate them up front.

    Under --force, any non-skipped phase without a destination is a fatal error
    (we cannot fall back to an interactive prompt in non-interactive mode and
    silent skipping would leave the offboarding half-done). Every unique
    resolved destination is checked against the directory via
    validate_destination() so we fail before any destructive action.

    Returns a dict mapping phase name to the resolved email (or None if the
    phase has no destination and will be resolved interactively later).
    """
    phases = {
        "drive":    (args.no_drive,    args.drive_to),
        "email":    (args.no_email,    args.email_to),
        "alias":    (args.no_alias,    args.alias_to),
        "calendar": (args.no_calendar, args.calendar_to),
        "forward":  (args.no_forward,  args.forward_to),
    }

    resolved: Dict[str, Optional[str]] = {}
    missing: List[str] = []
    for name, (skipped, specific) in phases.items():
        if skipped:
            resolved[name] = None
            continue
        dest = specific or args.all_transfer_to
        resolved[name] = dest
        if args.force and not dest:
            missing.append(name)

    if missing:
        print_error("--force requires a destination for every non-skipped phase.")
        print_error(f"Missing destinations for: {', '.join(missing)}")
        print_error(
            "Fix by adding --all-transfer-to <email>, a specific "
            "--<phase>-to <email>, or skipping with --no-<phase>."
        )
        sys.exit(2)

    # A destination equal to the source is always an operator error — picking
    # the leaver twice from a list, or a copy-paste. Nothing downstream catches
    # it: the plan reads normally, GYB would restore the mailbox into itself
    # under new labels, forwarding to self is a loop, and the account is
    # suspended at the end regardless. Refuse rather than execute nonsense.
    # An ALIAS of the leaver is a different address resolving to the same
    # mailbox, so a literal comparison misses it — and the alias is the more
    # plausible mis-pick, being the address the operator was just looking at.
    if source and any(resolved.values()):
        same_account = {source.lower()} | {a.lower() for a in _list_aliases(source)}
        self_targeted = sorted({n for n, d in resolved.items()
                                if d and d.lower() in same_account})
        if self_targeted:
            named = sorted({resolved[n] for n in self_targeted})  # type: ignore[misc]
            print_error(
                f"Destination is the same account being offboarded "
                f"({source}, via {', '.join(named)}) for: "
                f"{', '.join(self_targeted)}."
            )
            print_error(
                "Transferring a leaver's data to themselves does nothing, "
                "forwarding to self is a mail loop, and the account is "
                "suspended at the end anyway. Name a different successor."
            )
            sys.exit(2)

    # Only the forward phase may target a group address; all other phases
    # require a real user account (Drive/Email/Alias/Calendar transfers
    # cannot be received by a group).
    if resolved:
        print_info("Validating transfer destinations...")
        seen: Dict[str, bool] = {}
        for name, dest in resolved.items():
            if not dest:
                continue
            allow_group = (name == "forward")
            cache_key = f"{dest}|{allow_group}"
            if cache_key in seen:
                continue
            if not validate_destination(dest, allow_group=allow_group):
                print_error(f"Destination validation failed: {dest}")
                sys.exit(2)
            seen[cache_key] = True

    # The email destination needs an actual MAILBOX, not just a directory
    # entry: GYB restores into an unlicensed (Cloud Identity) user fail every
    # batch with "Mail service not enabled" — and without this check that only
    # surfaces AFTER the full mailbox download, which on a real leaver is
    # hours.
    email_dest = resolved.get("email")
    if email_dest:
        reason = _email_mailbox_missing(email_dest)
        if reason:
            print_error(
                f"Email destination {email_dest} has no usable Gmail mailbox "
                f"({reason}). The mailbox restore would fail after the full "
                f"backup download. Assign a Workspace licence and wait for "
                f"the mailbox to provision, or skip with --no-email."
            )
            sys.exit(2)

    return resolved


def _email_mailbox_missing(email: str) -> Optional[str]:
    """Return why `email` cannot receive a GYB restore, or None if it can.

    The probe is `show gmailprofile`, matched on its OUTPUT TEXT, not its
    exit status: for a settled unlicensed user gam FAILS (exit 73) with
    "Gmail Service/App not enabled" in the output, so gating on success made
    the check a no-op. Verified live on dev 2026-08-03.

    Known blind spot, also verified live: for the first minutes after a user
    is CREATED, gmailprofile (and even `gyb --action quota`) succeed for an
    unlicensed user, and `info user`'s "Mailbox is setup" field is no help —
    it stays False on licensed, provably restorable mailboxes. A brand-new
    unlicensed destination therefore slips this preflight; it is still
    caught by the same check re-run at restore time, after the download,
    when the state has settled.
    """
    _, profile = run_gam(["user", email, "show", "gmailprofile"],
                         dry_run=False, capture_output=True, timeout=60,
                         suppress_summary_error=True)
    if "not enabled" in profile.lower():
        return "Gmail service not enabled"
    return None


def validate_destination(email: str, allow_group: bool = False) -> bool:
    """
    Check that a destination exists and is active.

    When allow_group is True, a Google Group address is also accepted
    (used for email-forwarding destinations, which Gmail allows to point
    at a same-domain group).
    """
    # Probe as user first. Suppress summary_error so a not-a-user response
    # doesn't surface as a real error when the group fallback succeeds, or
    # when the caller is just probing.
    fields = _user_quick_fields(email)
    if fields is not None:
        if fields.get("account suspended", "").lower() == "true":
                print_error(
                    f"Destination user {email} is SUSPENDED. A restore into a "
                    f"suspended mailbox fails with a generic 'backendError' that "
                    f"looks exactly like rate limiting in the log, and GYB will "
                    f"retry it for minutes per batch before giving up quietly. "
                    f"Unsuspend the account first."
                )
                return False
        return True

    if allow_group:
        ok_group, _ = run_gam(
            ["info", "group", email],
            dry_run=False,
            capture_output=True,
            timeout=30,
            suppress_summary_error=True,
        )
        if ok_group:
            print_info(f"Destination {email} is a group — accepted for forwarding.")
            return True

    # No fallback worked — this is now a genuine error worth reporting.
    print_error(f"Destination user not found: {email}")
    summary_error(f"Destination not found: {email}")
    return False


###############################################################################
# USER VERIFICATION [CRITICAL]
###############################################################################

def verify_user(email: str) -> Optional[Dict[str, str]]:
    """
    [CRITICAL] Verify the user exists and display their current status.
    Returns a dict with user info on success, None on failure.
    """
    print_header("USER VERIFICATION")

    user_info = _user_quick_fields(email)
    if user_info is None:
        print_error(f"User not found or not accessible: {email}")
        summary_error(f"User verification failed for {email}")
        return None

    # Display user summary
    print_info(f"User: {email}")
    print_info(f"Full Name: {user_info.get('full name', '?')}")
    print_info(f"Suspended: {user_info.get('account suspended', '?')}")
    print_info(f"OU: {user_info.get('google org unit path', '?')}")
    print_info(f"Last Login: {user_info.get('last login time', '?')}")
    print_info(f"2SV Enrolled: {user_info.get('2-step enrolled', '?')}")
    print_info(f"2SV Enforced: {user_info.get('2-step enforced', '?')}")

    # EDGE CASE: Already suspended user
    is_suspended = user_info.get('account suspended', '').lower() == 'true'
    if is_suspended:
        print_warning(
            "User is ALREADY SUSPENDED. The following operations will fail "
            "on suspended users: deprovision (backup codes), turnoff2sv, "
            "delegate setup, email forwarding, auto-reply. "
            "Consider unsuspending first, running offboarding, then re-suspending."
        )
        summary_warning("User was already suspended at start of offboarding")

    # Admin roles are reported and gated by enforce_admin_account_gate().
    is_admin = user_info.get('is a super admin', '').lower() == 'true' or \
               user_info.get('is delegated admin', '').lower() == 'true'

    user_info['_is_suspended'] = str(is_suspended)
    user_info['_is_admin'] = str(is_admin)

    return user_info


class AdminAccountSafetyError(RuntimeError):
    """Raised when offboarding is attempted while admin roles remain."""


def enforce_admin_account_gate(email: str, user_info: Dict[str, str],
                               allow_admin_account: bool) -> None:
    """Refuse to offboard a privileged account without a deliberate override."""
    if user_info.get('_is_admin', 'False') != 'True':
        return

    print_error(
        "ADMIN ACCOUNT SAFETY HOLD: this user still has Google Workspace "
        "administrator privileges. No offboarding changes have been made."
    )
    print_error(
        "List every assigned role and its roleAssignmentId, remove each role, "
        "then rerun offboarding:\n"
        f"    gam print admins user {email}\n"
        "    gam delete admin <roleAssignmentId>"
    )

    if allow_admin_account:
        message = (
            "Admin account safety hold OVERRIDDEN by --allow-admin-account; "
            "administrator roles will NOT be revoked by this script"
        )
        print_warning(message)
        summary_warning(message)
        return

    raise AdminAccountSafetyError(
        "User still has administrator privileges; offboarding blocked. "
        "Remove all role assignments or rerun with --allow-admin-account."
    )


###############################################################################
# INTERACTIVE PROMPTS [RECOMMENDED]
###############################################################################

def prompt_yes_no(question: str, default: bool = False, force: bool = False) -> bool:
    """Ask a yes/no question. In --force mode, returns True always."""
    if force:
        print_info(f"{question} -> auto-yes (--force)")
        return True
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        try:
            answer = input(f"{Colours.YELLOW}{question}{suffix}{Colours.RESET}").strip().lower()
        except EOFError:
            # EDGE CASE: stdin is not a terminal (piped input)
            return default
        if answer == '':
            return default
        if answer in ('y', 'yes'):
            return True
        if answer in ('n', 'no'):
            return False
        print("Please enter 'y' or 'n'.")


def decide_unsuspend(force: bool, unsuspend_flag: bool, prompt_fn) -> bool:
    """Decide whether to temporarily unsuspend an already-suspended user.

    Under --force the explicit --unsuspend flag is the ONLY way to opt in:
    a non-interactive run must never silently reactivate a suspended
    account (the account then continues through limited offboarding, with
    suspension-dependent steps failing loudly). Without --force, the flag
    short-circuits and otherwise the operator is asked via prompt_fn.
    """
    if force:
        return unsuspend_flag
    return unsuspend_flag or prompt_fn()


def _user_quick_fields(email: str, bypass_shutdown: bool = False) -> Optional[Dict[str, str]]:
    """Run `gam info user <email> quick` and return its fields as a dict.

    Keys are the lower-cased field names ("account suspended", "2-step
    enrolled", "mailbox is setup", ...), values the text after the colon.
    One parser for every caller that needs a field out of that output:
    matching the FIELD, never a substring, because a user surnamed
    "Suspended" exists on the dev tenant and defeats a naive `in` test.
    None when the read fails.
    """
    ok, output = run_gam(
        ["info", "user", email, "quick"],
        dry_run=False,
        capture_output=True,
        timeout=30,
        suppress_summary_error=True,
        bypass_shutdown=bypass_shutdown,
    )
    if not ok:
        return None
    fields: Dict[str, str] = {}
    for line in output.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip().lower()] = value.strip()
    return fields


def read_suspended(email: str, bypass_shutdown: bool = False) -> Optional[bool]:
    """Read the account's actual suspension state; None if the read fails."""
    fields = _user_quick_fields(email, bypass_shutdown=bypass_shutdown)
    if fields is None or "account suspended" not in fields:
        return None
    return fields["account suspended"].lower() == "true"


def wait_for_suspended(email: str, expected: bool, timeout: int = 60,
                       poll_interval: int = 5, bypass_shutdown: bool = False) -> bool:
    """Poll until the directory agrees the account is/is not suspended.

    GAM has been observed reporting a successful suspension update that had not
    taken effect, so a state change we depend on is read back rather than
    trusted. Returns False if the state never matches within `timeout`, or as
    soon as Ctrl+C is pressed unless bypass_shutdown says the wait must finish.
    """
    deadline = time.time() + timeout
    while True:
        if read_suspended(email, bypass_shutdown=bypass_shutdown) is expected:
            return True
        if time.time() >= deadline:
            return False
        if shutdown_requested and not bypass_shutdown:
            return False
        time.sleep(poll_interval)


# Set (only) when a --no-suspend run reaches its suspension phase normally:
# from that point, leaving the account active is the operator's stated intent
# (reported loudly as a contract violation), so the atexit guard must stand
# down. Every OTHER exit path — crash, Ctrl+C, preflight abort — leaves this
# False and the guard re-suspends, --no-suspend or not: a run that died
# half-way made no informed decision to leave a suspended account active.
no_suspend_contract_waived = False


def restore_original_suspension(email: str, attempts: int = 3) -> bool:
    """Re-suspend an account this run temporarily unsuspended.

    Registered with atexit once the temporary unsuspend is verified, so the
    account is restored on EVERY exit path — a preflight abort, an unhandled
    exception, or a normal finish (where it is a verified no-op because the
    suspension phase already ran). The one stand-down: a --no-suspend run
    that completed normally (see no_suspend_contract_waived).
    """
    if no_suspend_contract_waived:
        return True
    # bypass_shutdown everywhere in here: this guard mostly runs AFTER a
    # Ctrl+C, and a gam call that refuses to run once shutdown_requested is
    # set would turn the guard into 90 seconds of sleeping followed by a
    # false EMERGENCY, with the account still active.
    if read_suspended(email, bypass_shutdown=True) is True:
        return True

    print_warning(f"Restoring original suspended state for {email} before exit...")
    for attempt in range(1, attempts + 1):
        run_gam(
            ["update", "user", email, "suspended", "on"],
            dry_run=False,
            capture_output=True,
            suppress_summary_error=True,
            bypass_shutdown=True,
        )
        # 60s per attempt: right after the kill switch's burst of directory
        # writes the flip took 54s to read back (dev, 2026-08-31 and again
        # 2026-09-02), so a 30s window failed attempt 1 on a suspend that
        # had worked.
        if wait_for_suspended(email, True, timeout=60, bypass_shutdown=True):
            print_success("Original suspended state restored and verified.")
            return True
        print_warning(f"Re-suspension attempt {attempt}/{attempts} was not verified.")

    print_error(
        f"EMERGENCY: {email} started suspended, was temporarily unsuspended by "
        f"this run, and could NOT be re-suspended. Suspend it manually now."
    )
    summary_error(f"Original suspension state NOT restored for {email}")
    return False


def prompt_email(question: str, force_value: Optional[str] = None) -> str:
    """Ask for an email address with basic validation."""
    if force_value:
        return force_value
    while True:
        try:
            email = input(f"{Colours.YELLOW}{question}: {Colours.RESET}").strip()
        except EOFError:
            print_error("No email provided (stdin closed).")
            sys.exit(2)
        if re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email):
            return email
        print("Please enter a valid email address.")


def _plan_email(question: str, allow_group: bool = False,
                source: Optional[str] = None,
                needs_mailbox: bool = False) -> str:
    """Prompt for a destination email and validate it against the directory now.

    Front-loading the decisions is only useful if a fat-fingered destination
    fails at plan time, not two phases into an unattended run — so unlike the
    old inline flow we validate here and re-ask until the address resolves.

    Interactively typed destinations get the same guards the flag path gets
    in preflight_destinations: when `source` is given, the leaver's own
    address or any of their aliases is refused (self-transfer does nothing,
    forward-to-self is a mail loop); when `needs_mailbox` is True, the
    address must have a usable Gmail mailbox so the restore does not fail
    only after the multi-hour download.
    """
    while True:
        email = prompt_email(question)
        if not validate_destination(email, allow_group=allow_group):
            # validate_destination already printed why it failed.
            print_warning("Destination did not validate — enter another.")
            continue
        if source:
            same_account = ({source.lower()}
                            | {a.lower() for a in _list_aliases(source)})
            if email.lower() in same_account:
                print_error(
                    f"{email} is the account being offboarded ({source}). "
                    f"Transferring a leaver's data to themselves does "
                    f"nothing, forwarding to self is a mail loop, and the "
                    f"account is suspended at the end anyway."
                )
                print_warning("Name a different successor.")
                continue
        if needs_mailbox:
            reason = _email_mailbox_missing(email)
            if reason:
                print_error(
                    f"{email} has no usable Gmail mailbox ({reason}). The "
                    f"mailbox restore would fail after the full backup "
                    f"download. Assign a Workspace licence and wait for the "
                    f"mailbox to provision, or pick another destination."
                )
                continue
        return email


# (plan key, prompt, destination prompt, allow_group, needs_mailbox)
_PLAN_TRANSFERS = (
    ("drive", "Transfer Drive files to another user?", "Drive destination email", False, False),
    ("email", "Migrate email to another user (requires GYB)?", "Email migration destination email", False, True),
    ("alias", "Transfer aliases to another user?", "Alias destination email", False, False),
    ("calendar", "Grant calendar access to another user?", "Calendar access destination email", False, False),
    ("forward", "Set up email forwarding to a successor?", "Forward emails to", True, False),
)


def collect_plan(args, dest_map: Dict[str, Optional[str]],
                 is_2sv_enrolled: bool = False,
                 is_2sv_enforced: bool = False,
                 source: Optional[str] = None) -> Dict[str, dict]:
    """Front-load every interactive offboarding decision into one block.

    Asks all the yes/no and destination questions up front — honouring --force
    and the --no-<phase> flags exactly as the old inline prompts did — so the
    operator answers everything once and the run then proceeds unattended.
    Destinations entered interactively are directory-validated immediately and
    get the same self-transfer / mailbox guards as flag-supplied ones (source
    is the leaver; passing it enables the self-transfer guard).
    The phase code reads the returned dict instead of prompting mid-run.
    """
    plan: Dict[str, dict] = {}

    for key, question, dest_question, allow_group, needs_mailbox in _PLAN_TRANSFERS:
        if getattr(args, f"no_{key}"):
            plan[key] = {"do": False, "dest": None}
        elif prompt_yes_no(question, force=args.force):
            dest = dest_map[key] or _plan_email(
                dest_question, allow_group=allow_group, source=source,
                needs_mailbox=needs_mailbox)
            plan[key] = {"do": True, "dest": dest}
        else:
            plan[key] = {"do": False, "dest": None}

    # Email label handling rides on the email decision.
    if plan["email"]["do"] and args.strip_labels is None:
        plan["email"]["strip_labels"] = prompt_yes_no(
            "Strip original Gmail labels and archive migrated mail under "
            "Migrated/<source-user> only? (No keeps INBOX and custom labels)",
            default=True, force=args.force)
    else:
        plan["email"]["strip_labels"] = True if args.strip_labels is None else args.strip_labels

    # Auto-reply (no destination)
    if args.no_auto_reply:
        plan["auto_reply"] = {"do": False}
    else:
        plan["auto_reply"] = {
            "do": prompt_yes_no("Set an auto-reply message on the account?", force=args.force)
        }

    # Suspend. --no-suspend and the temp-unsuspend contract are handled in the
    # phase itself; here we only capture the operator's default-yes intent.
    if args.no_suspend:
        plan["suspend"] = {"do": False}
    else:
        plan["suspend"] = {
            "do": prompt_yes_no("Suspend the user account?", default=True, force=args.force)
        }

    # Turn off 2SV. The kill switch's turnoff2sv errors out (GAM exit 50) when
    # 2SV is ENFORCED — by the OU's 2SV policy or by a 2SV-enforcement group —
    # because moving to the Offboarding OU doesn't clear a group-level policy.
    # So surface the situation up front and let the operator decide, rather than
    # letting it blow up mid-run. Not enrolled => nothing to turn off.
    if not is_2sv_enrolled:
        plan["turnoff2sv"] = {"do": False}
    elif args.force:
        # Attempt whenever there is something to turn off. Deciding on the
        # ENFORCED reading was wrong in both directions, because enforcement
        # follows the OU and the kill switch moves the user first:
        #   - offboarding OU enforces: plan says attempt, GAM exits 50 anyway
        #   - home OU enforced, offboarding OU not (the configuration this
        #     script REQUIRES): plan says skip, and 2SV is left on when the
        #     move would have made it work.
        # The refusal is cheap and now handled where it happens, so stop
        # predicting it. Proved on dev 2026-07-29.
        plan["turnoff2sv"] = {"do": True}
    else:
        print_info("This user has 2-Step Verification turned ON.")
        if is_2sv_enforced:
            print_warning(
                "2SV is ENFORCED by policy — either the OU's 2SV setting or a "
                "2SV-enforcement group (e.g. org2stepverification@...). "
                "Turning it off fails with GAM exit 50 ('user is required by "
                "admin policy to have 2-Step Verification') until that "
                "enforcement is removed. NOTE: this reading is for the OU the "
                f"user is in NOW. Enforcement follows the OU and they are "
                f"moved to {OFFBOARDING_OU} first, so the answer can change "
                "under it either way — the attempt is made regardless and the "
                "refusal reported plainly. The account is suspended at the end "
                "of offboarding either way, so leaving 2SV on is safe."
            )
        else:
            print_info(
                "2SV is enrolled but not policy-enforced, so turning it off "
                "should succeed. The account is suspended at the end regardless."
            )
        skip = prompt_yes_no(
            "Continue WITHOUT turning off 2SV?",
            default=is_2sv_enforced)
        plan["turnoff2sv"] = {"do": not skip}

    return plan


def print_plan(plan: Dict[str, dict]) -> None:
    """Echo the collected plan so the operator can catch a wrong destination.

    Also states the unconditional containment phase, which is not part of
    `plan` and cannot be skipped. This block is what the operator confirms, so
    leaving out the only irreversible phase would make the confirmation
    misleading — particularly for a `--backup-drive --no-transfer` run, where
    every other line reads "no".
    """
    def line(label: str, entry: dict) -> None:
        if entry.get("do"):
            dest = entry.get("dest")
            extra = f" -> {dest}" if dest else ""
            print_info(f"  [YES] {label}{extra}")
        else:
            print_info(f"  [ no] {label}")

    print_header("OFFBOARDING PLAN")
    # Containment is Phase 1 and unconditional, so it is not in `plan` and has
    # no flag to skip it. State it anyway: this block is what the operator
    # confirms, and omitting the only irreversible phase makes the confirmation
    # a lie. --backup-drive --no-transfer reads like a read-only backup and is
    # not one; this line is what says so before the prompt.
    print_warning("  [YES] CONTAINMENT (always runs, cannot be skipped):")
    print_warning("        OU move, recovery email + phone WIPED, app passwords")
    print_warning("        and OAuth tokens revoked, all sessions signed out,")
    print_warning("        PASSWORD SCRAMBLED, hidden from the GAL.")
    print_warning("        The user loses access immediately and irreversibly.")
    line("Transfer Drive files", plan["drive"])
    line("Migrate email", plan["email"])
    if plan["email"].get("do"):
        mode = "strip labels + archive" if plan["email"]["strip_labels"] else "keep labels + INBOX"
        print_info(f"         label handling: {mode}")
    line("Transfer aliases", plan["alias"])
    line("Grant calendar access", plan["calendar"])
    line("Email forwarding", plan["forward"])
    line("Auto-reply", plan["auto_reply"])
    line("Suspend account", plan["suspend"])
    if plan["turnoff2sv"]["do"]:
        print_info("  [YES] Turn off 2SV")
    else:
        print_info("  [ no] Turn off 2SV (left ON — enforced/not-enrolled or operator choice)")


###############################################################################
# PRE-FLIGHT SNAPSHOT [RECOMMENDED]
# Captures the user's complete state before any changes are made.
# This is your audit trail and rollback reference.
###############################################################################

def _parse_info_user_licences(output: str) -> Optional[List[Tuple[str, str]]]:
    """Read the `Licenses: (N)` block out of full `gam info user` output.

    GAM 7.48.01 prints (captured live 2026-09-02):
        Licenses: (2)
          1010010001 (Cloud Identity Free)
          1010020020 (Google Workspace Enterprise Plus (formerly G Suite Enterprise))
    Returns [(skuId, displayName), ...], [] for "(0)", or None when the block
    is absent so the caller can fall back rather than assume no licences.
    """
    lines = output.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"\s*Licenses:\s*\((\d+)\)", line)
        if not m:
            continue
        licences: List[Tuple[str, str]] = []
        for entry in lines[i + 1:i + 1 + int(m.group(1))]:
            em = re.match(r"\s*(\S+)\s*(?:\((.*)\))?\s*$", entry)
            if em:
                licences.append((em.group(1), em.group(2) or em.group(1)))
        return licences
    return None


def preflight_snapshot(email: str, dry_run: bool, timestamp: str = ""
                       ) -> Tuple[Optional[Path], Optional[List[Tuple[str, str]]]]:
    """
    [RECOMMENDED] Export user state to a JSON file before making changes.

    Captures: user info, group memberships, aliases, delegates, forwarding
    settings and send-as addresses. Licences come out of the full `info user`
    output, which lists them by skuId; the separate `print licenses` command
    lists every licence for every product in the tenant and filters, 23 s on
    a 50-user tenant and growing with it, so it is not run any more.

    The reads are independent and run in parallel. This runs even in dry-run
    mode because it is read-only.

    Returns (snapshot_file_path, licences) where licences is the
    [(skuId, name), ...] list for the licence-removal phase, or None when the
    read failed (the phase then queries for itself rather than assume none).
    """
    print_header("PRE-FLIGHT SNAPSHOT")

    snapshot = {
        "timestamp": datetime.now().isoformat(),
        "user": email,
        "dry_run": dry_run,
        "script_version": SCRIPT_VERSION,
        "data": {}
    }

    print_info("Capturing user info, groups, aliases, delegates, forwarding and send-as (in parallel)...")
    ro = dict(dry_run=False, capture_output=True)
    results = run_gam_parallel({
        "user_info": (["info", "user", email], dict(ro, timeout=60)),
        "groups": (["user", email, "print", "groups"], dict(ro, timeout=60, stdout_only=True)),
        "aliases": (["print", "aliases", "user", email], dict(ro, timeout=30, stdout_only=True)),
        "delegates": (["user", email, "show", "delegates"], dict(ro, timeout=30)),
        "forwarding": (["user", email, "show", "forward"], dict(ro, timeout=30)),
        "sendas": (["user", email, "show", "sendas"], dict(ro, timeout=30)),
    }, workers=6)
    for key, (ok, output) in results.items():
        if ok:
            snapshot["data"][key] = output

    licences: Optional[List[Tuple[str, str]]] = None
    if results["user_info"][0]:
        licences = _parse_info_user_licences(results["user_info"][1])
        if licences is not None:
            snapshot["data"]["licenses"] = [
                {"skuId": sku, "name": name} for sku, name in licences]

    # Save snapshot
    snapshot_dir = BACKUP_DIRECTORY / "snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    snapshot_file = snapshot_dir / f"{email}_{timestamp or datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    try:
        with open(snapshot_file, 'w', encoding='utf-8') as f:
            json.dump(snapshot, f, indent=2, default=str)
        print_success(f"Snapshot saved: {snapshot_file}")
        summary_action(f"Pre-flight snapshot saved to {snapshot_file}")
        return snapshot_file, licences
    except Exception as e:
        print_error(f"Failed to save snapshot: {e}")
        summary_error(f"Snapshot save failed: {e}")
        return None, licences


###############################################################################
# KILL SWITCH [CRITICAL]
###############################################################################

def _read_2sv_enrolled(email: str) -> Optional[bool]:
    """Read the user's actual 2SV enrollment state; None if the read fails."""
    fields = _user_quick_fields(email, bypass_shutdown=True)
    if fields is None or "2-step enrolled" not in fields:
        return None
    return fields["2-step enrolled"].lower() == "true"


def _first_line(text: str) -> str:
    """First non-blank line of GAM output, for quoting a reason to the user.

    run_gam puts stdout first and stderr after, so a command that only wrote to
    stderr leaves a leading blank line — quoting line [0] then prints nothing at
    all. Seen live on dev 2026-07-29: "turnoff2sv skipped: " with no reason.
    """
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return "no reason given"


# GAM's exact refusal when policy enforces 2SV (dev, 2026-07-29, exit 50):
#   "Turn Off 2-Step Verification Failed: 2-Step Verification cannot be
#    turned off: user is required by admin policy to have 2-Step
#    Verification ("enforced")"
_2SV_ENFORCED_ERROR = "required by admin policy"



def execute_kill_switch(email: str, dry_run: bool, is_suspended: bool,
                        is_2sv_enrolled: bool = True,
                        has_mailbox: bool = True,
                        turn_off_2sv: bool = True) -> Dict[str, bool]:
    """
    [CRITICAL] Immediate containment of the user account.

    Returns the containment outcome so the caller can act on it:
    {"password_scrambled", "signed_out", "contained", "started"}. `contained`
    is False whenever the account may still be reachable — a failed password
    scramble, or no successful sign-out — which is the combination that used
    to be printed and then forgotten (issue #5). `started` is False only when
    a shutdown was already requested and nothing was attempted.

    EXECUTION ORDER REASONING:
      1. OU move FIRST (allows turnoff2sv by removing 2SV enforcement)
      2. Wipe recovery info (prevents "Forgot Password" re-entry)
      3. Deprovision (tokens, ASPs, backup codes, POP/IMAP, signout, 2SV)
      4. Explicit signout (belt-and-braces)
      5. Explicit turnoff2sv (belt-and-braces, skipped if not enrolled)
      6. Scramble password (blocks login even if above steps partially fail)
      7. Hide from GAL (cosmetic but important for clean directory)

    EDGE CASE: If user is already suspended, deprovision backup codes
    and turnoff2sv will fail. We handle this by logging warnings rather
    than aborting the entire phase.

    EDGE CASE: If user is not enrolled in 2SV, skip turnoff2sv steps to
    avoid GAM exit-50 errors that pollute the error summary.
    """
    print_header("KILL SWITCH (CONTAINMENT)")

    # A Ctrl+C that lands between step 1 and step 7 must not leave the user
    # moved into an OU with no 2SV enforcement, with their password intact and
    # their sessions alive: weaker than before the run started. So the check
    # is made once here, and every step below runs with bypass_shutdown so
    # that a containment that has begun always finishes. main() checks the
    # flag again after this function returns.
    if shutdown_requested:
        print_warning("Shutdown requested before containment started; nothing changed.")
        return {"password_scrambled": False, "signed_out": False,
                "contained": False, "started": False}

    if is_suspended:
        print_warning(
            "User is already suspended. Deprovision backup codes and "
            "turnoff2sv will likely fail. Continuing with other steps."
        )

    # Step 1: Move to holding OU [CRITICAL]
    print_info("Step 1/7: Moving user to offboarding OU...")
    success, _ = run_gam(
        ["update", "user", email, "org", OFFBOARDING_OU],
        dry_run=dry_run, bypass_shutdown=True
    )
    if success:
        summary_action(f"Moved to OU: {OFFBOARDING_OU}")

    # NB: do NOT re-read 2SV enforcement here to decide anything. Enforcement
    # follows the OU and we have just changed it, but the user's flag lags the
    # move — measured on dev 2026-07-29, the OU move landed at 11:54:25 and the
    # flag had not flipped 6s later at 11:54:31, though it had within 15s.
    # A read here races that delay and answers for the OU the user left, so
    # turnoff2sv is simply attempted and the refusal handled where it happens.
    else:
        print_error("CRITICAL: Failed to move user to offboarding OU.")

    # Step 2: Wipe recovery info [CRITICAL]
    print_info("Step 2/7: Wiping recovery email and phone...")
    ok, _ = run_gam(
        ["update", "user", email, "recoveryemail", "", "recoveryphone", ""],
        dry_run=dry_run, bypass_shutdown=True
    )
    if ok:
        summary_action("Wiped recovery email and phone")

    # Step 3: Deprovision [CRITICAL]
    # GAM7 wiki (Users-Deprovision):
    #   gam <UserTypeEntity> deprovision|deprov [popimap] [signout] [turnoff2sv]
    # Deletes ASPs, backup codes, OAuth tokens.
    # [popimap] also disables POP/IMAP.
    # [signout] forces sign-out.
    # [turnoff2sv] disables 2-Step Verification.
    #
    # NOTE: Will partially fail on suspended users (backup codes).
    # NOTE: Only include turnoff2sv if the user is actually enrolled, otherwise
    #       GAM exits with code 50 which pollutes the error summary.
    # NOTE: Only include popimap if the user has a mailbox — disabling
    #       POP/IMAP on a Gmail-less user (e.g. Cloud Identity licence)
    #       fails the whole deprovision with exit 73 even though ASPs,
    #       codes, tokens and signout all succeeded (observed live on
    #       dev tenant 2026-07-13).
    deprov_args = ["user", email, "deprovision", "signout"]
    if has_mailbox:
        deprov_args.insert(3, "popimap")
    do_2sv = is_2sv_enrolled and turn_off_2sv
    if do_2sv:
        deprov_args.append("turnoff2sv")
    label = ("ASPs, backup codes, tokens, signout"
             + (", POP/IMAP" if has_mailbox else "")
             + (", 2SV" if do_2sv else ""))
    print_info(f"Step 3/7: Deprovisioning ({label})...")
    success, output = run_gam(deprov_args, dry_run=dry_run, capture_output=True,
                              non_fatal_patterns=[_2SV_ENFORCED_ERROR],
                              bypass_shutdown=True)
    if success and _2SV_ENFORCED_ERROR in (output or "").lower():
        # GAM exits 50 for the 2SV step alone, but the bundle is not atomic:
        # ASPs, backup codes, tokens, signout and POP/IMAP all completed first
        # (verified line by line on dev 2026-07-29). Reporting this as a failed
        # deprovision would tell the operator containment did not happen.
        print_warning(
            f"Deprovision completed EXCEPT turning off 2SV, which policy "
            f"enforces. Everything else in the bundle succeeded "
            f"({label.replace(', 2SV', '')}) — containment is done."
        )
        summary_action(f"Deprovisioned: {label.replace(', 2SV', '')} (2SV enforced, left on)")
    elif success:
        summary_action(f"Deprovisioned: {label}")
    # Check for partial failure (backup codes on suspended user)
    if output and "not deprovisioned" in output.lower():
        print_warning(f"Partial deprovision: {output}")
        summary_warning("Deprovision partially failed (likely suspended user)")

    # Step 4: Explicit signout [RECOMMENDED]
    # GAM7 wiki (Users-Signout-Turnoff2SV):
    #   gam <UserTypeEntity> signout
    print_info("Step 4/7: Forcing sign-out from all sessions...")
    signout_ok, _ = run_gam(["user", email, "signout"], dry_run=dry_run,
                            bypass_shutdown=True)
    if signout_ok:
        summary_action("Forced sign-out")
    signed_out = signout_ok or bool(success)

    # Step 5: Turn off 2SV [RECOMMENDED]
    # GAM7 wiki (Users-Signout-Turnoff2SV):
    #   gam <UserTypeEntity> turnoff2sv
    # Will fail if: suspended, not enrolled, OU enforces 2SV, or Advanced Protection
    # Skipped entirely if not enrolled to avoid spurious GAM exit-50 errors.
    #
    # Verify-first: when deprovision (step 3) carried the turnoff2sv token
    # and succeeded, 2SV is already off here, and re-firing turnoff2sv on an
    # unenrolled user fails with exit 50 — a false error in the summary of a
    # successful run (observed live on dev 2026-07-13). So read the actual
    # enrollment state and only fire the explicit command if still enrolled.
    if not is_2sv_enrolled:
        print_info("Step 5/7: Skipping turnoff2sv (user not enrolled in 2SV).")
        summary_warning("turnoff2sv skipped (user not enrolled in 2SV)")
    elif not turn_off_2sv:
        print_info("Step 5/7: Leaving 2SV ON (operator chose to skip turnoff2sv).")
        summary_warning("2SV left ON — turnoff2sv skipped by operator (likely enforced by OU/group)")
    elif dry_run:
        print_info("Step 5/7: Turning off 2-Step Verification...")
        run_gam(["user", email, "turnoff2sv"], dry_run=True)
        summary_action("Turned off 2SV")
    else:
        print_info("Step 5/7: Verifying 2-Step Verification is off...")
        if _read_2sv_enrolled(email) is False:
            print_success("2SV is off (deprovision's turnoff2sv took effect).")
            summary_action("2SV off (verified by read-back)")
        else:
            success, output = run_gam(
                ["user", email, "turnoff2sv"],
                dry_run=False,
                capture_output=True,
                suppress_summary_error=True,
                bypass_shutdown=True,
            )
            if success or _read_2sv_enrolled(email) is False:
                summary_action("Turned off 2SV")
            elif output and "not enrolled" in output.lower():
                # GAM says there is nothing to turn off, and we only reach here
                # for a user who WAS enrolled at the start of the run — so the
                # deprovision in step 3 already did it and the directory read
                # above was stale. This is the success case, not a skip.
                # Measured on dev 2026-07-29: deprovision turned 2SV off at
                # 12:26:12 and `gam info user quick` still said enrolled at
                # 12:26:22, ten seconds later.
                print_success("2SV is off (deprovision took effect; the "
                              "directory read lagged behind it).")
                summary_action("Turned off 2SV (via deprovision)")
            elif output and "suspended" in output.lower():
                print_warning(f"turnoff2sv skipped: {_first_line(output)}")
                summary_warning("turnoff2sv skipped (account suspended)")
            elif output and _2SV_ENFORCED_ERROR in output.lower():
                # Retrying the same command is pointless: policy, not the
                # account, is refusing. Say what would actually change it.
                print_warning(
                    f"2SV cannot be turned off for {email} — policy enforces "
                    f"it on {OFFBOARDING_OU}. Retrying will fail identically. "
                    f"Remove the enforcement from that OU (Admin console -> "
                    f"Security -> Authentication -> 2-Step Verification) if "
                    f"you need 2SV off; the account is suspended at the end of "
                    f"offboarding regardless, so leaving it on is safe."
                )
                summary_warning(
                    f"2SV left ON for {email} (enforced by policy on "
                    f"{OFFBOARDING_OU})"
                )
            else:
                print_error(f"turnoff2sv failed and 2SV still reads enrolled for {email}. "
                            f"Retry manually: gam user {email} turnoff2sv")
                summary_error(f"turnoff2sv failed — 2SV may still be enrolled for {email}")

    # Step 6: Scramble password [CRITICAL]
    # GAM7 wiki (Users): gam update user <email> password random
    print_info("Step 6/7: Scrambling password...")
    password_scrambled, _ = run_gam(
        ["update", "user", email, "password", "random", "changepassword", "on"],
        dry_run=dry_run, bypass_shutdown=True
    )
    if password_scrambled:
        summary_action("Password scrambled and forced change on next login")
    else:
        print_error("CRITICAL: Password scramble failed — the user can still log in.")

    # Step 7: Hide from GAL [IMPORTANT]
    # GAM7 wiki (Users): gam update user <email> gal off
    print_info("Step 7/7: Hiding from Global Address List...")
    ok, _ = run_gam(
        ["update", "user", email, "gal", "off"],
        dry_run=dry_run, bypass_shutdown=True
    )
    if ok:
        summary_action("Hidden from GAL")

    # An account that started suspended and was not unsuspended cannot sign
    # out or deprovision (the API refuses on a suspended user), and it does
    # not need to: suspension already closes the sessions. Counting that as
    # "sign-out not confirmed" produced a CONTAINMENT INCOMPLETE error and a
    # forced re-suspend of an account that was suspended all along.
    if is_suspended:
        signed_out = True
    contained = bool(password_scrambled and signed_out)
    if not contained:
        reasons = []
        if not password_scrambled:
            reasons.append("password not scrambled")
        if not signed_out:
            reasons.append("sign-out not confirmed")
        summary_error(
            f"CONTAINMENT INCOMPLETE for {email} ({', '.join(reasons)}) — "
            f"the account may still be accessible with its old credentials"
        )
    return {
        "password_scrambled": bool(password_scrambled),
        "signed_out": bool(signed_out),
        "contained": contained,
        "started": True,
    }


###############################################################################
# DEVICE MANAGEMENT [IMPORTANT]
###############################################################################

def manage_devices(email: str, _dry_run: bool) -> None:
    """
    [IMPORTANT] List and optionally wipe devices associated with the user.
    Actual wipe operations are logged as guidance, not executed automatically,
    because factory-resetting a device is destructive and irreversible.
    """
    print_header("DEVICE MANAGEMENT")

    print_info("Querying mobile and ChromeOS devices (in parallel)...")
    ro = dict(dry_run=False, capture_output=True, stdout_only=True)
    devices = run_gam_parallel({
        "mobile": (["print", "mobile", "query", f"email:{email}"], ro),
        "cros": (["print", "cros", "query", f"user:{email}"], ro),
    }, workers=2)

    success, output = devices["mobile"]
    mobile_lines = [l for l in output.splitlines() if l.strip()]
    if not success:
        summary_error(
            f"Mobile device query failed for {email} — check by hand with: "
            f"gam print mobile query \"email:{email}\""
        )
    elif len(mobile_lines) > 1:
        print_warning("Mobile devices found. Review and wipe manually:")
        print_info("  Account wipe (corp data): gam update mobile <resourceId> action account_wipe")
        print_info("  Factory reset: gam update mobile <resourceId> action wipe")
        summary_action("Mobile devices found and listed for review")
    else:
        print_success("No mobile devices found.")
        summary_action("No mobile devices")

    success, output = devices["cros"]
    cros_lines = [l for l in output.splitlines() if l.strip()]
    if not success:
        summary_error(
            f"ChromeOS device query failed for {email} — check by hand with: "
            f"gam print cros query \"user:{email}\""
        )
    elif len(cros_lines) > 1:
        print_warning("ChromeOS devices found. Review and disable/deprovision manually:")
        print_info("  Disable: gam update cros <deviceId> action disable")
        print_info("  Deprovision: gam update cros <deviceId> action deprovision_retiring_device")
        summary_action("ChromeOS devices found and listed for review")
    else:
        print_success("No ChromeOS devices found.")
        summary_action("No ChromeOS devices")


###############################################################################
# GROUP REMOVAL [IMPORTANT]
###############################################################################

def remove_groups(email: str, dry_run: bool):
    """
    [IMPORTANT] Remove the user from all groups.

    GAM7: gam user <email> delete groups
    """
    print_header("GROUP REMOVAL")

    print_info("Listing current group memberships...")
    # stdout_only=True: keep stderr out of the captured CSV so GAM's
    # "Getting Groups for user@..." / "Got N Groups" progress lines
    # can't be mistaken for CSV rows by DictReader.
    success, output = run_gam(
        ["user", email, "print", "groups"],
        dry_run=False,
        capture_output=True,
        stdout_only=True,
    )

    if not success:
        # A timed-out or failed listing is not "no groups". Saying so here
        # skipped `delete groups` and left every group-granted share and list
        # membership in place behind a summary line that read as clean.
        print_error("Could not list group memberships; remove them manually.")
        summary_error(
            f"Group listing failed for {email} — remove memberships by hand "
            f"with: gam user {email} delete groups"
        )
        return

    group_count = 0
    group_names: List[str] = []
    if output.strip():
        # GAM 7.48.01 prints `User,Group,Role,Status,Delivery` (captured
        # 2026-09-02) but the column name has varied across versions, so the
        # group-address column is matched by substring ("Group", "GroupEmail",
        # "groupKey") with an email-shaped fallback.
        csv_lines = output.strip().splitlines()
        if csv_lines:
            try:
                reader = csv.DictReader(io.StringIO("\n".join(csv_lines)))
                rows = list(reader)
                group_count = len(rows)
                fieldnames = [f for f in (reader.fieldnames or []) if f]
                # Prefer a column with "group" in the name; otherwise
                # take the first column that holds an email-looking value
                # that ISN'T the queried user's own address.
                group_col = next(
                    (f for f in fieldnames if "group" in f.lower()),
                    None,
                )
                if not group_col and rows:
                    for f in fieldnames:
                        v = (rows[0].get(f) or "").strip()
                        if "@" in v and v.lower() != email.lower():
                            group_col = f
                            break
                if group_col:
                    for row in rows:
                        v = (row.get(group_col) or "").strip()
                        if v:
                            group_names.append(v)

                # Diagnostic: if we counted rows but couldn't extract any
                # names, dump headers + first row so the GAM output format
                # is debuggable straight from the log file without a re-run.
                if group_count > 0 and not group_names:
                    first_row = rows[0] if rows else {}
                    logger.info(
                        f"Group preview empty despite {group_count} row(s). "
                        f"Headers: {fieldnames}. Chose column: {group_col!r}. "
                        f"First row: {dict(first_row)!r}"
                    )
            except csv.Error:
                group_count = max(0, len(csv_lines) - 1)

    if group_count == 0:
        print_success("User is not a member of any groups.")
        summary_action("No group memberships to remove")
        return

    preview = ", ".join(group_names[:5])
    if len(group_names) > 5:
        preview += f", ... (+{len(group_names) - 5} more)"
    print_info(f"Found {group_count} group membership(s): {preview}")

    if dry_run:
        run_gam(["user", email, "delete", "groups"], dry_run=True)
        summary_action(f"Would remove {group_count} group membership(s)")
        return

    print_info(f"Removing from {group_count} group(s)...")
    ok, _ = run_gam(["user", email, "delete", "groups"], dry_run=False)
    if ok:
        summary_action(f"Removed from {group_count} group(s)")
    else:
        summary_error(f"Group removal failed (was member of {group_count} group(s))")


###############################################################################
# DELEGATE CLEANUP [IMPORTANT]
# Removes both:
#   - Delegates who have access TO this user's mailbox
#   - Delegate access this user has TO other mailboxes
###############################################################################

def cleanup_delegates(email: str, dry_run: bool):
    """
    [IMPORTANT] Remove all mailbox delegation relationships.

    Two directions to clean up:
    1. People who can read THIS user's mailbox (inbound delegates)
    2. Mailboxes THIS user can read (outbound, harder to find)

    For inbound, we use:
      gam user <email> show delegates -> get list
      gam user <email> delete delegate <delegate>

    For outbound, there is no single GAM command to find all mailboxes
    a user is a delegate of. This would require iterating all users.
    We log a warning about this limitation.

    GAM7 wiki (Users-Gmail-Delegates):
      gam <UserTypeEntity> delete delegate <UserEntity>
      gam <UserTypeEntity> show delegates
    """
    print_header("DELEGATE CLEANUP")

    # Inbound: who can access this user's mailbox?
    print_info("Checking who has delegate access to this mailbox...")
    success, output = run_gam(
        ["user", email, "show", "delegates"],
        dry_run=False,
        capture_output=True
    )

    if success and output:
        # Parse delegate addresses from output
        delegates = re.findall(r'Delegate:\s+(\S+@\S+)', output, re.IGNORECASE)
        if delegates:
            total = len(delegates)
            print_info(f"Found {total} delegate(s) with access to this mailbox.")
            removed = 0
            for i, delegate in enumerate(delegates, 1):
                print_info(f"  [{i}/{total}] Removing delegate: {delegate}")
                ok, _ = run_gam(
                    ["user", email, "delete", "delegate", delegate],
                    dry_run=dry_run
                )
                if ok:
                    removed += 1
            if dry_run:
                summary_action(f"Would remove {total} inbound delegate(s)")
            else:
                summary_action(f"Removed {removed}/{total} inbound delegate(s)")
        else:
            print_success("No inbound delegates found.")
            summary_action("No inbound delegates to remove")
    else:
        print_success("No delegates found or unable to query.")

    # Outbound warning
    print_warning(
        "NOTE: This script cannot automatically find all mailboxes this "
        "user has delegate access TO (it would require scanning all users). "
        "Check the pre-flight snapshot's delegate section for any references, "
        "or run: gam all users print delegates | grep <email>"
    )
    # Carry the command in the SUMMARY line too, not just the phase output —
    # the summary is what gets read at the end of a long run, and "requires
    # manual verification" alone leaves the operator to work out how.
    summary_warning(
        f"Outbound delegate access not cleaned up ({email} may still be a "
        f"delegate on other mailboxes). Find them with: "
        f"gam all users print delegates | grep {email}"
    )


###############################################################################
# LICENCE REMOVAL [RECOMMENDED]
###############################################################################

def remove_licences(email: str, dry_run: bool,
                    cached_licences: Optional[List[Tuple[str, str]]] = None) -> None:
    """
    [RECOMMENDED] Remove all licences from the user to free up seats.

    The licence list comes from the `Licenses: (N)` block of `gam info user`,
    which names each skuId with its display name, normally already captured
    by the pre-flight snapshot (`cached_licences`). Each licence is then
    deleted individually with `gam user <email> delete license <skuId>`.
    """
    print_header("LICENCE REMOVAL")

    licences = cached_licences
    if licences is None:
        print_info("Querying assigned licences...")
        ok, output = run_gam(["info", "user", email], dry_run=False,
                             capture_output=True, timeout=60)
        licences = _parse_info_user_licences(output) if ok else None
        if licences is None:
            # Timeout, API failure or no Licenses block: do NOT claim there
            # are no licences, or a timed-out query leaves paid seats assigned.
            print_error("Could not query licences; manual cleanup required.")
            summary_error(
                f"Licence query failed for {email} — verify and remove manually "
                f"with: gam info user {email}"
            )
            return
    else:
        print_info("Reusing licence list from pre-flight snapshot...")

    if not licences:
        print_success("No licences to remove")
        summary_action("No licences found")
        return

    labels = [f"{name} ({sku})" if name != sku else sku for sku, name in licences]
    print_info(f"Found {len(licences)} licence(s): {', '.join(labels)}")

    if dry_run:
        for sku, _ in licences:
            run_gam(["user", email, "delete", "license", sku], dry_run=True)
        summary_action(f"Licences listed (dry run): {', '.join(labels)}")
        return

    removed_labels, auto_assigned_labels, failed_labels = [], [], []
    for i, (sku, _) in enumerate(licences):
        lbl = labels[i]
        print_info(f"  [{i + 1}/{len(licences)}] Removing licence: {lbl}")
        ok, delete_output = run_gam(
            ["user", email, "delete", "license", sku],
            dry_run=False,
            capture_output=True,
            non_fatal_patterns=["auto-assigned"]
        )
        if "auto-assigned" in delete_output.lower():
            auto_assigned_labels.append(lbl)
        elif ok:
            removed_labels.append(lbl)
        else:
            failed_labels.append(lbl)

    if removed_labels:
        print_success(f"Removed {len(removed_labels)} licence(s): {', '.join(removed_labels)}")
        summary_action(f"Removed {len(removed_labels)} licence(s): {', '.join(removed_labels)}")
    if auto_assigned_labels:
        print_warning(
            f"Licence(s) {', '.join(auto_assigned_labels)} have auto-assignment "
            f"enabled and cannot be removed via API. Remove manually in Admin "
            f"Console > Billing > Subscriptions."
        )
        summary_warning(
            f"Licence(s) {', '.join(auto_assigned_labels)} are auto-assigned; "
            f"manual removal required in Admin Console"
        )
    if failed_labels:
        summary_error(f"Licence removal failed for: {', '.join(failed_labels)}")


###############################################################################
# DATA TRANSFERS [IMPORTANT]
###############################################################################

def transfer_drive(source: str, destination: str, dry_run: bool):
    """
    [IMPORTANT] Transfer Drive file ownership.

    Streams GAM's per-file progress to the log instead of buffering it,
    so the user can see "Got N files" / "Transferring file X of Y" while
    the transfer is in flight. Uses no overall timeout because large
    drives can legitimately take hours.

    GAM7 wiki (Users-Drive-Transfer):
      gam user <source> transfer drive <destination> [keepuser]
    """
    print_header("DRIVE TRANSFER")

    print_info(f"Transferring Drive files: {source} -> {destination}")
    print_info(
        "Progress is also visible in Admin Console -> Reporting -> Audit "
        "and investigation -> Drive log events (filter Actor=source user, "
        f"Event=Change owner), or in {destination}'s Drive UI under "
        "'Shared with me'."
    )

    full_cmd = [GAM_COMMAND, "user", source, "transfer", "drive",
                destination, "keepuser"]
    cmd_str = " ".join(full_cmd)

    if dry_run:
        print_info(f"DRY RUN: {cmd_str}")
        summary_action(f"Drive transfer planned to {destination}")
        return

    logger.info(f"Executing: {cmd_str}")

    try:
        # Count the per-file "Ownership Transferred" confirmations, NOT GAM's
        # opening "Got N Drive Files/Folders for Source User" line. That header
        # counts files the source can ACCESS — which after a previous
        # `keepuser` transfer includes files they no longer own. Measured on
        # the dev tenant: header said 100 for a user owning 0. Without a count
        # the summary reads "Drive transferred" whether it moved everything or
        # nothing, and nothing moving usually means the wrong source address or
        # a transfer that already ran.
        transferred = 0

        def on_line(line: str):
            nonlocal transferred
            if "Ownership Transferred to User:" in line:
                transferred += 1
            logger.info(line)

        returncode = _stream_process(full_cmd, on_line)
        file_count = transferred

        if returncode == 0:
            if file_count == 0:
                print_warning(
                    f"Drive transfer reported success but {source} owned NO "
                    f"files to transfer. If that is unexpected, check the "
                    f"source address and whether a transfer already ran."
                )
                summary_warning(
                    f"Drive transfer to {destination} moved 0 files "
                    f"({source} owned none)"
                )
            else:
                summary_action(
                    f"Drive transferred to {destination} ({file_count} file(s)/folder(s))"
                )
        elif returncode == 56:
            # GAM exits 56 when some of the files it listed could not be
            # transferred — normally files the source can ACCESS but does not
            # OWN (ownership of someone else's file cannot move). The files
            # the source did own transferred fine, per the confirmations
            # counted above. Reporting this as a hard failure blocked licence
            # removal behind a "failed" transfer that lost nothing (a week on
            # one client ticket), so it is a warning with a verify instruction.
            # UNLESS nothing at all moved: the benign reading needs at least
            # one successful move to stand on. Zero confirmations means
            # either every listed item failed (API errors) or the source
            # owned nothing while non-owned files were listed — the two are
            # indistinguishable from the exit code alone, and the first one
            # loses data if licences are removed on top of it. Hold licence
            # removal and send the operator to look.
            if file_count == 0:
                print_error(
                    f"Drive transfer exited 56 and transferred NOTHING: no "
                    f"'Ownership Transferred' confirmations were seen. Either "
                    f"every listed item failed, or {source} owned no files "
                    f"while non-owned ones were listed. Verify which in the "
                    f"successor's Drive (and gam's log above) before "
                    f"removing licences."
                )
                summary_error(
                    f"Drive transfer to {destination}: exit 56 with 0 files "
                    f"moved — either all items failed or the source owned "
                    f"nothing. Verify before licence removal; re-run the "
                    f"transfer if files are missing."
                )
            else:
                print_warning(
                    f"Drive transfer finished with exit 56: {file_count} owned "
                    f"file(s)/folder(s) transferred; files {source} could access "
                    f"but did not own were skipped (their ownership cannot move)."
                )
                summary_warning(
                    f"Drive transfer to {destination} completed with skips "
                    f"(exit 56, {file_count} owned file(s) moved; non-owned files "
                    f"skipped). Spot-check the successor's Drive before removing "
                    f"licences."
                )
        else:
            print_error(f"Drive transfer failed (exit {returncode}): {cmd_str}")
            summary_error(f"Drive transfer failed: {source} -> {destination}")

    except FileNotFoundError:
        print_error(f"GAM command not found: {GAM_COMMAND}")
        summary_error("GAM7 not found in PATH")
    except Exception as e:
        print_error(f"Drive transfer exception: {e}")
        summary_error(f"Drive transfer exception: {e}")


def _list_aliases(source: str) -> List[str]:
    """Return the source user's alias addresses from GAM's aliases CSV."""
    success, output = run_gam(
        ["print", "aliases", "user", source],
        dry_run=False,
        capture_output=True,
        timeout=60,
        stdout_only=True
    )
    aliases: List[str] = []
    if success and output.strip():
        reader = csv.DictReader(io.StringIO(output.strip()))
        for row in reader:
            value = (row.get("Alias") or "").strip()
            if value:
                aliases.append(value)
    return aliases


def transfer_aliases(source: str, destination: str, dry_run: bool):
    """
    [RECOMMENDED] Transfer email aliases, one delete + create per alias.

    Deliberately NOT `gam update alias` or the csv pipe pattern: update
    alias is delete-then-insert under the hood, and the insert can race
    Directory API propagation of its own delete, failing with "Duplicate"
    and leaving the alias DESTROYED (deleted, never recreated) — while
    `gam csv` swallows the child's exit code so the pipe still exits 0.
    Observed live on dev.osh.co.za 2026-07-13 (evan.legacy lost, run
    reported success). Instead: delete the alias, then create it on the
    destination, retrying the create for up to ~60s while the deletion
    propagates. Each alias is reported individually.
    """
    print_header("ALIAS TRANSFER")

    aliases = _list_aliases(source)
    if not aliases:
        print_success("No aliases to transfer.")
        summary_action("No aliases to transfer")
        return

    print_info(f"Transferring {len(aliases)} alias(es): {', '.join(aliases)} "
               f"-> {destination}")

    if dry_run:
        for alias in aliases:
            run_gam(["delete", "alias", alias], dry_run=True)
            run_gam(["create", "alias", alias, "user", destination], dry_run=True)
        summary_action(f"Would transfer {len(aliases)} alias(es) to {destination}")
        return

    moved: List[str] = []
    failed: List[str] = []
    for alias in aliases:
        ok, _ = run_gam(["delete", "alias", alias], dry_run=False,
                        capture_output=True)
        if not ok:
            failed.append(alias)
            continue
        # Retry the create while the deletion propagates ("Duplicate").
        created = False
        deadline = time.time() + 60
        while True:
            ok, output = run_gam(
                ["create", "alias", alias, "user", destination],
                dry_run=False,
                capture_output=True,
                suppress_summary_error=True
            )
            if ok and "duplicate" not in output.lower():
                created = True
                break
            if time.time() >= deadline or shutdown_requested:
                break
            print_info(f"  {alias}: waiting for deletion to propagate, retrying...")
            time.sleep(5)
        if created:
            moved.append(alias)
        else:
            failed.append(alias)
            print_error(
                f"Alias {alias} was deleted but could NOT be recreated on "
                f"{destination}. Recreate it manually: "
                f"gam create alias {alias} user {destination}"
            )

    if moved:
        print_success(f"Transferred {len(moved)} alias(es): {', '.join(moved)}")
        summary_action(f"Aliases transferred to {destination}: {', '.join(moved)}")
    if failed:
        summary_error(
            f"Alias transfer FAILED for: {', '.join(failed)} — mail to these "
            f"addresses will bounce until recreated on {destination}"
        )


@contextlib.contextmanager
def _gyb_db(db_path):
    """Open GYB's message DB, committing on success and ALWAYS closing it.

    sqlite3's own context manager commits the transaction but does NOT close the
    connection. On POSIX that is invisible; on Windows the file handle stays
    open for the life of the process, so the backup directory cannot afterwards
    be moved, renamed or deleted (WinError 32) and a second process touching the
    same DB can hit "database is locked". Found on Windows 11 ARM64,
    2026-07-29 — five call sites, all leaking.
    """
    db = sqlite3.connect(db_path)
    try:
        with db:
            yield db
    finally:
        db.close()


def _message_dates(backup_path: Path, msg_ids: List[str]) -> Dict[str, str]:
    """Look up message dates for the given Gmail IDs in GYB's own msg-db.

    Read-only; basename match avoids the Windows/POSIX path-separator
    difference in the stored filenames. Missing IDs are simply absent.
    """
    dates: Dict[str, str] = {}
    try:
        with _gyb_db(backup_path / "msg-db.sqlite") as db:
            for msg_id in msg_ids:
                row = db.execute(
                    "SELECT message_internaldate FROM messages "
                    "WHERE message_filename LIKE ?", (f"%{msg_id}%",),
                ).fetchone()
                if row:
                    dates[msg_id] = str(row[0])
    except (sqlite3.Error, OSError) as db_err:
        print_warning(f"Could not read message dates from msg-db.sqlite: {db_err}")
    return dates


def _record_skipped(backup_path: Path, msg_ids: List[str],
                    moved_to: Dict[str, Path], note: str) -> Tuple[Path, Dict[str, str]]:
    """Append skipped messages to <backup>_skipped-messages.csv.

    Always APPEND. The restore retry loop calls the crash-directed quarantine
    and then the full re-scan on later attempts; when the re-scan opened this
    file for writing it truncated the rows the earlier attempts had recorded,
    and the one artefact that says which mail was excluded lost entries.
    Returns the CSV path and the dates found for the IDs.
    """
    dates = _message_dates(backup_path, msg_ids)
    csv_path = backup_path.parent / f"{backup_path.name}_skipped-messages.csv"
    new_file = not csv_path.exists()
    with open(csv_path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        if new_file:
            writer.writerow(["gmail_message_id", "message_date",
                             "quarantined_file", "note"])
        for msg_id in msg_ids:
            writer.writerow([msg_id, dates.get(msg_id, "unknown"),
                             str(moved_to[msg_id]), note])
    return csv_path, dates


def quarantine_unreadable_messages(backup_path: Path) -> List[str]:
    """
    Move unreadable .eml files out of the GYB backup folder so the restore
    skips them instead of crashing, and write a skipped-messages CSV.

    Why: endpoint antivirus can quarantine a message file in place right
    after GYB writes it during backup (a genuinely malicious email that was
    sitting in the source mailbox). The file still exists on disk but every
    read raises PermissionError, and GYB's restore has no per-message
    read-error handling, so one locked file kills the whole restore mid-run.
    GYB DOES skip a file that is absent (its own os.path.isfile() check), so
    the portable fix is to make the bad file absent: probe each .eml with a
    one-byte read and move any unreadable one to a sibling
    <backup>_quarantined/ folder, outside --local-folder. Moving works even
    while reading is blocked, because a rename is a directory metadata
    operation, not a file read. Nothing is deleted.

    Each skipped file is reported by its basename, which is the Gmail
    immutable message ID: admins can look the message up in their AV
    quarantine log, Google Vault, or the Security Investigation Tool. The
    message date is pulled from GYB's msg-db.sqlite (read-only) when
    available. A CSV of skipped messages is written next to the backup
    folder.

    Never raises: any unexpected condition degrades to a loud warning so the
    pre-scan can slow a run down but cannot break one. Side benefit: reading
    every file here provokes on-access AV to flag bad files BEFORE the
    restore starts rather than partway through it.
    """
    skipped: List[str] = []
    moved_to: Dict[str, Path] = {}
    try:
        quarantine_dir = backup_path.parent / f"{backup_path.name}_quarantined"
        for eml in sorted(backup_path.rglob("*.eml")):
            try:
                with open(eml, "rb") as fh:
                    fh.read(1)
            except OSError as read_err:
                target = quarantine_dir / eml.relative_to(backup_path)
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(eml), str(target))
                except OSError as move_err:
                    print_warning(
                        f"Unreadable message {eml.name} could not be moved aside "
                        f"({move_err}); the GYB restore may crash on it. "
                        f"Move or delete it manually, then re-run."
                    )
                    continue
                print_warning(
                    f"Skipping unreadable message {eml.stem} ({read_err}); "
                    f"moved to {target}"
                )
                skipped.append(eml.stem)
                moved_to[eml.stem] = target

        if skipped:
            csv_path, dates = _record_skipped(
                backup_path, skipped, moved_to,
                "Unreadable on disk (likely quarantined by local antivirus). "
                "NOT restored to the destination mailbox. Look it up by "
                "message ID in your AV quarantine log, Google Vault, or the "
                "Security Investigation Tool.")
            # Enumerated in red so the skipped mail cannot be missed in the
            # scroll-back or the end-of-run summary.
            skipped_list = ", ".join(
                f"{msg_id} (dated {dates.get(msg_id, 'unknown')})" for msg_id in skipped
            )
            print_warning(
                f"{Colours.RED}{len(skipped)} unreadable message(s) moved to "
                f"{quarantine_dir} and excluded from the restore: {skipped_list}. "
                f"Details: {csv_path}{Colours.RESET}"
            )
            summary_warning(
                f"{Colours.RED}{len(skipped)} email message(s) skipped as "
                f"unreadable/AV-quarantined (not migrated): {skipped_list}; "
                f"see {csv_path}{Colours.RESET}"
            )
    except Exception as scan_err:  # pre-scan must never break an offboarding run
        print_warning(f"Backup pre-scan for unreadable messages failed: {scan_err}")
    return skipped


def quarantine_gyb_locked_file(backup_path: Path, gyb_output: str) -> List[str]:
    """
    Move aside the .eml file(s) named in a GYB crash so the retry can pass them.

    More reliable than re-scanning, which races the non-deterministic AV lock.
    A file that reads cleanly again is left alone; nothing is deleted.
    """
    quarantined: List[str] = []
    try:
        paths = re.findall(
            r"PermissionError: \[Errno \d+\][^:]*: '([^']+\.eml)'", gyb_output
        )
        # Patched GYB reports the same event without dying; match that wording too.
        paths += re.findall(
            r"WARNING! could not read (\S+\.eml) for message", gyb_output
        )
        if not paths:
            return quarantined
        backup_resolved = backup_path.resolve()
        quarantine_dir = backup_path.parent / f"{backup_path.name}_quarantined"
        moved_to: Dict[str, Path] = {}
        for raw in dict.fromkeys(paths):  # de-dup, preserve order
            eml = Path(raw)
            try:
                rel = eml.resolve().relative_to(backup_resolved)
            except (ValueError, OSError):
                continue  # not inside this backup — ignore
            if not eml.exists():
                continue  # already moved aside on an earlier attempt
            try:
                with open(eml, "rb") as fh:
                    fh.read(1)
                continue  # readable now — transient block, leave it for retry
            except OSError:
                pass       # still locked — a real quarantine, move it aside
            target = quarantine_dir / rel
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(eml), str(target))
            except OSError as move_err:
                print_warning(
                    f"Could not move AV-locked message {eml.name} aside "
                    f"({move_err}); the restore may crash on it again. "
                    f"Move or delete it manually, then re-run."
                )
                continue
            print_warning(
                f"{Colours.RED}Quarantined AV-locked message {eml.stem} "
                f"(named in GYB's crash); excluded from the restore and NOT "
                f"delivered to the successor. Moved to {target}{Colours.RESET}"
            )
            quarantined.append(eml.stem)
            moved_to[eml.stem] = target

        if quarantined:
            csv_path, _ = _record_skipped(
                backup_path, quarantined, moved_to,
                "AV-locked on disk (named in GYB crash); excluded from "
                "restore as malware. Look up by message ID in your AV "
                "quarantine log, Google Vault, or the Security "
                "Investigation Tool.")
            summary_warning(
                f"{Colours.RED}{len(quarantined)} AV-locked message(s) named in "
                f"a GYB crash, quarantined and excluded from the restore: "
                f"{', '.join(quarantined)}; see {csv_path}{Colours.RESET}"
            )
    except Exception as parse_err:  # never break the retry loop
        print_warning(f"Could not parse GYB crash for a locked file: {parse_err}")
    return quarantined


_SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3,
               "TB": 1024 ** 4, "PB": 1024 ** 5}


def _parse_gam_size(output: str, field: str) -> Optional[int]:
    """
    Read a byte count out of a GAM field that prints a HUMAN-FORMATTED size.

    `gam <user> show drivesettings` emits "limit: 329.85 TB", not raw bytes, so
    a digits-only regex reads 329.85 TB as 329 BYTES and every storage
    comparison downstream is nonsense. Parse the number AND its unit.

    Anchored to the start of the line so `usage` does not also match
    `usageInDrive` / `usageInDriveTrash`, which follow it in the same output.
    Returns None when the field is absent or unparseable; callers skip the
    check rather than guessing.
    """
    m = re.search(
        rf"^\s*{re.escape(field)}\s*:\s*([\d.]+)\s*([KMGTP]?B)\b",
        output, re.IGNORECASE | re.MULTILINE,
    )
    if not m:
        return None
    try:
        return int(float(m.group(1)) * _SIZE_UNITS[m.group(2).upper()])
    except (ValueError, KeyError):
        return None


def _estimate_mailbox_bytes(email: str) -> Optional[int]:
    """Estimate the user's Gmail storage in bytes from GAM's drivesettings.

    `usage` is the account's total storage; subtracting `usageInDrive` and
    `usageInDriveTrash` leaves (approximately) Gmail. Used to size a GYB
    backup before committing a long download to a too-small disk. Returns
    None when the fields are absent or unparseable; callers skip the check
    rather than guessing.
    """
    ok, out = run_gam(["user", email, "show", "drivesettings"],
                      dry_run=False, capture_output=True, timeout=60,
                      suppress_summary_error=True)
    if not ok:
        return None
    usage = _parse_gam_size(out, "usage")
    in_drive = _parse_gam_size(out, "usageInDrive")
    in_trash = _parse_gam_size(out, "usageInDriveTrash")
    if usage is None:
        return None
    return max(0, usage - (in_drive or 0) - (in_trash or 0))


def check_restore_destination_ready(destination: str, backup_path: Path,
                                    dry_run: bool) -> bool:
    """
    Check the destination can receive a restore: storage headroom and undated mail.

    Storage is pooled tenant-wide, so warns rather than blocks — the figure is an
    estimate and Gmail charges less than the backup's on-disk size.
    """
    if dry_run:
        return True

    reason = _email_mailbox_missing(destination)
    if reason:
        print_error(
            f"Destination {destination} has no usable Gmail mailbox "
            f"({reason}). Every message import would fail with 'Mail service "
            f"not enabled'. Assign a Workspace licence to the account first."
        )
        summary_error(f"Email restore to {destination} skipped: Gmail not enabled")
        return False

    ok, out = run_gam(["user", destination, "show", "drivesettings"],
                      dry_run=False, capture_output=True, timeout=60,
                      suppress_summary_error=True)
    if not ok:
        print_warning(
            f"Could not read storage settings for {destination}; skipping the "
            f"pre-flight storage check and continuing."
        )
        return True

    limit = _parse_gam_size(out, "limit")
    usage = _parse_gam_size(out, "usage")

    try:
        backup_bytes = sum(f.stat().st_size for f in backup_path.rglob("*.eml"))
    except OSError:
        backup_bytes = 0

    if limit and usage is not None and backup_bytes:
        headroom = limit - usage
        gb = 1024 ** 3
        print_info(
            f"Tenant storage (pooled): {usage / gb:.1f} GB used of "
            f"{limit / gb:.1f} GB, {headroom / gb:.1f} GB free. "
            f"Backup on disk: {backup_bytes / gb:.1f} GB."
        )
        if backup_bytes > headroom:
            print_warning(
                f"{Colours.RED}The backup ({backup_bytes / gb:.1f} GB) is larger "
                f"than the tenant's free pooled storage ({headroom / gb:.1f} GB). "
                f"The restore may fill the pool and start failing on quota part "
                f"way through. Add storage or reduce the migration scope before "
                f"running a large restore.{Colours.RESET}"
            )
            summary_warning(
                f"Restore to {destination} started with less free pooled storage "
                f"({headroom / gb:.1f} GB) than the backup size "
                f"({backup_bytes / gb:.1f} GB)"
            )

    undated = count_undated_messages(backup_path)
    if undated:
        print_warning(
            f"{undated} message(s) in this backup have no usable Date header "
            f"(stored at the Unix epoch, filed under 1970/). Gmail cannot date "
            f"them on import either, so they will arrive in {destination}'s "
            f"mailbox stamped with today's date rather than their original one. "
            f"Nothing can be done about this in GYB — it is caused by the "
            f"original sender. Mention it if the client asks why a handful of "
            f"old messages look new."
        )
        summary_warning(
            f"{undated} message(s) restored with today's date (no usable Date "
            f"header in the original)"
        )
    return True


def _build_batch_ladder(start: int) -> List[int]:
    """
    Batch sizes to fall back through when Gmail throttles: 100 -> 75 -> 50 -> 25 -> 10.

    Floors at 10 because below that GYB stops committing its resume DB mid-run.
    """
    # The floor is 10, or the operator's own value if they started lower.
    floor = min(10, start)
    ladder = [start, int(start * 0.75), int(start * 0.5), int(start * 0.25), floor]
    out: List[int] = []
    for size in ladder:
        size = max(floor, size)
        if size < (out[-1] if out else start + 1) and size not in out:
            out.append(size)
        elif not out:
            out.append(size)
    return out


def _restored_count(backup_path: Path, destination: str) -> int:
    """
    Messages GYB has committed to its resume DB for this destination.

    The reliable progress signal; GYB's stdout stalls and its denominator is
    post-skip. Returns 0 if the resume DB does not exist yet.
    """
    try:
        db_path = backup_path / f"{destination}-restored.sqlite"
        if not db_path.exists():
            return 0
        with _gyb_db(db_path) as db:
            row = db.execute("SELECT count(*) FROM restored_messages").fetchone()
            return int(row[0]) if row else 0
    except (sqlite3.Error, OSError):
        return 0


def _looks_rate_limited(gyb_output: str) -> bool:
    """
    Whether a failed run looks like throttling rather than a bad file.

    A suspended destination looks identical here; validate_destination() is
    what separates them, before the restore starts.
    """
    markers = ("rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded",
               "Backing off", "backendError")
    return any(m in gyb_output for m in markers)


def _looks_terminal(gyb_output: str) -> Optional[str]:
    """Return the terminal-refusal marker in a failed GYB run, or None.

    These are 400-class API refusals that no retry, batch step-down, or
    quarantine pass can fix — the request itself is being rejected. Retrying
    them burns attempts and (on a large corpus) full quarantine re-scans.
    Deliberately NOT including throttling/backend markers (see
    _looks_rate_limited) — those DO heal.
    """
    for marker in ("failedPrecondition", "Mail service not enabled",
                   "invalid_grant", "unauthorized_client"):
        if marker in gyb_output:
            return marker
    return None


def verify_backup_complete(backup_path: Path) -> Tuple[int, int]:
    """
    Check a GYB backup's message DB against the .eml files actually on disk.

    A backup whose DB claims messages it cannot produce restores silently
    short. The shortfall is CLASSIFIED before it is reported (issue #11's
    lesson: an unclassified "short = failed" rule recreates the exit-56
    false-failure trap): messages this tooling moved into the sibling
    <backup>_quarantined/ folder are deliberate exclusions (AV-flagged
    malware, never restored), so only a shortfall beyond those is data at
    risk. A genuine shortfall is a summary_error — inside a
    record_failure() context that holds licence removal back, keeping the
    Gmail access a re-download would need. Returns (db_rows, on_disk).

    A DB that is missing or unreadable is a summary_error, not an empty backup:
    callers detect failure by that count growing, and (0, 0) alone would pass a
    failed backup as one with no mail. The existence check comes first because
    sqlite3.connect() would otherwise CREATE the missing file.
    """
    db_path = backup_path / "msg-db.sqlite"
    try:
        if not db_path.is_file():
            raise FileNotFoundError("file does not exist")
        with _gyb_db(db_path) as db:
            rows = int(db.execute("SELECT count(*) FROM messages").fetchone()[0])
    except (sqlite3.Error, OSError) as e:
        print_error(f"Cannot verify the backup: {db_path} is missing or unreadable ({e}).")
        summary_error(
            f"Backup at {backup_path} could not be verified: {db_path} is "
            f"missing or unreadable ({e}). Re-run the backup."
        )
        return (0, 0)
    on_disk = sum(1 for _ in backup_path.rglob("*.eml"))
    if rows > on_disk:
        quarantine_dir = backup_path.parent / f"{backup_path.name}_quarantined"
        quarantined = (sum(1 for _ in quarantine_dir.rglob("*.eml"))
                       if quarantine_dir.is_dir() else 0)
        genuinely_missing = rows - on_disk - quarantined
        if genuinely_missing > 0:
            print_error(
                f"Backup is incomplete: msg-db lists {rows} message(s) but "
                f"{on_disk} .eml file(s) are on disk and only {quarantined} "
                f"are quarantined — {genuinely_missing} unaccounted for. "
                f"Re-run the backup to re-fetch them before restoring."
            )
            summary_error(
                f"Backup at {backup_path} is missing {genuinely_missing} "
                f"message(s) beyond the {quarantined} quarantined (DB {rows}, "
                f"disk {on_disk}). Re-run the backup to re-fetch them."
            )
        else:
            print_success(
                f"Backup verified: {rows} message(s); the {rows - on_disk} "
                f"not on disk are all in quarantine (deliberate exclusions)."
            )
    elif rows < on_disk:
        summary_warning(
            f"Backup at {backup_path} has {on_disk - rows} more .eml file(s) "
            f"on disk than msg-db lists ({rows}) — stray files from an "
            f"earlier run? The restore only sends what the DB lists."
        )
    else:
        print_success(f"Backup verified: {rows} message(s), DB matches disk.")
    return (rows, on_disk)


def count_undated_messages(backup_path: Path) -> int:
    """
    Count backup messages stored at the Unix epoch (unparseable sender Date).

    Gmail re-stamps these with the restore date, so warn before old mail
    arrives looking new. Returns 0 on any error; never blocks a run.
    """
    try:
        with _gyb_db(backup_path / "msg-db.sqlite") as db:
            row = db.execute(
                "SELECT count(*) FROM messages WHERE message_internaldate < ?",
                ("1971-01-01",),
            ).fetchone()
            return int(row[0]) if row else 0
    except (sqlite3.Error, OSError):
        return 0


# How old (days) an existing mailbox backup folder may be and still be
# reused WITHOUT asking, under --force. Retried offboardings span days;
# a folder older than this is far more likely a previous engagement
# (e.g. a rehire's first offboarding), and resuming into one would
# restore mail the user has long since deleted.
REUSE_BACKUP_MAX_AGE_DAYS = 30


def _select_backup_path(subdir: str, name_prefix: str, is_backup, kind: str,
                        verb: str, force: bool) -> Path:
    """Pick a dated backup folder under BACKUP_DIRECTORY/<subdir>, offering
    to resume the newest prior one.

    The folder name is date-stamped, so a re-run on a LATER day used to mint
    a fresh folder and re-download everything from scratch: on a real 107 GB
    mailbox that was a full lost day. When a prior folder for this user
    exists (identified by `is_backup(path)`), ask the operator whether to
    resume into it; under --force, resume automatically if it is within
    REUSE_BACKUP_MAX_AGE_DAYS and start fresh if older. Only folders named
    <prefix>_YYYYMMDD[_HHMMSS] are considered, so the mailbox picker never
    sees the backup-email phase's <user>_email_YYYYMMDD siblings.
    """
    root = BACKUP_DIRECTORY / subdir
    prior = sorted(
        p for p in root.glob(f"{name_prefix}_*")
        if re.fullmatch(re.escape(name_prefix) + r"_\d{8}(_\d{6})?", p.name)
        and is_backup(p)
    )
    if prior:
        newest = prior[-1]
        stamp = re.search(r"_(\d{8})(?:_\d{6})?$", newest.name).group(1)  # type: ignore[union-attr]
        age_days = (datetime.now() - datetime.strptime(stamp, "%Y%m%d")).days
        if force:
            reuse = age_days <= REUSE_BACKUP_MAX_AGE_DAYS
            print_info(
                f"Found existing {kind} backup {newest.name} "
                f"({age_days} day(s) old): "
                + (f"{verb} into it (--force, within "
                   f"{REUSE_BACKUP_MAX_AGE_DAYS} days)." if reuse else
                   f"older than {REUSE_BACKUP_MAX_AGE_DAYS} days, starting a "
                   f"fresh download instead.")
            )
        else:
            reuse = prompt_yes_no(
                f"Found an existing {kind} backup {newest.name} "
                f"({age_days} day(s) old). {verb.capitalize()} into it "
                f"(only new/changed content is fetched) instead of "
                f"downloading from scratch?",
                default=True,
            )
        if reuse:
            return newest
    fresh = root / f"{name_prefix}_{datetime.now().strftime('%Y%m%d')}"
    if fresh.exists():
        # Declined reuse on the same day the existing folder is named for:
        # a fresh folder needs a distinct name or the tool resumes anyway.
        fresh = root / f"{name_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    return fresh


def _select_email_backup_path(source: str, force: bool = False) -> Path:
    """Mailbox backup folder: a GYB backup is one that holds msg-db.sqlite."""
    return _select_backup_path("mailboxes", source,
                               lambda p: (p / "msg-db.sqlite").exists(),
                               "mailbox", "resuming", force)


# High ceiling is safe: resume means each attempt continues where the last
# died, and the loop bails out early once it stops making progress.
MAX_RESTORE_ATTEMPTS = 20


def next_restore_action(progressed: int, gyb_output: str, newly_quarantined: int,
                        stalled: int, ladder_pos: int,
                        ladder: List[int]) -> Tuple[str, int, int]:
    """Decide what the restore loop does after a failed attempt.

    Pure, so the ladder and bail-out rules are table-testable without
    scripting GYB. Returns (action, ladder_pos, stalled) where action is:
      STOP_TERMINAL  a 400-class refusal with nothing restored (2026-08-03
                     dev round burned attempts, each with a full quarantine
                     re-scan, on a failedPrecondition the first response had
                     already decided);
      STEP_DOWN      throttling: continue with the next smaller batch size.
                     Only throttling steps the ladder, because a smaller batch
                     is slower and an AV crash must not drag it down;
      STOP_STALLED   three consecutive attempts that neither restored anything
                     nor cleared a blocker;
      RETRY          otherwise.
    """
    if progressed == 0 and _looks_terminal(gyb_output):
        return "STOP_TERMINAL", ladder_pos, stalled
    action = "RETRY"
    if _looks_rate_limited(gyb_output) and ladder_pos < len(ladder) - 1:
        ladder_pos += 1
        action = "STEP_DOWN"
    if progressed == 0 and not newly_quarantined:
        stalled += 1
        if stalled >= 3:
            return "STOP_STALLED", ladder_pos, stalled
    else:
        stalled = 0
    return action, ladder_pos, stalled


def migrate_email(source: str, destination: str, dry_run: bool, strip_labels: bool = True,
                  reuse_backup: Optional[Path] = None, batch_size: int = RESTORE_BATCH_SIZE,
                  force: bool = False):
    """
    [OPTIONAL] Back up and restore email using GYB.

    When strip_labels is True (the default), GYB's --strip-labels is passed on
    restore so all original Gmail labels — including INBOX — are discarded, and
    the only label remaining on each restored message is Migrated/<source-user>.
    Effectively this archives the migrated mail under a single namespaced label.
    When False, original labels (INBOX, custom labels, system labels) are
    preserved and the migration label is added on top.

    When reuse_backup is given, the GYB backup step is SKIPPED and the restore
    runs against that existing local backup folder. Use this to resume a restore
    that died partway (e.g. on an AV-locked message) without re-downloading a
    large mailbox — Gmail dedupes re-restored messages server-side, so it is
    safe. The path must be a GYB backup folder (contains msg-db.sqlite).

    GYB syntax:
      gyb --email <src> --action backup --local-folder <path>
      gyb --email <dst> --action restore --local-folder <path>
    """
    print_header("EMAIL MIGRATION")

    if not validate_destination(destination):
        summary_error(f"Email migration skipped: destination {destination} invalid")
        return

    print_info(f"Migrating email: {source} -> {destination}")

    if reuse_backup is not None:
        # Restore-only: skip backup, restore from the existing folder.
        backup_path = reuse_backup
        if not dry_run and not (backup_path / "msg-db.sqlite").exists():
            print_error(
                f"--reuse-email-backup path is not a GYB backup folder "
                f"(no msg-db.sqlite): {backup_path}"
            )
            summary_error(f"Email restore skipped: invalid reuse-backup path {backup_path}")
            return
        print_info(f"Reusing existing backup (skipping download): {backup_path}")
    else:
        backup_path = _select_email_backup_path(source, force=force)
        if not dry_run:
            backup_path.mkdir(parents=True, exist_ok=True)

        # Backup
        print_info(f"Backing up email to: {backup_path}")
        print_info(SPAM_TRASH_NOTE)
        print_info(
            "GYB will print a live progress bar (e.g. ' 42%|####  | 1234/2950 [01:23<02:45]'). "
            "For large mailboxes this phase can run for tens of minutes."
        )
        success, _ = run_gyb(
            ["--email", source, "--action", "backup", "--local-folder", str(backup_path)],
            dry_run=dry_run
        )
        if not success and not dry_run:
            print_error("Email backup failed; skipping restore.")
            summary_error("Email backup failed")
            return
        if not dry_run:
            errors_before = len(summary_errors)
            verify_backup_complete(backup_path)
            if len(summary_errors) > errors_before:
                # A short backup restores short. The error is already recorded
                # and holds licence removal; do not restore on top of it and
                # then report "Email migrated".
                print_error("Backup failed verification; restore skipped. "
                            "Re-run to fetch the missing messages.")
                return

    # Pre-flight the destination before spending hours on a doomed restore.
    if not check_restore_destination_ready(destination, backup_path, dry_run):
        summary_error(f"Email restore to {destination} skipped: destination not ready")
        return

    # Pre-scan: move any unreadable (AV-quarantined) messages aside so the
    # restore cannot crash on them. See quarantine_unreadable_messages().
    skipped: List[str] = []
    if not dry_run:
        print_info("Scanning backup for unreadable (AV-quarantined) messages...")
        skipped = quarantine_unreadable_messages(backup_path)

    # Restore
    migration_label = f"Migrated/{source}"
    # GYB 1.95 creates the --label-restored label with a leading underscore, so
    # what lands in the destination is '_Migrated/<source>', not the name passed
    # here. Report the landed name: an admin searching Gmail for the name we
    # asked for finds nothing. Verified 2026-08-31 on GYB 1.95 (Win/Linux/macOS).
    landed_label = f"_{migration_label}"
    mode_desc = "archived under single label" if strip_labels else "original labels preserved + migration label"
    print_info(f"Restoring email to: {destination} (label: {landed_label}; {mode_desc})")
    restore_args = ["--email", destination, "--action", "restore",
                    "--local-folder", str(backup_path),
                    "--label-restored", migration_label,
                    # Batch messages so the restore is fast AND commits its
                    # resume DB per batch (GYB's default of 1 is serial and only
                    # commits at end — a crash then restarts from scratch).
                    "--batch-size", str(batch_size)]
    if strip_labels:
        restore_args.append("--strip-labels")
    print_info(f"Restore batch size: {batch_size} (messages <=1MB per import request)")

    # Restore with auto-recovery from AV-locked messages.
    #
    # Endpoint AV can lock a malicious .eml at ANY moment — even after the
    # pre-scan read it cleanly, and non-deterministically (the same file can
    # read fine one moment and raise PermissionError the next). A single locked
    # file kills GYB's restore mid-run because GYB has no per-message read-error
    # handling. So one clean pre-scan can't guarantee a clean restore.
    #
    # Re-running the restore is SAFE: GYB makes no attempt to de-duplicate, but
    # Gmail's servers do — importing the exact same message twice leaves one
    # copy (GYB maintainer, jay0lee, GYB discussion #446). So messages already
    # restored before a crash collapse to a single copy on the next pass and
    # the run continues past the poison. On each failure we quarantine whatever
    # is unreadable right now (moving it aside makes GYB skip it — its own
    # os.path.isfile check) and retry. The malware is intentionally never
    # restored to the successor.
    #
    success = False
    batch_ladder = _build_batch_ladder(batch_size)
    ladder_pos = 0
    stalled = 0
    for attempt in range(1, MAX_RESTORE_ATTEMPTS + 1):
        before = _restored_count(backup_path, destination)
        # Keep recovered intermediate failures out of the end-of-run summary.
        success, gyb_output = run_gyb(
            restore_args, dry_run=dry_run,
            suppress_summary_error=(attempt < MAX_RESTORE_ATTEMPTS),
        )
        if success or dry_run:
            break
        if shutdown_requested:
            # We terminated GYB ourselves. Quarantine re-scans and retries
            # after that are minutes of disk reads the operator asked to stop.
            print_warning("Restore interrupted by operator (Ctrl+C).")
            break
        progressed = _restored_count(backup_path, destination) - before

        if progressed == 0 and _looks_terminal(gyb_output):
            newly: List[str] = []
        else:
            # Prefer the file named in the crash; a re-scan races the AV lock
            # and often finds nothing, leaving the next attempt to die on the
            # same file.
            newly = quarantine_gyb_locked_file(backup_path, gyb_output)
            if not newly:
                newly = quarantine_unreadable_messages(backup_path)
            skipped.extend(m for m in newly if m not in skipped)

        action, ladder_pos, stalled = next_restore_action(
            progressed, gyb_output, len(newly), stalled, ladder_pos, batch_ladder)
        if action == "STOP_TERMINAL":
            print_error(
                f"Restore refused with a terminal error (no retry can "
                f"succeed): {_looks_terminal(gyb_output)}. Stopping after "
                f"attempt {attempt} instead of retrying."
            )
            break
        if action == "STEP_DOWN":
            new_size = batch_ladder[ladder_pos]
            restore_args[restore_args.index("--batch-size") + 1] = str(new_size)
            print_warning(
                f"Gmail is throttling the restore; stepping batch size down to "
                f"{new_size} (ladder: {' -> '.join(str(b) for b in batch_ladder)})."
            )
        if action == "STOP_STALLED":
            print_error(
                f"Restore made no progress across {stalled} consecutive "
                f"attempts and found nothing to quarantine; stopping rather "
                f"than retrying {MAX_RESTORE_ATTEMPTS - attempt} more times."
            )
            break

        if attempt < MAX_RESTORE_ATTEMPTS:
            print_warning(
                f"Restore attempt {attempt}/{MAX_RESTORE_ATTEMPTS} failed; "
                f"restored {progressed} message(s) before dying, quarantined "
                f"{len(newly)}. Retrying — resume skips what already landed and "
                f"Gmail dedupes anything re-sent."
            )
    if not success and not dry_run:
        print_error(f"Email restore failed; backup retained at {backup_path}")
        # `attempt` is the number actually run — the stall bail-out usually
        # stops well before the ceiling, and reporting the ceiling here made
        # a 3-attempt failure read as 20.
        summary_error(
            f"Email restore to {destination} FAILED after {attempt} "
            f"attempt(s); backup retained at {backup_path}. Re-run the same gyb "
            f"restore command (resume is on by default) or re-run this script. "
            f"If AV keeps locking messages mid-restore, add an on-access-scan "
            f"exclusion for {backup_path.parent} in the endpoint AV policy."
        )
        return
    migrated_desc = f"Email migrated to {destination} under label '{landed_label}' ({mode_desc})"
    if skipped:
        migrated_desc += f", excluding {len(skipped)} unreadable/AV-quarantined message(s)"
    if not dry_run:
        # GYB exit 0 is the claim; its resume DB is the evidence. Count what
        # it committed against what was on disk to send.
        restored = _restored_count(backup_path, destination)
        to_send = sum(1 for _ in backup_path.rglob("*.eml"))
        migrated_desc += f"; GYB resume DB: {restored} restored of {to_send} on disk"
        if restored < to_send:
            summary_warning(
                f"Email restore to {destination}: GYB's resume DB lists "
                f"{restored} restored message(s) but {to_send} .eml files were "
                f"on disk to send. Re-run the same restore (resume is on by "
                f"default) and compare again."
            )
    summary_action(migrated_desc)


def transfer_calendar(source: str, destination: str, dry_run: bool):
    """
    [RECOMMENDED] Add the destination user as a manager of the
    departing user's calendar so they can see/manage existing events.

    GAM7:
      gam user <source> add calendaracls <source> writer user:<destination>

    NOTE: Full calendar ownership transfer is now possible via the
    Google Admin console (October 2025 update), but not yet directly
    via the Calendar API/GAM. This step grants editor access as
    the closest API-supported equivalent.
    """
    print_header("CALENDAR ACCESS TRANSFER")

    print_info(f"Granting calendar editor access: {source} -> {destination}")
    # GAM7 syntax: gam user <src> add calendaracls <calendarid> <role> user:<email>
    # Use the source email as the calendar ID (their primary calendar).
    # Role 'writer' is the Calendar API name for what the UI calls
    # "Make changes to events" (editor-level access).
    ok, _ = run_gam(
        ["user", source, "add", "calendaracls", source, "writer", f"user:{destination}"],
        dry_run=dry_run
    )
    if ok:
        summary_action(f"Calendar editor access granted to {destination}")


###############################################################################
# EMAIL FORWARDING [RECOMMENDED]
# Sets up email forwarding to a successor so incoming mail is not lost.
###############################################################################

def setup_forwarding(email: str, forward_to: str, dry_run: bool):
    """
    [RECOMMENDED] Set up email forwarding to a successor.

    Three steps (GAM7 wiki, Users-Gmail-Forwarding):
      1. gam user <email> add forwardingaddress <forward_to>
      2. wait until `show forwardingaddresses` reports it accepted
      3. gam user <email> forward on <forward_to> keep

    The 'keep' action leaves a copy in the departing user's mailbox
    (useful for Vault retention). Alternatives: archive, delete, markread.

    EDGE CASE: Forwarding only works within the same domain or to
    verified alias/secondary domains. Cross-domain forwarding may fail.

    EDGE CASE: The forwarding address must be registered BEFORE it
    can be activated. There may be a brief delay between the two steps.
    """
    print_header("EMAIL FORWARDING SETUP")

    # Step 1: Register the forwarding address
    print_info(f"Registering forwarding address: {forward_to}")
    success, output = run_gam(
        ["user", email, "add", "forwardingaddress", forward_to],
        dry_run=dry_run,
        capture_output=True,
        non_fatal_patterns=["already exists"]
    )

    if not dry_run and not success:
        print_error(f"Could not register forwarding address. Output: {output}")
        summary_error(f"Forwarding registration failed for {forward_to}")
        return

    if not dry_run and "already exists" in output.lower():
        print_info("Forwarding address already registered — continuing to activate.")

    # Step 2: Wait until the address shows verificationStatus=accepted.
    # Activating before verification propagates fails with
    # "Set Failed: Invalid forwarding address" even for same-domain destinations.
    if not dry_run:
        print_info("Waiting for forwarding address to be verified...")
        verified = False
        deadline = time.time() + 60  # poll up to 60s total
        attempt = 0
        while time.time() < deadline:
            attempt += 1
            # suppress_summary_error: a transient poll failure must not add
            # one summary error line per attempt; the unverified outcome is
            # reported once below if the deadline passes.
            ok, status_output = run_gam(
                ["user", email, "show", "forwardingaddresses"],
                dry_run=False,
                capture_output=True,
                timeout=30,
                stdout_only=True,
                suppress_summary_error=True
            )
            if ok:
                # Match 'accepted' on the SAME line as the target address.
                # A substring check across the whole output false-positives
                # when a DIFFERENT, previously registered forwarding address
                # is already accepted while the target is still pending.
                for status_line in status_output.lower().splitlines():
                    if forward_to.lower() in status_line and "accepted" in status_line:
                        verified = True
                        break
                if verified:
                    print_success(
                        f"Forwarding address verified after {attempt} check(s)."
                    )
                    break
            if shutdown_requested:
                break
            time.sleep(3)

        if not verified:
            # Timing is not the whole story, and the old "within 60s" wording
            # implied it was. Same-domain auto-acceptance is inconsistent: over
            # five dev runs on 2026-08-31 one destination was accepted on the
            # FIRST poll while three others were still 'pending' an hour later,
            # never having moved. When it does not auto-accept, Gmail mails a
            # "Forwarding Confirmation" from forwarding-noreply@google.com to
            # the DESTINATION and the address stays pending until someone opens
            # it — so polling longer is not reliably the answer, and the
            # operator needs to be sent to that mailbox, not back to a wait.
            # Activating while pending genuinely fails ("Set Failed: Invalid
            # forwarding address"), so skipping here is correct.
            print_error(
                f"Forwarding address {forward_to} is still 'pending' after 60s, "
                f"so activation is skipped."
            )
            print_info(
                f"Gmail does not always auto-accept a same-domain destination. "
                f"When it does not, it sends a 'Forwarding Confirmation' from "
                f"forwarding-noreply@google.com to {forward_to}, and the address "
                f"stays pending until that mail is confirmed. Read it with:"
            )
            # showbody: the confirmation link is in the body, and `show messages`
            # prints headers only without it.
            print_info(
                f"  gam user {forward_to} show messages query "
                f"\"from:forwarding-noreply@google.com\" showbody"
            )
            print_info(
                f"The alias / recipient-address-map / group options in the MANUAL "
                f"ACTION block below need no confirmation and, unlike Gmail "
                f"forwarding, survive suspension."
            )
            summary_error(
                f"Forwarding NOT activated for {email}: {forward_to} still awaiting "
                f"confirmation in the destination mailbox. Once confirmed, run: "
                f"gam user {email} forward on {forward_to} keep"
            )
            return

    # Step 3: Activate forwarding
    print_info(f"Activating forwarding: {email} -> {forward_to} (keep copy)")
    activate_ok, _ = run_gam(
        ["user", email, "forward", "on", forward_to, "keep"],
        dry_run=dry_run,
        capture_output=True
    )

    if dry_run or activate_ok:
        summary_action(f"Email forwarding set to {forward_to} (keep copy)")
    else:
        summary_error(
            f"Forwarding activation failed for {email} -> {forward_to}. "
            f"Retry with: gam user {email} forward on {forward_to} keep"
        )


###############################################################################
# RCLONE DRIVE BACKUP [RECOMMENDED]
# Downloads the user's entire Drive to local disk before any transfers.
###############################################################################

def check_shared_drives(email: str, dry_run: bool) -> List[str]:
    """
    Report Shared Drives the leaver organizes, flagging any they organize ALONE.

    Nothing in an offboarding touches Shared Drives. Their content is owned by
    the drive, not by a member, so `gam transfer drive` (My Drive ownership)
    moves none of it and rclone — which walks the user's own Drive tree — backs
    up none of it. A leaver who is the SOLE organizer therefore leaves a drive
    that, once the account is deleted, no one can add members to, change
    settings on, or delete.

    GAM cannot fix this as part of the transfer because there is no correct
    automatic answer to who should inherit it. So this reports and instructs,
    the same way the mail-capture block does.

    Returns the drives that must BLOCK an irreversible deletion: those left
    without another organizer, PLUS those whose membership could not be read.
    An unread ACL is not evidence of safety — treating "we could not check" as
    "nothing to worry about" is the same mistake as reporting it as orphaned,
    just in the direction that loses the drive. The same holds one level up: a
    drive LIST that cannot be read or parsed comes back as one entry naming the
    failure, because an empty list means "no drives" and unlocks the deletion.
    """
    if dry_run:
        print_info("DRY RUN: would check Shared Drive memberships")
        return []

    # GAM exits 60 on `print shareddrives` when the user is in NO shared drive,
    # even though the query succeeded and printed the CSV header. Without this
    # pattern every ordinary leaver triggers the "check by hand" warning below —
    # exactly the case where there is nothing to check. Verified 2026-08-31 on
    # GAM 7.48.01 on dev.
    ok, out = run_gam(["user", email, "print", "shareddrives"],
                      dry_run=False, capture_output=True, timeout=180,
                      non_fatal_patterns=["got 0 shared drives"],
                      suppress_summary_error=True)
    if not ok:
        print_warning(
            f"Could not list Shared Drives for {email}; check by hand whether "
            f"they solely organize any before deleting the account."
        )
        summary_warning(f"Shared Drive check inconclusive for {email}")
        return [f"Shared Drive list for {email} could not be read"]

    try:
        rows = list(csv.DictReader(io.StringIO(
            out[out.index("User,id,name,role"):])))
    except (ValueError, csv.Error):
        # Never fail silently: an unparseable list is indistinguishable from
        # "no shared drives" to the operator, and that is the wrong reading.
        print_warning(
            f"Could not parse the Shared Drive list for {email} (unexpected "
            f"GAM output). Check by hand whether they solely organize any "
            f"before deleting the account."
        )
        summary_warning(f"Shared Drive check inconclusive for {email}")
        return [f"Shared Drive list for {email} could not be parsed"]

    organized = [r for r in rows if (r.get("role") or "").lower() == "organizer"]
    if not organized:
        print_info("No Shared Drives organized by this user.")
        return []

    orphaned: List[str] = []
    unknown: List[str] = []
    for row in organized:
        drive_id, name = row.get("id", ""), row.get("name", "(unnamed)")
        # CSV, not `show drivefileacls`: the text form prints role and
        # emailAddress on separate lines with no stable ordering between them,
        # so pairing them by proximity is guesswork. The CSV gives indexed
        # permissions.N.emailAddress / permissions.N.role columns that pair
        # unambiguously.
        ok_acl, acl = run_gam(["user", email, "print", "drivefileacls", drive_id],
                              dry_run=False, capture_output=True, timeout=120,
                              suppress_summary_error=True)
        # Another organizer means the drive stays manageable without the leaver.
        # A FAILED read is not the same as "no other organizer" — reporting an
        # unread ACL as orphaned states as fact something we never saw.
        if not ok_acl:
            unknown.append(f"{name} ({drive_id})")
            continue
        others = 0
        try:
            acl_rows = list(csv.DictReader(io.StringIO(
                acl[acl.index("Owner,"):])))
        except (ValueError, csv.Error):
            unknown.append(f"{name} ({drive_id})")
            continue
        for acl_row in acl_rows:
            for key, addr in acl_row.items():
                m_perm = re.fullmatch(r"permissions\.(\d+)\.emailAddress", key or "")
                if not m_perm or not addr:
                    continue
                role = acl_row.get(f"permissions.{m_perm.group(1)}.role", "")
                if (addr.lower() != email.lower()
                        and (role or "").lower() == "organizer"):
                    others += 1
        if others == 0:
            orphaned.append(f"{name} ({drive_id})")

    print_warning(
        f"{email} organizes {len(organized)} Shared Drive(s). NONE of their "
        f"content is backed up or transferred by this script — Shared Drive "
        f"files are owned by the drive, not by the user."
    )
    if orphaned:
        print_error(
            f"{Colours.RED}{len(orphaned)} Shared Drive(s) have NO other "
            f"organizer. Once this account is deleted no MEMBER can add "
            f"members, change settings or delete them; recovering one then "
            f"means a super admin taking it over in Admin console -> Apps -> "
            f"Google Workspace -> Drive and Docs -> Manage shared drives:"
            f"{Colours.RESET}"
        )
        for item in orphaned:
            print_error(f"    - {item}")
        print_error(
            "Cheaper to fix now. Add a replacement organizer BEFORE deleting "
            "the account, running it AS the leaver — they are the only "
            "organizer, and a non-member cannot grant themselves access (GAM "
            "answers 'Add Failed: Does not exist'):\n"
            f"    gam user {email} add drivefileacl <driveId> "
            "user <new-organizer> role organizer"
        )
        summary_warning(
            f"{len(orphaned)} Shared Drive(s) left with no organizer other than "
            f"{email}: {'; '.join(orphaned)}"
        )
    elif not unknown:
        summary_warning(
            f"{email} organizes {len(organized)} Shared Drive(s); content not "
            f"backed up or transferred (other organizers remain)"
        )
    if unknown:
        print_warning(
            f"Could not read the membership of {len(unknown)} Shared Drive(s), "
            f"so whether {email} is their only organizer is UNKNOWN — check "
            f"each by hand before deleting the account:"
        )
        for item in unknown:
            print_warning(f"    - {item}")
        summary_warning(
            f"Shared Drive membership unread for {len(unknown)} drive(s) "
            f"({'; '.join(unknown)}); sole-organizer status unknown"
        )
    return orphaned + unknown


def _count_unexportable(out: str) -> int:
    """
    Count Forms and Sites in `gam print filelist fields id,mimetype` output.

    Drive's export API has no format for either, so rclone never lists them and
    they can never be in a Drive backup. That makes them a deliberate exclusion
    rather than data at risk, which is the distinction a shortfall has to be
    classified on before it is called an error — the same split the mail path
    makes between quarantined and genuinely missing messages.

    Counts substring matches rather than parsing the CSV: run_gam merges GAM's
    stderr progress lines into the output, so a strict DictReader over the whole
    string trips on them.
    """
    return (out.count("application/vnd.google-apps.form")
            + out.count("application/vnd.google-apps.site"))


def _parse_gam_got_count(out: str) -> int:
    """
    Read the file count out of `gam print filelist` output.

    Uses GAM's own tally rather than counting lines: run_gam merges stderr into
    stdout and GAM writes its progress there, so a raw line count over-reports.

    GAM prints one "Got N" per PAGE, separated by carriage returns, and N is the
    running total — so the LAST one is the answer and the first is a page-size
    reading. Measured on dev 2026-07-29: a 256-file user paged at 100 printed
    "Got 100\rGot 200\rGot 256". Taking the first match reported 100 for that
    user, which on a real Drive (pages of 1000) means a 4,800-file backup
    "verifies" against a Drive read as 1,000 and every shortfall goes unseen.
    """
    counts = re.findall(r"Got (\d+) Drive Files/Folders", out)
    if counts:
        return int(counts[-1])
    # Fall back to CSV rows after the header. Only id/mimeType are requested,
    # so no field can contain an embedded newline — file NAMES can (and one in
    # the dev fixture does), which would break this. Progress lines carry no
    # comma, so requiring one keeps any stray stderr line out of the count.
    lines = [ln for ln in out.splitlines() if ln.strip()]
    header = next((i for i, ln in enumerate(lines) if ln.startswith("Owner,")), None)
    if header is None:
        return 0
    return sum(1 for ln in lines[header + 1:] if "," in ln)


def verify_drive_backup_complete(email: str, backup_path: Path,
                                 duplicates: Optional[List[str]] = None) -> Tuple[int, int]:
    """
    Reconcile the files in the user's Drive against the files rclone wrote.

    Drive is not a filesystem: it allows two files with the SAME NAME in the
    same folder, distinguished only by file ID. A filesystem cannot, so when
    both export to the same extension (two Google Docs called "Notes" both
    become "Notes.docx") the second overwrites the first. rclone treats that as
    an ordinary destination write, exits 0, and the backup is silently short.
    Nothing else in the run notices — the same failure shape as the GYB restore
    defects: data lost, exit code clean.

    "Untitled document" is the most common filename in Drive, so this is a
    routine case, not a contrived one.

    `duplicates` carries the paths rclone itself named as same-name collisions
    ("NOTICE: <path>: Duplicate object found in source - ignoring"). When we
    have them, the warning lists the files that were actually dropped instead of
    naming three possible causes.

    Returns (drive_files, local_files). Counts only, no listing of every file,
    to stay cheap on a large Drive.
    """
    # `trashed = false` is load-bearing: GAM's filelist INCLUDES trashed files
    # by default and rclone downloads none of them, so counting the default
    # list reports a shortfall for every user with a non-empty bin — i.e. most
    # of them. Measured on the dev fixture: 134 counted vs 126 untrashed.
    ok, out = run_gam(
        ["user", email, "print", "filelist", "fields", "id,mimetype",
         "query", "mimeType != 'application/vnd.google-apps.folder' "
                  "and trashed = false"],
        dry_run=False, capture_output=True, timeout=600,
        suppress_summary_error=True,
    )
    if not ok:
        print_warning(
            "Could not list Drive to reconcile the backup; skipping the "
            "completeness check. Verify the file count by hand before deleting "
            "the source account."
        )
        return (0, 0)

    drive_files = _parse_gam_got_count(out)

    local_files = sum(1 for p in backup_path.rglob("*") if p.is_file())

    # Classify the shortfall before reporting it, the way verify_backup_complete
    # does for mail (issue #11). Forms and Sites have no export format at all,
    # so rclone never lists them and their absence is a deliberate, unavoidable
    # exclusion — not data at risk. Everything else missing IS at risk. The
    # mimetype column is already in the filelist query above, so this costs no
    # extra call.
    unexportable = _count_unexportable(out)
    shortfall = max(drive_files - local_files, 0)
    genuinely_missing = max(shortfall - unexportable, 0)

    if duplicates:
        # rclone named them, so they are known losses whatever the totals say:
        # a folder resumed on top of an earlier backup can carry leftovers that
        # pad local_files past drive_files and hide the shortfall.
        # rclone named them, so stop guessing at causes for these ones.
        print_warning(
            f"{Colours.RED}Drive backup is SHORT: {drive_files} file(s) owned "
            f"in Drive but {local_files} on disk ({drive_files - local_files} "
            f"missing). rclone named {len(duplicates)} of them as same-name "
            f"collisions and dropped them — on Drive they are distinct file "
            f"IDs, on disk the second would overwrite the first:{Colours.RESET}"
        )
        for item in duplicates:
            print_warning(f"    - {item}")
        print_warning(
            "These are NOT in this backup. Rename them in Drive and re-run, or "
            "transfer ownership instead. Any remaining shortfall is Forms and "
            "Sites (not exportable, so never listed) or files owned here but "
            "parented only in someone else's folder."
        )
        # rclone NAMED these, so they are known losses, not a maybe. An error
        # (not a warning) so exit_code goes non-zero and the enclosing
        # record_failure() holds licence removal — the same treatment the mail
        # path gives an unexplained shortfall. Before this, a short Drive backup
        # warned loudly and still exited 0, so any wrapper reading only the exit
        # status went on to delete the source account (issue #11).
        summary_error(
            f"Drive backup at {backup_path} is short by {shortfall} file(s); "
            f"rclone dropped these as same-name collisions: "
            f"{'; '.join(duplicates)}"
        )
    elif drive_files and local_files < drive_files and genuinely_missing:
        summary_error(
            f"Drive backup at {backup_path} is short by {shortfall} file(s), "
            f"{genuinely_missing} of them unaccounted for beyond the "
            f"{unexportable} Form(s)/Site(s) that cannot be exported "
            f"(Drive {drive_files}, on disk {local_files}). Verify before "
            f"deleting the source account."
        )
        print_warning(
            f"{Colours.RED}Drive backup is SHORT: {drive_files} file(s) owned in "
            f"Drive but {local_files} on disk. {unexportable} are Forms/Sites "
            f"that cannot be exported; {genuinely_missing} are unaccounted "
            f"for.{Colours.RESET}"
        )
    elif drive_files and local_files < drive_files:
        # Shortfall fully explained by Forms/Sites: a real limit of the export
        # API, nothing an operator can fix, so it stays a warning.
        print_warning(
            f"Drive backup is short by {shortfall} file(s), all of them "
            f"Forms/Sites that have no export format. Nothing else is missing. "
            f"A Form carries its response data — transfer its ownership rather "
            f"than relying on this backup."
        )
        summary_warning(
            f"Drive backup at {backup_path} excludes {unexportable} "
            f"Form(s)/Site(s) (not exportable); nothing else is missing"
        )
    elif drive_files == local_files:
        print_success(f"Drive backup verified: {local_files} file(s), matches Drive.")
    elif drive_files:
        # More on disk than in Drive. Not a loss, but "matches" would be a lie:
        # usually leftovers from an earlier backup in the same dated folder.
        print_info(
            f"Drive backup holds {local_files} file(s) against {drive_files} "
            f"in Drive. Nothing is missing; the extra files are most likely "
            f"left over from an earlier backup into the same folder."
        )

    # Trashed files are excluded from the comparison above because rclone does
    # not fetch them. That makes the count honest, but it also means a leaver's
    # bin is silently absent from the backup — and a bin can hold work deleted
    # in the last 30 days. Report it rather than let it disappear quietly.
    # Ask for the bin directly rather than listing the whole Drive a second
    # time and subtracting: on the 130k-file load fixture each full listing
    # is minutes, the bin is usually a few rows.
    ok_all, out_all = run_gam(
        ["user", email, "print", "filelist", "fields", "id",
         "query", "mimeType != 'application/vnd.google-apps.folder' "
                  "and trashed = true"],
        dry_run=False, capture_output=True, timeout=600,
        suppress_summary_error=True,
    )
    trashed = _parse_gam_got_count(out_all) if ok_all else 0
    if trashed > 0:
        print_warning(
            f"{trashed} file(s) are in {email}'s TRASH and are NOT in this "
            f"backup (rclone does not fetch trashed files). Google purges the "
            f"bin 30 days after deletion, and deleting the account destroys it "
            f"immediately. Restore anything still wanted in Drive first, then "
            f"re-run the backup."
        )
        summary_warning(
            f"{trashed} trashed file(s) for {email} were not backed up"
        )
    return (drive_files, local_files)


def _select_drive_backup_path(email: str, force: bool = False) -> Path:
    """Drive backup folder: any non-empty directory; rclone sync is
    naturally incremental so resuming into it is free."""
    return _select_backup_path("drive", email,
                               lambda p: p.is_dir() and any(p.iterdir()),
                               "Drive", "syncing", force)


def backup_drive_rclone(email: str, dry_run: bool, force: bool = False) -> bool:
    """
    [RECOMMENDED] Back up user's Drive to local disk via rclone.

    Uses --drive-impersonate to access the user's Drive via domain-wide
    delegation (same service account as GAM7). Re-runs offer to sync into
    the newest prior backup folder instead of re-downloading everything.

    Returns True on success, False on failure.
    """
    print_header("DRIVE BACKUP (RCLONE)")

    backup_path = _select_drive_backup_path(email, force=force)
    if not dry_run:
        backup_path.mkdir(parents=True, exist_ok=True)

    rclone_args = [
        RCLONE_COMMAND, "sync",
        f"{RCLONE_REMOTE}:", str(backup_path),
        "--drive-impersonate", email,
        "--drive-export-formats", RCLONE_EXPORT_FORMATS,
        "-P", "--fast-list", "--transfers=4"
    ]
    cmd_str = " ".join(rclone_args)

    if dry_run:
        print_info(f"DRY RUN: {cmd_str}")
        summary_action(f"Drive backup planned to {backup_path}")
        return True

    print_info(f"Backing up Drive to: {backup_path}")
    print_info(
        "rclone -P prints a live transfer summary (Transferred: X / Y, N%, "
        "MiB/s, ETA). Updates are throttled to one log line per second."
    )

    try:
        # rclone -P repaints its summary using \r; progress redraws are
        # throttled to one log entry per second to keep the log manageable.
        last_progress_log = 0.0
        last_summary_line = ""

        # Drive refuses to serve files it has flagged as malware/spam, so a
        # backup can be short by those files alone. Name them rather than
        # reporting the whole backup as failed.
        abusive_files: List[str] = []
        # Matched off per-file "ERROR : <name>: Failed to copy" lines only; the
        # "Attempt N/3" lines name no file and "Errors: N" needs -P.
        failed_files: List[str] = []
        # rclone NAMES the files it drops to a same-name collision:
        #   NOTICE: <path>: Duplicate object found in source - ignoring
        # It is a NOTICE, not an error, and the run still exits 0 — but it is
        # the exact list the reconciliation can otherwise only guess at.
        duplicate_files: List[str] = []

        def emit(line: str):
            nonlocal last_progress_log, last_summary_line
            m_dup = re.search(
                r"NOTICE\s*:\s*(\S.*?):\s*Duplicate object found in source", line)
            if m_dup and m_dup.group(1) not in duplicate_files:
                duplicate_files.append(m_dup.group(1))
            m = re.search(r"ERROR\s*:\s*(\S.*?):\s*Failed to copy", line)
            if m:
                name = m.group(1)
                if name not in failed_files:
                    failed_files.append(name)
                if "cannotDownloadAbusiveFile" in line and name not in abusive_files:
                    abusive_files.append(name)
            is_progress = line.startswith("Transferred:") or "ETA" in line or "%" in line
            if is_progress:
                now = time.time()
                if now - last_progress_log < 1.0:
                    return
                last_progress_log = now
                last_summary_line = line
            logger.info(line)

        returncode = _stream_process(rclone_args, emit)

        if returncode == 0:
            print_success(f"Drive backed up to: {backup_path}")
            if last_summary_line:
                print_info(f"  {last_summary_line}")
            summary_action(f"Drive backed up via rclone to {backup_path}")
            # rclone exiting 0 does not mean every file arrived; same-name
            # collisions overwrite silently. Reconcile before believing it.
            verify_drive_backup_complete(email, backup_path, duplicate_files)
            return True
        elif abusive_files and len(failed_files) == len(abusive_files):
            # Only flagged files failed, so the rest of the backup is intact.
            print_warning(
                f"{Colours.RED}Drive backed up to {backup_path}, EXCEPT "
                f"{len(abusive_files)} file(s) Google has flagged as malware or "
                f"spam and refuses to release: {', '.join(abusive_files)}. "
                f"Everything else transferred. These cannot be recovered by "
                f"re-running; the owner can still download them by hand from "
                f"the Drive web UI after acknowledging the warning."
                f"{Colours.RESET}"
            )
            summary_warning(
                f"Drive backup to {backup_path} completed WITHOUT "
                f"{len(abusive_files)} malware/spam-flagged file(s): "
                f"{', '.join(abusive_files)}"
            )
            # The rest of the backup still has to reconcile against Drive.
            verify_drive_backup_complete(email, backup_path, duplicate_files)
            return True
        elif shutdown_requested:
            # We terminated rclone ourselves on Ctrl+C. Reporting that as a
            # tool failure misleads whoever reads the log later — the backup is
            # incomplete because someone stopped it, not because rclone broke.
            print_warning(
                f"Drive backup CANCELLED by operator (Ctrl+C). The partial "
                f"backup at {backup_path} is incomplete — do not treat it as a "
                f"copy of this user's Drive. Re-run to finish it."
            )
            summary_warning(
                f"Drive backup cancelled by operator; partial data at "
                f"{backup_path} is INCOMPLETE"
            )
            return False
        else:
            print_error(f"rclone failed (exit {returncode})")
            if abusive_files:
                print_error(
                    f"  including {len(abusive_files)} file(s) Google refused to "
                    f"release as malware/spam: {', '.join(abusive_files)}"
                )
            summary_error(f"rclone backup failed (exit {returncode})")
            return False

    except FileNotFoundError:
        print_error(f"rclone not found: {RCLONE_COMMAND}")
        summary_error("rclone not found in PATH")
        return False
    except Exception as e:
        print_error(f"rclone exception: {e}")
        summary_error(f"rclone exception: {e}")
        return False


###############################################################################
# GYB EMAIL BACKUP ONLY [RECOMMENDED]
# Downloads the user's mailbox to local disk WITHOUT restoring elsewhere.
###############################################################################

def backup_email_only(email: str, dry_run: bool) -> bool:
    """
    [RECOMMENDED] Back up user's email to local disk via GYB.
    Does NOT restore to another user; local archive only.

    Returns True on success, False on failure.
    """
    print_header("EMAIL BACKUP (GYB, LOCAL ONLY)")

    backup_path = BACKUP_DIRECTORY / "mailboxes" / f"{email}_email_{datetime.now().strftime('%Y%m%d')}"
    if not dry_run:
        backup_path.mkdir(parents=True, exist_ok=True)

    print_info(f"Backing up email to: {backup_path}")
    print_info(SPAM_TRASH_NOTE)

    success, output = run_gyb(
        ["--email", email, "--action", "backup", "--local-folder", str(backup_path)],
        dry_run=dry_run
    )

    if success:
        # Same reconciliation the migration path gets: exit 0 with msg-db
        # rows missing their .eml files is a silent shortfall, and on an
        # archive-only offboarding this backup is the ONLY copy before the
        # account is deleted. A genuine shortfall raises summary_error,
        # which holds licence removal via record_failure("Email backup").
        if not dry_run:
            errors_before = len(summary_errors)
            verify_backup_complete(backup_path)
            if len(summary_errors) > errors_before:
                print_error("Email backup failed verification (see above)")
                return False
        print_success(f"Email backed up to: {backup_path}")
        summary_action(f"Email backed up via GYB to {backup_path}")
        return True
    else:
        if not dry_run:
            print_error("Email backup failed")
            summary_error("GYB email backup failed")
        return False


###############################################################################
# USER DELETION [CRITICAL]
# Permanently deletes the user account. ONLY used in --scorched-earth mode.
###############################################################################

def delete_user(email: str, dry_run: bool):
    """
    [CRITICAL] Permanently delete the user account.

    GAM7 wiki (Users): gam delete user <email>

    IRREVERSIBLE after Google's 20-day undelete window.
    Only called in --scorched-earth mode.
    """
    print_header("USER DELETION (SCORCHED EARTH)")

    print_error("WARNING: PERMANENTLY DELETING user account.")
    print_error(f"User: {email}")
    print_error("Irreversible after 20-day recovery window.")

    ok, _ = run_gam(
        ["delete", "user", email],
        dry_run=dry_run
    )
    if ok:
        summary_action(f"USER DELETED: {email}")
    else:
        print_error(
            f"CRITICAL: Deletion FAILED — {email} still exists. "
            f"Verify with: gam info user {email}"
        )
        summary_error(f"Deletion failed — {email} still exists")


###############################################################################
# AUTO-REPLY [RECOMMENDED]
###############################################################################

def set_auto_reply(email: str, dry_run: bool):
    """
    [RECOMMENDED] Set an out-of-office auto-reply.

    GAM7: gam user <email> vacation on subject <subject> message <message>

    EDGE CASE: This will not work if the user is suspended, so it must
    happen BEFORE suspension.
    """
    print_header("AUTO-REPLY SETUP")

    ok, _ = run_gam(
        [
            "user", email, "vacation", "on",
            "subject", "Out of Office",
            "message", AUTO_REPLY_MESSAGE
        ],
        dry_run=dry_run
    )
    if ok:
        summary_action("Auto-reply message configured")


###############################################################################
# SUSPENSION [IMPORTANT]
###############################################################################

def suspend_user(email: str, dry_run: bool, bypass_shutdown: bool = False) -> bool:
    """
    [IMPORTANT] Suspend the user account and verify it by read-back.

    GAM7 wiki (Users): gam update user <email> suspended on

    This is ALWAYS the last step because deprovision (backup codes),
    turnoff2sv, forwarding and the vacation responder all fail on a
    suspended user.

    Returns True only when the directory reads the account as suspended (or
    in dry run). A successful 'Updated' response can lie: observed live on
    dev 2026-07-13, an unsuspend returned 'Updated' with no state change for
    70+ seconds until a suspend-toggle cycle cleared it.

    How long to wait is measured, not guessed (dev, 2026-08-31). On a quiet
    account the flip reads back in 4-5s (5 of 5 trials). Straight after the
    kill switch's burst of directory writes the SAME flip took 54s, and the
    old ~18s window failed verification on every scorched-earth run that
    suspended correctly. 120s covers the measured worst case with headroom
    and costs the normal path nothing, because it returns on the first read.

    bypass_shutdown: the containment-failure suspend and the re-suspend of a
    temporarily unsuspended account must run even after Ctrl+C.
    """
    print_header("SUSPENSION")

    ok, _ = run_gam(
        ["update", "user", email, "suspended", "on"],
        dry_run=dry_run, bypass_shutdown=bypass_shutdown
    )
    if not ok:
        print_error(
            f"CRITICAL: Suspension FAILED — {email} is still active. "
            f"Suspend manually: gam update user {email} suspended on"
        )
        summary_error(f"Suspension failed — {email} is still ACTIVE")
        return False

    if dry_run:
        summary_action("User account suspended")
        return True

    started = time.time()
    if wait_for_suspended(email, True, timeout=120, bypass_shutdown=bypass_shutdown):
        summary_action(
            f"User account suspended (verified by read-back "
            f"after {int(time.time() - started)}s)"
        )
        return True
    print_error(
        f"CRITICAL: Suspension reported success but {email} still reads as "
        f"ACTIVE after 120s. Toggle it manually: gam update user {email} "
        f"suspended on (if that reports Updated with no effect, run suspended "
        f"off then suspended on) and verify with: gam info user {email} quick"
    )
    summary_error(
        f"Suspension NOT verified — {email} may still be ACTIVE despite "
        f"a successful-looking update"
    )
    return False


###############################################################################
# SUMMARY REPORT [RECOMMENDED]
###############################################################################

def print_summary(dry_run: bool) -> None:
    """End-of-run report: actions, warnings, skips, errors, phase timings."""
    print_header("OFFBOARDING SUMMARY")

    if dry_run:
        print_warning("DRY RUN ONLY, NO CHANGES WERE MADE")
        print_info("Re-run with --doit to execute these operations.")

    sections = (
        (summary_actions, "Actions completed", print_info, "+"),
        (summary_warnings, "Warnings", print_warning, "~"),
        (summary_skipped, "Skipped", print_info, "-"),
        (summary_errors, "Errors", print_error, "!"),
    )
    for items, label, printer, marker in sections:
        if items:
            _emit('info', "")
            printer(f"{label} ({len(items)}):")
            for item in items:
                _emit('info', f"  {marker} {item}")

    if phase_timings:
        _emit('info', "")
        print_info("Phase timings:")
        total = 0.0
        for phase, elapsed in phase_timings:
            _emit('info', f"  {phase}: {elapsed:.1f}s")
            total += elapsed
        _emit('info', f"  Total: {total:.1f}s")

    _emit('info', "")
    print_info(f"Log file: {LOG_FILENAME}")


def print_mail_capture_instructions(offboarded_email: str, successor_email: str):
    """
    Print the end-of-run MANUAL ACTION block with three admin-console options
    for capturing mail to the offboarded address after suspension/deletion.

    Surfaced because GAM cannot configure the "Recipient address map" Gmail
    routing feature directly, and Gmail user-level forwarding stops once the
    source account is suspended/deleted. This block tells the admin what to
    do in the console.
    """
    width = 70
    bar = "=" * width
    logger.info("")
    logger.info(f"{Colours.YELLOW}{bar}")
    logger.info(f"  MANUAL ACTION REQUIRED — Mail capture for {offboarded_email}")
    logger.info(f"{bar}{Colours.RESET}")
    lines = [
        "",
        "Once the offboarded user is suspended or deleted, Gmail-level",
        "forwarding stops. To keep capturing mail sent to",
        f"  {offboarded_email}",
        "choose ONE of the following in the Admin console:",
        "",
        "OPTION 1 — Add as alias on the successor (simplest, single recipient)",
        f"  1. Admin console -> Directory -> Users -> {successor_email}",
        "  2. User information -> Email aliases -> ADD AN ALIAS",
        f"  3. Alias: {offboarded_email.split('@')[0]}",
        "  4. SAVE",
        "  Note: requires the offboarded address to be released. If the user",
        "  was only suspended, delete them first OR rename them.",
        "",
        "OPTION 2 — Recipient address map (works while user still exists)",
        "  1. Admin console -> Apps -> Google Workspace -> Gmail",
        "     -> Default routing",
        "  2. ADD ANOTHER RULE",
        f"  3. Single recipient: {offboarded_email}",
        f"  4. Action: Change envelope recipient -> {successor_email}",
        "  5. SAVE — takes effect within ~1 hour",
        "",
        "OPTION 3 — Convert to a Group (multiple recipients)",
        "  1. Admin console -> Directory -> Groups -> CREATE GROUP",
        f"  2. Group email: {offboarded_email}",
        f"  3. Add {successor_email} (and any others) as members",
        "  Note: same address-release requirement as Option 1.",
        "",
        f"Successor on record: {successor_email}",
    ]
    for line in lines:
        logger.info(line)
    logger.info(f"{Colours.YELLOW}{bar}{Colours.RESET}")


###############################################################################
# ARGUMENT PARSING [IMPORTANT]
###############################################################################

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"Google Workspace User Offboarding Script v{SCRIPT_VERSION} (GAM7)",
        epilog=(
            "Examples:\n"
            "  python offboard_user.py                                          # Dry run\n"
            "  python offboard_user.py --doit                                   # Execute\n"
            "  python offboard_user.py --doit --backup-drive --backup-email     # Backup locally\n"
            "  python offboard_user.py --doit --no-transfer --backup-drive      # Backup, no transfers\n"
            "  python offboard_user.py --doit --force --user leaver@yourdomain.com \\\n"
            "      --all-transfer-to testoffboard.team@yourdomain.com                              # All transfers -> one user\n"
            "  python offboard_user.py --doit --force --user leaver@yourdomain.com \\\n"
            "      --all-transfer-to testoffboard.team@yourdomain.com \\\n"
            "      --drive-to testoffboard.manager@yourdomain.com                                  # Split: Drive -> manager, rest -> team\n"
            "  python offboard_user.py --doit --force --user leaver@yourdomain.com \\\n"
            "      --drive-to testoffboard.manager@yourdomain.com \\\n"
            "      --email-to testoffboard.ops@yourdomain.com --no-alias \\\n"
            "      --no-calendar --no-forward                                                       # Per-phase routing, no global default\n"
            "  python offboard_user.py --doit --force --scorched-earth          # DELETE user\n"
            "\n"
            "Transfer destination precedence (Drive, Email, Alias, Calendar, Forward):\n"
            "  1. Phase-specific flag (--drive-to, --email-to, --alias-to,\n"
            "     --calendar-to, --forward-to) -- always wins.\n"
            "  2. --all-transfer-to -- fallback for any phase without a specific flag.\n"
            "  3. Interactive prompt -- only when --force is NOT set.\n"
            "\n"
            "  With --force, every non-skipped transfer phase MUST resolve to a\n"
            "  destination via (1) or (2), or the run aborts before any change\n"
            "  is made. Skip a phase with --no-drive / --no-email / --no-alias /\n"
            "  --no-calendar / --no-forward.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # --- Execution mode ---
    parser.add_argument("--doit", action="store_true",
                        help="Execute changes (default is dry-run mode)")
    parser.add_argument("--force", action="store_true",
                        help="Skip all interactive prompts (auto-yes). Exception: "
                             "an already-suspended user is only temporarily "
                             "unsuspended when --unsuspend is explicitly given.")

    # --- Backup flags ---
    backup_grp = parser.add_argument_group("Backup options")
    backup_grp.add_argument(
        "--backup-drive", action="store_true",
        help="Download Drive files locally via rclone BEFORE any transfer. "
             "Requires rclone configured with a Google Drive remote.")
    backup_grp.add_argument(
        "--backup-email", action="store_true",
        help="Download email locally via GYB WITHOUT restoring to another user. "
             "Requires GYB. When the email migration also runs, no separate "
             "download happens: the migration's retained GYB backup serves "
             "as the archive.")
    backup_grp.add_argument(
        "--backup-dir", type=str, metavar="PATH",
        help="Root folder for ALL backups (snapshots, mailbox, Drive). "
             "Subfolders are created inside it. Default: ./offboarding_backups "
             "in the current directory. Point this OUTSIDE any synced folder "
             "(iCloud/Dropbox/Drive): a mailbox backup can be hundreds of GB "
             "and a synced folder re-uploads all of it every run.")
    backup_grp.add_argument(
        "--reuse-email-backup", type=str, metavar="PATH",
        help="Restore email from this EXISTING GYB backup folder and skip the "
             "download step. Use to resume a restore that died partway (e.g. on "
             "an AV-locked message) without re-downloading a large mailbox — "
             "Gmail dedupes re-restored mail server-side, so it is safe. The "
             "path must contain msg-db.sqlite.")
    backup_grp.add_argument(
        "--restore-batch-size", type=int, metavar="N", default=RESTORE_BATCH_SIZE,
        help=f"Messages per Gmail import request on restore (1-100, default "
             f"{RESTORE_BATCH_SIZE}). GYB's own default is 1 = serial + only "
             f"commits resume state at the end (a crash restarts from scratch); "
             f">1 batches small messages (fast) and commits per batch (a crash "
             f"resumes). Drop toward 10 if Gmail returns rateLimitExceeded.")

    # --- Mode flags ---
    mode_grp = parser.add_argument_group("Operation modes")
    mode_grp.add_argument(
        "--no-transfer", action="store_true",
        help="Skip ALL data transfers, forwarding, aliases, calendar, delegates, "
             "and auto-reply. Only runs: kill switch, devices, groups, licences, "
             "backups (if specified), and suspension.")
    mode_grp.add_argument(
        "--scorched-earth", action="store_true",
        help="DANGER: Snapshot, kill switch, remove groups/licences, suspend, "
             "then permanently DELETE the user. Refuses any backup or transfer "
             "flag (run those first, then delete). Requires --doit and --force. "
             "You must type the email to confirm.")
    mode_grp.add_argument(
        "--allow-orphaned-shared-drives", action="store_true",
        help="With --scorched-earth, delete the user even when they are the "
             "ONLY organizer of a Shared Drive. Without this the run aborts "
             "before any change, because deleting the sole organizer leaves a "
             "drive only a super admin can recover.")
    mode_grp.add_argument(
        "--allow-admin-account", action="store_true",
        help="DANGER: Continue even when the target still has Super Admin or "
             "delegated admin privileges. This script does not revoke those "
             "roles; remove them first unless this override is intentional.")

    # --- Skip flags ---
    skip_grp = parser.add_argument_group("Skip options")
    skip_grp.add_argument("--no-devices", action="store_true",
                          help="Skip device management")
    skip_grp.add_argument("--no-drive", action="store_true",
                          help="Skip Drive ownership transfer")
    skip_grp.add_argument("--no-email", action="store_true",
                          help="Skip email migration (GYB backup+restore)")
    skip_grp.add_argument("--no-alias", action="store_true",
                          help="Skip alias transfer")
    skip_grp.add_argument("--no-calendar", action="store_true",
                          help="Skip calendar access transfer")
    skip_grp.add_argument("--no-forward", action="store_true",
                          help="Skip email forwarding setup")
    skip_grp.add_argument("--no-auto-reply", action="store_true",
                          help="Skip auto-reply message")
    skip_grp.add_argument("--no-snapshot", action="store_true",
                          help="Skip pre-flight snapshot")
    skip_grp.add_argument("--no-delegates", action="store_true",
                          help="Skip delegate cleanup")
    skip_grp.add_argument("--no-suspend", action="store_true",
                          help="Skip final suspension")
    skip_grp.add_argument("--unsuspend", action="store_true",
                          help="Temporarily unsuspend an already-suspended user to allow "
                               "full offboarding; they will be re-suspended at the end")

    # --- Email migration label handling (mutually exclusive) ---
    label_grp = parser.add_argument_group("Email label options")
    label_mx = label_grp.add_mutually_exclusive_group()
    label_mx.add_argument("--strip-labels", dest="strip_labels", action="store_true", default=None,
                          help="On email restore, discard all original Gmail labels (including "
                               "INBOX) and keep only Migrated/<source-user>. Migrated mail is "
                               "effectively archived under one namespaced label. This is the "
                               "default in --force mode; without --force you are prompted.")
    label_mx.add_argument("--keep-labels", dest="strip_labels", action="store_false",
                          help="Preserve original Gmail labels (INBOX, custom labels) on restore; "
                               "Migrated/<source-user> is added on top.")

    # --- Target flags ---
    target_grp = parser.add_argument_group("Target options")
    target_grp.add_argument("--user", type=str,
                            help="Email of user to offboard")
    target_grp.add_argument("--all-transfer-to", type=str,
                            help="Default destination for ALL transfer phases "
                                 "(Drive, Email, Alias, Calendar, Forward). "
                                 "Overridden per-phase by --drive-to, --email-to, "
                                 "--alias-to, --calendar-to, --forward-to.")
    target_grp.add_argument("--drive-to", type=str,
                            help="Destination for Drive transfer "
                                 "(overrides --all-transfer-to for this phase).")
    target_grp.add_argument("--email-to", type=str,
                            help="Destination for email migration "
                                 "(overrides --all-transfer-to for this phase).")
    target_grp.add_argument("--alias-to", type=str,
                            help="Destination for alias transfer "
                                 "(overrides --all-transfer-to for this phase).")
    target_grp.add_argument("--calendar-to", type=str,
                            help="Destination for calendar access transfer "
                                 "(overrides --all-transfer-to for this phase).")
    target_grp.add_argument("--forward-to", type=str,
                            help="Destination for email forwarding "
                                 "(overrides --all-transfer-to for this phase).")
    target_grp.add_argument("--forward-alias-to", type=str,
                            help="Successor address to surface in the end-of-run "
                                 "MANUAL ACTION block, with admin-console "
                                 "instructions for capturing mail to the "
                                 "offboarded address after suspension/deletion "
                                 "(alias / recipient address map / group). "
                                 "If omitted, falls back to --forward-to then "
                                 "--all-transfer-to. No automated change is made.")
    target_grp.add_argument("--log-dir", type=str,
                            help="Directory for log files")

    args = parser.parse_args()

    # === Flag validation and implications ===

    # GYB's own argparse restricts --batch-size to choices 1-100 and rejects
    # anything else outright. Caught here, that is a one-line usage error;
    # caught by GYB, it fails EVERY restore attempt instantly — but only after
    # the mailbox backup has already run, which on a large mailbox is hours.
    if not 1 <= args.restore_batch_size <= 100:
        parser.error(
            f"--restore-batch-size must be between 1 and 100 "
            f"(got {args.restore_batch_size}); GYB rejects anything outside "
            f"that range. Use {RESTORE_BATCH_SIZE} unless you have a reason."
        )
    if args.restore_batch_size == 1:
        parser.error(
            "--restore-batch-size 1 makes GYB upload every message singly AND "
            "commit its resume DB only at the end, so a crash restarts from "
            "message 1. Use 2 or more (10 is the throttling floor)."
        )

    if args.scorched_earth:
        if not args.doit:
            parser.error("--scorched-earth requires --doit")
        if not args.force:
            parser.error("--scorched-earth requires --force")
        # A backup flag typed next to a permanent delete used to be dropped
        # silently, and the mailbox went with it. Refuse; do not guess.
        for flag, value in (("--backup-drive", args.backup_drive),
                            ("--backup-email", args.backup_email),
                            ("--unsuspend", args.unsuspend),
                            ("--no-suspend", args.no_suspend),
                            ("--reuse-email-backup", args.reuse_email_backup),
                            ("--all-transfer-to", args.all_transfer_to),
                            ("--drive-to", args.drive_to),
                            ("--email-to", args.email_to),
                            ("--alias-to", args.alias_to),
                            ("--calendar-to", args.calendar_to),
                            ("--forward-to", args.forward_to)):
            if value:
                parser.error(
                    f"--scorched-earth cannot be combined with {flag}: it "
                    f"deletes the user with no backup and no transfer. Run "
                    f"the backup or transfer first, then delete."
                )
        # No transfers, no frills. The snapshot stays: it is read-only, it is
        # the only record of the account once the delete lands, and it costs
        # seconds.
        args.no_drive = True
        args.no_email = True
        args.no_alias = True
        args.no_calendar = True
        args.no_forward = True
        args.no_delegates = True
        args.no_auto_reply = True

    if args.reuse_email_backup:
        # Restore-only mode runs ONLY the email restore. Anything else on the
        # command line would be ignored, which is a worse answer than a usage
        # error. --email-to is required because nothing else names the
        # destination (checked here, not after the dependency probes).
        if not (args.email_to or args.all_transfer_to):
            parser.error("--reuse-email-backup requires --email-to (or --all-transfer-to).")
        for flag, value in (("--no-email", args.no_email),
                            ("--no-transfer", args.no_transfer),
                            ("--backup-drive", args.backup_drive),
                            ("--backup-email", args.backup_email),
                            ("--unsuspend", args.unsuspend)):
            if value:
                parser.error(f"--reuse-email-backup cannot be combined with {flag}: "
                             f"restore-only mode runs nothing but the email restore.")

    if args.no_transfer:
        args.no_drive = True
        args.no_email = True
        args.no_alias = True
        args.no_calendar = True
        args.no_forward = True
        args.no_delegates = True
        args.no_auto_reply = True

    # An account that starts suspended is restored to suspended at the end;
    # asking for both is asking for two opposite end states. (Gavin-X, PR #7.)
    if args.unsuspend and args.no_suspend:
        parser.error(
            "--unsuspend cannot be combined with --no-suspend: an account "
            "that starts suspended is always returned to suspended."
        )

    return args


###############################################################################
# MAIN EXECUTION [CRITICAL]
###############################################################################

def run_phase(name: str, fn, *args, hold: Optional[List[str]] = None, **kwargs):
    """Run one phase: time it, turn an exception into a summary error, and
    when `hold` is given record the phase there if it lost data (so licence
    removal can be held back). Returns the phase's result, or None on an
    exception. A programming error inside a phase therefore never stops the
    run short of suspension, which is the deliberate trade: containment and
    suspension matter more than a clean traceback."""
    guard = record_failure(name, hold) if hold is not None else contextlib.nullcontext()
    with PhaseTimer(name), guard:
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            print_error(f"{name} failed: {e}")
            summary_error(f"{name} exception: {e}")
            return None


# The account this run temporarily unsuspended, if any. finish_run() restores
# it explicitly before the summary so the outcome is IN the summary and in the
# exit code; the atexit registration of the same function is the fallback for
# a crash that never reaches finish_run().
_resuspend_email: Optional[str] = None


def finish_run(dry_run: bool) -> int:
    """Restore a temporary unsuspend, print the summary, return the exit code."""
    if _resuspend_email and not dry_run:
        restore_original_suspension(_resuspend_email)
    print_summary(dry_run)
    return exit_code


def _abort_if_shutdown(dry_run: bool) -> None:
    """Between phases: honour Ctrl+C by summarising and exiting."""
    if shutdown_requested:
        sys.exit(finish_run(dry_run))


def main():
    global logger, BACKUP_DIRECTORY, _resuspend_email

    args = parse_args()
    dry_run = not args.doit
    configure_colours()
    install_signal_handlers()

    # --backup-dir overrides the module default so large backups can live off a
    # synced folder (iCloud/Dropbox). expanduser() so '~' works; resolve() so
    # the logged path is unambiguous.
    if args.backup_dir:
        BACKUP_DIRECTORY = Path(args.backup_dir).expanduser().resolve()

    # Get user email before logging so the filename can include it
    user_email = args.user or prompt_email("Enter the email of the user to offboard")

    # Capture start timestamp once so log and snapshot filenames match
    run_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_dir = Path(args.log_dir) if args.log_dir else Path("./logs")
    logger = setup_logging(log_dir, user_email, run_timestamp)

    print_header(f"GOOGLE WORKSPACE OFFBOARDING v{SCRIPT_VERSION}")
    print_info(f"Platform: {sys.platform}")
    print_info(f"Python: {sys.version.split()[0]}")
    print_info(f"Execution mode: {'LIVE' if args.doit else 'DRY RUN'}")
    print_info(f"Interactive: {'No (--force)' if args.force else 'Yes'}")
    print_info(f"Offboarding OU: {OFFBOARDING_OU}")

    # Non-blocking check against the remote VERSION file.
    check_for_updates()

    if args.scorched_earth:
        print_error("MODE: SCORCHED EARTH - User will be DELETED")
    elif args.reuse_email_backup:
        print_info("MODE: Restore-only (resume email restore from an existing backup)")
    elif args.no_transfer:
        print_info("MODE: No-transfer - No data moves to other users")
    if args.backup_drive:
        print_info("BACKUP: Drive download via rclone enabled")
    if args.backup_email:
        print_info("BACKUP: Email download via GYB enabled (local only)")

    for flag in ("no_devices", "no_drive", "no_email", "no_alias", "no_calendar",
                 "no_forward", "no_auto_reply", "no_snapshot", "no_delegates",
                 "no_suspend"):
        if getattr(args, flag):
            print_warning(f"--{flag.replace('_', '-')} enabled")

    # Mode-aware dependency check
    need_gyb = (not args.no_email) or args.backup_email or bool(args.reuse_email_backup)
    if not check_dependencies(need_gyb=need_gyb, need_rclone=args.backup_drive,
                              user_email=user_email, dry_run=dry_run,
                              skip_disk_check=bool(args.reuse_email_backup)):
        print_error("Dependency check failed. Aborting.")
        sys.exit(2)

    user_info = verify_user(user_email)
    if user_info is None:
        print_error("User verification failed. Aborting.")
        sys.exit(2)

    # GAM resolves an alias to its user, but the alias itself later moves to the
    # destination (transfer_aliases), after which every command naming it hits
    # the DESTINATION's account. Run on the primary address from here on, and
    # refuse rather than carry on with an input that might be an alias.
    primary = user_info.get("user", "")
    if not primary:
        print_error(f"Could not read the primary address of {user_email}. Aborting.")
        summary_error(f"Primary address of {user_email} unreadable; refusing to continue")
        sys.exit(2)
    if primary.lower() != user_email.lower():
        print_info(f"{user_email} is an alias; offboarding its primary address {primary}.")
        user_email = primary

    # Privileged roles survive password resets and suspension and become live
    # again if the account is restored or unsuspended. Gate before every
    # possible mutation, including destination checks and temporary unsuspend.
    try:
        enforce_admin_account_gate(user_email, user_info, args.allow_admin_account)
    except AdminAccountSafetyError as e:
        print_error(str(e))
        summary_error(str(e))
        sys.exit(finish_run(dry_run))

    is_suspended = user_info.get('_is_suspended', 'False') == 'True'
    is_2sv_enrolled = user_info.get('2-step enrolled', 'false').lower() == 'true'
    is_2sv_enforced = user_info.get('2-step enforced', 'false').lower() == 'true'
    has_mailbox = user_info.get('mailbox is setup', 'true').lower() == 'true'

    # --- Restore-only / resume mode (--reuse-email-backup) -------------------
    # Resuming a failed email restore must NOT re-run containment (password
    # scramble, sign-out), group/licence removal, or any other transfer. Do
    # only the email restore against the existing backup, then exit. Flag
    # conflicts and the --email-to requirement are refused in parse_args.
    if args.reuse_email_backup:
        reuse_backup = Path(args.reuse_email_backup).expanduser().resolve()
        email_dest = args.email_to or args.all_transfer_to
        # preflight_destinations() is what refuses the leaver (or one of
        # their aliases) as a destination; this mode skips it, so refuse here
        # or the mailbox restores into itself under new labels.
        same_account = {user_email.lower()} | {a.lower() for a in _list_aliases(user_email)}
        if email_dest.lower() in same_account:
            print_error(f"Restore destination {email_dest} is the account being offboarded.")
            sys.exit(2)
        if not dry_run and not validate_destination(email_dest):
            print_error(f"Restore destination {email_dest} did not validate; aborting.")
            summary_error(f"Restore-only aborted: destination {email_dest} invalid")
            sys.exit(2)
        strip_labels = args.strip_labels if args.strip_labels is not None else True
        print_header("RESTORE-ONLY MODE (resume email restore from existing backup)")
        print_info(f"Source user : {user_email}")
        print_info(f"Restore to  : {email_dest}")
        print_info(f"Backup      : {reuse_backup}")
        print_info(f"Label mode  : {'strip (single Migrated/ label)' if strip_labels else 'keep original labels'}")
        if not dry_run and not prompt_yes_no("Proceed with restore-only?", force=args.force):
            print_info("Aborted by operator.")
            sys.exit(0)
        run_phase("Email migration", migrate_email, user_email, email_dest, dry_run,
                  strip_labels=strip_labels, reuse_backup=reuse_backup,
                  batch_size=args.restore_batch_size, force=args.force)
        sys.exit(finish_run(dry_run))

    # Resolve and validate transfer destinations BEFORE any account change.
    # This used to run after the temporary unsuspend below, so a preflight
    # exit(2) left an account that started suspended sitting active (issue #2).
    dest_map = preflight_destinations(args, source=user_email)

    # --- Temporarily unsuspend if requested ---
    temp_unsuspended = False
    if is_suspended and not args.scorched_earth:
        do_unsuspend = decide_unsuspend(
            args.force, args.unsuspend,
            lambda: prompt_yes_no(
                "User is suspended. Temporarily unsuspend to allow full offboarding? "
                "(Will be re-suspended at the end)",
                default=False
            )
        )
        if args.force and not args.unsuspend:
            print_warning(
                "User is suspended and --unsuspend was not given: continuing "
                "WITHOUT unsuspending. Suspension-dependent steps (deprovision "
                "backup codes, turnoff2sv, forwarding, auto-reply) will fail. "
                "Add --unsuspend to temporarily reactivate for full offboarding."
            )
        if do_unsuspend:
            print_info("Temporarily unsuspending user for offboarding...")
            success, _ = run_gam(
                ["update", "user", user_email, "suspended", "off"],
                dry_run=dry_run
            )
            if dry_run and success:
                is_suspended = False
                temp_unsuspended = True
                print_info("DRY RUN: unsuspend would be verified by read-back.")
                summary_action("Would temporarily unsuspend for offboarding")
            elif success and wait_for_suspended(user_email, False):
                is_suspended = False
                temp_unsuspended = True
                print_success("User unsuspended and verified. Will be re-suspended at the end.")
                summary_action("Temporarily unsuspended for offboarding (verified)")
                # finish_run() restores the account on every normal exit path
                # so the outcome lands in the summary and the exit code; the
                # atexit registration is the fallback for a crash or a
                # sys.exit that never reaches finish_run(). Idempotent: after
                # the suspension phase it reads the restored state and changes
                # nothing. Registered even under --no-suspend: only a run that
                # REACHES the suspension phase waives it
                # (no_suspend_contract_waived).
                _resuspend_email = user_email
                atexit.register(restore_original_suspension, user_email)
            else:
                print_error(
                    "Could not verify that the user was unsuspended. Restoring "
                    "the original state and aborting before any offboarding change."
                )
                if not dry_run:
                    restore_original_suspension(user_email)
                sys.exit(2)

    # --- Scorched earth confirmation (even with --force, must type email) ---
    if args.scorched_earth and not dry_run:
        _emit('info', "")
        print_error("=" * 60)
        print_error("  SCORCHED EARTH MODE")
        print_error(f"  User: {user_email}")
        print_error("  This will PERMANENTLY DELETE the user and ALL data.")
        print_error("  No undo after 20-day recovery window.")
        print_error("=" * 60)
        try:
            confirm = input(
                f"{Colours.RED}Type the full email address to confirm: {Colours.RESET}"
            ).strip()
        except EOFError:
            confirm = ""
        if confirm != user_email:
            print_error("Email mismatch. Aborting.")
            sys.exit(2)

        # Scorched earth short-circuits straight to deletion and so never
        # reaches the Shared Drive check that every other run does. Deleting
        # the sole organizer leaves a drive no MEMBER can add members to,
        # change settings on or delete — only a super admin taking it over in
        # the console recovers it, and nothing in the run said so (issue #9).
        # Proved on dev 2026-08-31: a scorched-earth delete left
        # `gam print shareddriveorganizers` reporting that drive with an empty
        # organizer column and printed no warning at all.
        #
        # This runs BEFORE the kill switch on purpose: aborting here leaves the
        # account completely untouched, so the operator can add an organizer
        # and re-run. Deletion is the one step with no undo, so it is the one
        # step that gets a gate rather than a warning.
        orphans = check_shared_drives(user_email, dry_run)
        if orphans and not args.allow_orphaned_shared_drives:
            print_error(
                f"Refusing to delete {user_email}: {len(orphans)} Shared "
                f"Drive item(s) listed above are either organized by them "
                f"ALONE or could not be checked (a drive's membership, or the "
                f"whole drive list). Deleting the account strands any drive "
                f"that has no other organizer."
            )
            print_error(
                "Add a replacement organizer first (the command above runs as "
                "the leaver, who is the only one who can grant it), or re-run "
                "with --allow-orphaned-shared-drives to delete anyway."
            )
            summary_error(
                f"Scorched earth aborted: {len(orphans)} Shared Drive item(s) of "
                f"{user_email} are sole-organized or unverifiable"
            )
            finish_run(dry_run)
            sys.exit(2)  # a preflight refusal, same code as every other abort

    elif not dry_run and not args.force:
        _emit('info', "")
        print_warning(f"You are about to OFFBOARD: {user_email}")
        print_warning("This will revoke access, scramble password, and optionally suspend.")
        if not prompt_yes_no("Are you sure you want to proceed?"):
            print_info("Aborted by operator.")
            sys.exit(0)

    # Front-load every remaining interactive decision into one block, echo the
    # plan, and take a single final confirmation. After this the run needs no
    # further operator input — the phases below read `plan` instead of prompting.
    plan = collect_plan(args, dest_map, is_2sv_enrolled, is_2sv_enforced,
                        source=user_email)
    print_plan(plan)
    if not dry_run:
        if not prompt_yes_no("Proceed with this plan?", force=args.force):
            print_info("Aborted by operator.")
            sys.exit(0)

    sys.exit(run_offboarding(args, plan, user_email, dry_run, run_timestamp,
                             is_suspended, temp_unsuspended, is_2sv_enrolled,
                             has_mailbox))


def run_offboarding(args, plan: Dict[str, dict], user_email: str, dry_run: bool,
                    run_timestamp: str, is_suspended: bool, temp_unsuspended: bool,
                    is_2sv_enrolled: bool, has_mailbox: bool) -> int:
    """Run the phases in order and return the exit code.

    Everything interactive has already happened in main(); from here the run
    is unattended. Order (see the header): snapshot, kill switch, devices,
    groups, delegates, local backups, transfers, Shared Drive check,
    forwarding, auto-reply, licence removal, suspension. Scorched earth runs
    snapshot, kill switch, groups, licences, suspension, deletion.
    """
    global no_suspend_contract_waived
    transfer_failures: List[str] = []

    # ---- Pre-flight snapshot -------------------------------------------
    cached_licences: Optional[List[Tuple[str, str]]] = None
    if args.no_snapshot:
        summary_skip("Pre-flight snapshot (--no-snapshot)")
    else:
        result = run_phase("Pre-flight snapshot", preflight_snapshot,
                           user_email, dry_run, run_timestamp)
        if result:
            cached_licences = result[1]
    _abort_if_shutdown(dry_run)

    # ---- Kill switch (always runs, finishes even after Ctrl+C) ------------
    containment = run_phase("Kill switch", execute_kill_switch, user_email, dry_run,
                            is_suspended, is_2sv_enrolled, has_mailbox,
                            turn_off_2sv=plan["turnoff2sv"]["do"]) or {"contained": False}

    # Containment failed and --no-suspend would leave the account reachable.
    # Suspension is the one remaining lever, so it overrides the flag rather
    # than the run ending with a printed warning nobody acts on (issue #5).
    force_suspend = not containment.get("contained", False)
    if force_suspend and args.no_suspend:
        print_error(
            "Containment did not complete and --no-suspend was given. "
            "Suspending anyway: an account that cannot be locked must not be "
            "left active. Re-run without --no-suspend once containment works."
        )
        summary_warning(
            "--no-suspend overridden: containment failed, account suspended "
            "to close the access it left open"
        )
    if shutdown_requested and force_suspend and containment.get("started", True):
        # Ctrl+C after a containment that did not complete: the forced
        # suspension is the one thing that must still happen before exit.
        print_error("Shutdown requested with containment incomplete: suspending before exit.")
        run_phase("Suspension", suspend_user, user_email, dry_run, bypass_shutdown=True)
    _abort_if_shutdown(dry_run)

    # ---- Scorched earth: short circuit after the kill switch --------------
    if args.scorched_earth:
        run_phase("Group removal", remove_groups, user_email, dry_run)
        run_phase("Licence removal", remove_licences, user_email, dry_run,
                  cached_licences=cached_licences)
        run_phase("Suspension", suspend_user, user_email, dry_run, bypass_shutdown=True)
        run_phase("User deletion", delete_user, user_email, dry_run)
        return finish_run(dry_run)

    # ---- Devices, groups, delegates ---------------------------------------
    if args.no_devices:
        summary_skip("Device management (--no-devices)")
    else:
        run_phase("Device management", manage_devices, user_email, dry_run)
    _abort_if_shutdown(dry_run)

    run_phase("Group removal", remove_groups, user_email, dry_run)

    if args.no_delegates:
        summary_skip("Delegate cleanup (--no-delegates)")
    else:
        run_phase("Delegate cleanup", cleanup_delegates, user_email, dry_run)
    _abort_if_shutdown(dry_run)

    # ---- Local backups (BEFORE any ownership transfers) --------------------
    # These run even with --no-transfer so you can archive without moving data.
    if args.backup_drive:
        run_phase("Drive backup (rclone)", backup_drive_rclone, user_email, dry_run,
                  force=args.force, hold=transfer_failures)

    if args.backup_email:
        if plan["email"]["do"]:
            # The migration phase below downloads the same mailbox with GYB
            # and its backup folder stays on disk afterwards — a second full
            # download here doubled a 100 GB+ overnight run for an identical
            # artefact. One download serves both purposes.
            print_info(
                "Skipping the separate --backup-email download: the email "
                "migration below makes the same GYB backup and retains it "
                f"under {BACKUP_DIRECTORY / 'mailboxes'}."
            )
            summary_action(
                "Email archive: covered by the migration's retained GYB "
                f"backup under {BACKUP_DIRECTORY / 'mailboxes'}"
            )
        else:
            run_phase("Email backup (GYB, local only)", backup_email_only,
                      user_email, dry_run, hold=transfer_failures)
    _abort_if_shutdown(dry_run)

    # ---- Data transfers ----------------------------------------------------
    print_header("DATA TRANSFER DESTINATIONS")

    def transfer(key: str, label: str, fn, *extra, **kw) -> None:
        if getattr(args, f"no_{key}"):
            summary_skip(f"{label} (--no-{key})")
        elif plan[key]["do"]:
            run_phase(label, fn, user_email, plan[key]["dest"], dry_run, *extra,
                      hold=transfer_failures, **kw)
        else:
            summary_skip(f"{label} (declined)")

    transfer("drive", "Drive transfer", transfer_drive)

    # Shared Drives are untouched by every phase above, so report them
    # regardless of whether the My Drive transfer ran or was skipped.
    if run_phase("Shared Drive check", check_shared_drives, user_email, dry_run) is None:
        summary_warning(f"Shared Drive check did not complete for {user_email}; "
                        f"check by hand whether they solely organize any")

    transfer("email", "Email migration", migrate_email,
             strip_labels=plan["email"]["strip_labels"],
             batch_size=args.restore_batch_size, force=args.force)
    transfer("alias", "Alias transfer", transfer_aliases)
    transfer("calendar", "Calendar transfer", transfer_calendar)
    _abort_if_shutdown(dry_run)

    # ---- Forwarding and auto-reply (no licence hold: nothing moves) --------
    if args.no_forward:
        summary_skip("Email forwarding (--no-forward)")
    elif plan["forward"]["do"]:
        run_phase("Email forwarding", setup_forwarding, user_email,
                  plan["forward"]["dest"], dry_run)
    else:
        summary_skip("Email forwarding (declined)")

    if args.no_auto_reply:
        summary_skip("Auto-reply (--no-auto-reply)")
    elif plan["auto_reply"]["do"]:
        run_phase("Auto-reply", set_auto_reply, user_email, dry_run)
    else:
        summary_skip("Auto-reply (declined)")

    # ---- Licence removal (after all transfers so licence is intact for
    # Drive/Gmail API access during data operations) ------------------------
    # A failed backup or transfer means data is still only in this account.
    # Removing the licence kills Gmail and Drive API access and makes the retry
    # impossible, so the licence stays until the transfer actually worked
    # (issue #3). Suspension below still runs — the account is contained either
    # way; what is held back is the thing that would destroy the retry.
    if transfer_failures and not dry_run:
        blocked = ", ".join(transfer_failures)
        print_error("DATA PROTECTION HOLD: licences will NOT be removed.")
        print_error(f"Failed phase(s): {blocked}")
        print_warning(
            "The account is still suspended below. The licence is left in "
            "place so the failed phase can be retried after a controlled "
            "unsuspend; remove it by hand once the data is safe."
        )
        summary_skip(f"Licence removal held back by failed phase(s): {blocked}")
        summary_warning(
            "Licences RETAINED so the failed transfer can be retried — "
            "remove them manually once the data is confirmed moved"
        )
    else:
        run_phase("Licence removal", remove_licences, user_email, dry_run,
                  cached_licences=cached_licences)

    # ---- Suspension (always last) ------------------------------------------
    # If we temporarily unsuspended an already-suspended user at the start of
    # the run, we promised to re-suspend at the end. Honour that contract:
    # skip the prompt and force suspension so the account never ends in a
    # less-restricted state than it started in. --no-suspend still wins, but
    # we make a lot of noise about it.
    skip_suspend = args.no_suspend and not force_suspend
    if temp_unsuspended:
        if skip_suspend:
            # The run completed to this point, so leaving the account active
            # is now the operator's informed --no-suspend choice: stand the
            # re-suspend guard down and make the noise instead.
            no_suspend_contract_waived = True
            summary_skip("Suspension (--no-suspend)")
            summary_warning(
                "CONTRACT VIOLATION: User was suspended at start of run, "
                "temporarily unsuspended, and --no-suspend prevented "
                "re-suspension. Account is now ACTIVE — suspend manually "
                "immediately."
            )
            print_error(
                "WARNING: account started suspended and is now ACTIVE due "
                "to --no-suspend. Suspend manually."
            )
        else:
            print_info(
                "Re-suspending: account was suspended at start of run "
                "(temporary unsuspend honoured)."
            )
            if run_phase("Suspension", suspend_user, user_email, dry_run,
                         bypass_shutdown=True):
                summary_action("Re-suspended (restored original state)")
    elif skip_suspend:
        summary_skip("Suspension (--no-suspend)")
        summary_warning(
            "User was NOT suspended. Remember to suspend manually when "
            "the transition period is over."
        )
    elif plan["suspend"]["do"] or force_suspend:
        run_phase("Suspension", suspend_user, user_email, dry_run,
                  bypass_shutdown=force_suspend)
    else:
        summary_skip("Suspension (declined)")

    code = finish_run(dry_run)

    # End-of-run MANUAL ACTION block for mail capture. GAM cannot configure
    # the "Recipient address map" routing feature, and Gmail user-level
    # forwarding stops once the source account is suspended/deleted — so
    # surface admin-console instructions whenever a successor was specified.
    mail_capture_successor = (
        args.forward_alias_to or args.forward_to or args.all_transfer_to
    )
    if mail_capture_successor:
        print_mail_capture_instructions(user_email, mail_capture_successor)

    return code


if __name__ == "__main__":
    main()
