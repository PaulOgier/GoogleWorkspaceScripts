# Google Workspace User Offboarding Script for GAM7 (`offboard_user.py`)

A free, open-source Python script that automates **Google Workspace employee
offboarding** end to end with [GAM7](https://github.com/GAM-team/GAM): snapshot
the account, lock it down, clean up groups and delegates, hand Drive, calendar,
aliases and mail to a successor, recover the licence, and suspend last. One
command, in the right order, with a log and a summary you can file.

It runs in **dry-run mode by default**. Nothing changes until you pass
`--doit`, and a no-code [command builder](offboarding_command_builder.html)
writes the command for you.

Built and maintained by Paul Ogier, [Outsource House](https://osh.co.za).
Training at [Taming.Tech](https://taming.tech).

## Contents

- [Who this is for](#who-this-is-for)
- [Why this exists](#why-this-exists)
- [What one run does](#what-one-run-does)
- [Safety: what the script refuses to do](#safety-what-the-script-refuses-to-do)
- [What you get](#what-you-get)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Command builder (no-code helper)](#command-builder-no-code-helper)
- [Mailbox migration and backup with GYB](#mailbox-migration-and-backup-with-gyb)
- [Drive transfer and backup](#drive-transfer-and-backup)
- [Mail capture after suspension](#mail-capture-after-suspension)
- [Already-suspended users](#already-suspended-users)
- [Deleting the account](#deleting-the-account)
- [How it compares to other offboarding tools](#how-it-compares-to-other-offboarding-tools)
- [Frequently asked questions](#frequently-asked-questions)
- [Tests](#tests)
- [Licence](#licence)

## Who this is for

- **Google Workspace administrators** who offboard leavers by hand from a
  checklist and want the same result every time.
- **Managed service providers (MSPs) and IT consultants** who offboard users
  across many client tenants and need an audit trail per run.
- **Security teams** who want containment (sign-out, password reset, token
  revocation, device review) to happen first and provably.
- **Occasional admins** who run an offboarding a few times a year and do not
  want to relearn the GAM commands each time. The command builder is for you.

## Why this exists

Offboarding a Google Workspace user properly is fifteen to twenty separate
actions, and the order matters. Suspend too early and the Drive transfer,
mailbox migration and calendar handover all fail, because most GAM operations
need an active account. Remove the licence before the transfers finish and
Gmail and Drive access disappear with it. Forget the delegates and the leaver's
manager keeps reading a mailbox that no longer exists. Every admin has a
checklist; the checklist gets skipped on the busy day, which is the day the
leaver is walked out of the building.

This script is the checklist as code. It has been in production use on our
own clients since 2023, through three GAM major versions, and each field
incident became a guard in the script rather than a note in a wiki.

## What one run does

The phases run in this order, and the order is the point:

1. **Pre-flight snapshot.** The user's profile, licences, aliases, groups,
   delegates, forwarding, signature, Drive settings and devices are exported
   to JSON before anything changes. This is the audit trail, and it is kept
   even on a delete.
2. **Kill switch.** Containment first: move to the Offboarding organisational
   unit, wipe recovery details, reset the password, sign out every session,
   and revoke application tokens.
3. **Device management.** Mobile and ChromeOS devices are listed for review
   and action.
4. **Group removal.** Every group membership is removed.
5. **Delegate cleanup.** Inbound and outbound mailbox delegates are removed.
6. **Local backups** (optional). Drive via rclone, mailbox via
   [GYB](https://github.com/GAM-team/got-your-back).
7. **Data transfers.** Drive ownership, mailbox contents, email aliases and
   calendar access go to the successor, or to a different successor per
   phase.
8. **Shared Drive check.** Every Shared Drive the leaver organises is
   reported, and any that would be left with no organiser is flagged.
   Shared Drive content belongs to the drive, not the user, so nothing here
   is moved.
9. **Email forwarding** to the successor.
10. **Auto-reply** telling senders who to contact now.
11. **Licence removal.** Seats are freed only after the transfers succeeded.
12. **Suspension.** Last, because almost everything above fails on a
    suspended account.

Any phase can be skipped with a `--no-*` flag, and `--no-transfer` reduces the
run to containment, cleanup and suspension.

## Safety: what the script refuses to do

- **Dry run is the default.** Without `--doit` every command is printed and
  nothing runs. `--force` answers the prompts for scripted use; it does not
  imply any of the overrides below.
- **It will not offboard an admin.** A user who still holds Super Admin or a
  delegated admin role stops the run before any change, with the exact GAM
  commands to list and remove the roles. `--allow-admin-account` is the
  deliberate override.
- **It will not orphan a Shared Drive.** A delete that would leave a Shared
  Drive with no organiser aborts before any change, and an ACL it could not
  read counts as unknown, not as permission. `--allow-orphaned-shared-drives`
  overrides.
- **A failed transfer holds the licence.** If a Drive transfer, mailbox
  migration or backup falls short, the licence is not removed, because the
  retry needs the Gmail and Drive access the licence provides. Suspension
  still runs; containment is not the thing worth deferring.
- **A short backup is an error, not a warning.** Mailbox backups are
  reconciled against the message database and Drive backups against the file
  count. A shortfall fails the run and exits non-zero.
- **An account that started suspended ends suspended.** With `--unsuspend`,
  a guard re-suspends the account on every exit path, including Ctrl+C and an
  unhandled exception, and verifies the result by reading it back.
- **Containment failures are loud.** A password scramble that failed or a
  sign-out that could not be confirmed is a summary error, and it overrides
  `--no-suspend`: an account that could not be locked is not left active.
- **Conflicting flags are usage errors**, not silent overrides.
- **Deleting needs three things**: `--scorched-earth`, `--doit` and
  `--force`, and you type the address to confirm.

## What you get

- A timestamped log per run in `logs/` (change with `--log-dir`), with every
  GAM command and its result.
- The pre-flight snapshot as JSON in the backup directory.
- A phase-by-phase summary with timing, what succeeded, what failed and what
  was skipped, written for the ticket.
- A **MANUAL ACTION** block at the end for the things GAM cannot do, such as
  capturing mail to the leaver's address after suspension (see below).
- Exit codes a scheduler can act on: `0` success, `1` errors in one or more
  phases, `2` fatal (nothing or little ran), `130` stopped by Ctrl+C or
  SIGTERM (the summary names the last phase that ran; re-run to finish).

## Requirements

- Python 3.8+ (standard library only, no packages to install)
- GAM7 (GAM ADV X) installed and authorised against your domain
- Optional: [GYB](https://github.com/GAM-team/got-your-back) for mailbox
  migration and backup
- Optional: [rclone](https://rclone.org) with a Google Drive remote for local
  Drive backups
- Works on Windows, macOS and Linux

Step-by-step installation of GAM7, GYB and rclone:
[`installation_macos.md`](installation_macos.md) and
[`installation_windows.md`](installation_windows.md).

## Install

Clone the repository, or download `offboard_user.py` on its own.

```
git clone https://github.com/PaulOgier/GoogleWorkspaceScripts.git
cd GoogleWorkspaceScripts/google-workspace-offboarding
python3 offboard_user.py
```

The first run is a dry run. Read the plan it prints, then add `--doit`.

## Usage

```bash
# Dry run (default, no changes made)
python3 offboard_user.py

# Execute the offboarding, answering the prompts
python3 offboard_user.py --doit

# Non-interactive: everything to one successor
python3 offboard_user.py --doit --force --user leaver@yourdomain.com \
    --all-transfer-to team@yourdomain.com

# Split destinations: Drive to the manager, the rest to the team
python3 offboard_user.py --doit --force --user leaver@yourdomain.com \
    --all-transfer-to team@yourdomain.com --drive-to manager@yourdomain.com

# Back up Drive and mailbox locally, transfer nothing
python3 offboard_user.py --doit --no-transfer --backup-drive --backup-email

# Offboard an already-suspended user (unsuspend, offboard, re-suspend)
python3 offboard_user.py --doit --unsuspend --user leaver@yourdomain.com

# Skip phases
python3 offboard_user.py --doit --no-devices --no-calendar

# Delete the account after containment, group and licence cleanup
python3 offboard_user.py --doit --force --scorched-earth --user leaver@yourdomain.com
```

### Every flag

**Run mode**

| Flag | What it does |
|---|---|
| `--doit` | Execute changes. Without it the run is a dry run. |
| `--force` | Skip every interactive prompt. Every non-skipped transfer phase must then have a destination from a flag, or the run aborts before any change. Does not imply `--unsuspend`, `--allow-admin-account` or `--allow-orphaned-shared-drives`. |
| `--user <email>` | The user to offboard. Prompted for if omitted and `--force` is not set. |
| `--log-dir <dir>` | Where log files go. Default `logs/`. |

**Transfer destinations**

| Flag | What it does |
|---|---|
| `--all-transfer-to <email>` | Default successor for Drive, email, aliases, calendar and forwarding. |
| `--drive-to <email>` | Successor for the Drive ownership transfer. Overrides the default for this phase. |
| `--email-to <email>` | Successor for the mailbox migration. |
| `--alias-to <email>` | Successor for the email aliases. |
| `--calendar-to <email>` | Successor for calendar access. |
| `--forward-to <email>` | Address for Gmail forwarding. |
| `--forward-alias-to <email>` | Successor named in the end-of-run MANUAL ACTION block for capturing mail after suspension. Falls back to `--forward-to`, then `--all-transfer-to`. Makes no change itself. |

Precedence: the phase-specific flag wins, then `--all-transfer-to`, then the
interactive prompt (only without `--force`).

**Backups**

| Flag | What it does |
|---|---|
| `--backup-drive` | Download the user's Drive locally with rclone before any transfer. |
| `--backup-email` | Download the mailbox locally with GYB without restoring it anywhere. If a mailbox migration also runs, the migration's retained backup serves as the archive and nothing is downloaded twice. |
| `--backup-dir <path>` | Root for all backups (snapshots, mailbox, Drive). Default `./offboarding_backups`. Point it outside any synced folder. |
| `--reuse-email-backup <path>` | Restore from an existing GYB backup folder and skip the download. For resuming a restore that died partway. |
| `--restore-batch-size <n>` | Messages per Gmail import request on restore, 2 to 100, default 50 (1 is refused: GYB would save restore progress only at the end). Drop towards 10 if Gmail rate-limits. |
| `--strip-labels` / `--keep-labels` | On restore, discard the original Gmail labels (default under `--force`) or keep them. The migrated label is added either way. |

**Skipping phases**

| Flag | What it does |
|---|---|
| `--no-transfer` | Skip all transfers, forwarding, aliases, calendar, delegates and auto-reply. Only containment, devices, groups, licences, backups and suspension run. |
| `--no-snapshot` | Skip the pre-flight snapshot. |
| `--no-devices` | Skip device management. |
| `--no-delegates` | Skip delegate cleanup. |
| `--no-drive` | Skip the Drive ownership transfer. |
| `--no-email` | Skip the mailbox migration. |
| `--no-alias` | Skip the alias transfer. |
| `--no-calendar` | Skip the calendar transfer. |
| `--no-forward` | Skip email forwarding. |
| `--no-auto-reply` | Skip the auto-reply. |
| `--no-suspend` | Skip the final suspension. Refused together with `--unsuspend`. |

**Overrides and deletion**

| Flag | What it does |
|---|---|
| `--unsuspend` | Temporarily unsuspend an already-suspended user for the full offboarding, then re-suspend at the end. |
| `--allow-admin-account` | Continue even though the user still holds Super Admin or delegated admin rights. The script does not revoke those roles. |
| `--scorched-earth` | Snapshot, kill switch, remove groups and licences, suspend, then permanently delete the user. Needs `--doit` and `--force`, refuses every backup and transfer flag, and asks you to type the address. |
| `--allow-orphaned-shared-drives` | With `--scorched-earth`, delete the user even when they are the only organiser of a Shared Drive. |

## Command builder (no-code helper)

If you would rather not hand-craft the command line, open
[`offboarding_command_builder.html`](offboarding_command_builder.html) in any
browser. It is a single self-contained HTML page (no server, no install, works
offline) that turns every flag into a form field with inline help. Fill in the
leaver, the successor, the domain and any phase toggles, and it renders the
exact `python3 offboard_user.py ...` command to copy.

## Mailbox migration and backup with GYB

The mailbox migration uses GYB to download the leaver's mail and restore it
into the successor's mailbox under a `_Migrated/<leaver>` label, so years of
mail arrive filed rather than flooding the successor's inbox. Before the
download starts the script checks that the destination has an active Gmail
mailbox, that the backup volume has room for the mailbox, and that the
destination is not the leaver's own address or alias. Restores commit per
batch, so a crash resumes instead of restarting, and a re-run on a later day
offers to resume into the existing backup folder rather than downloading the
mailbox again. A backup that comes up short against GYB's own message
database fails the run.

Messages whose headers Gmail refuses on import are recorded in a
skipped-messages CSV. The [GYB Mailbox Tools](../gyb-gmail-backup-tools/README.md) in
this repository check a backup and find those messages.

## Drive transfer and backup

Drive ownership moves to the successor into an organised folder named for the
leaver. With `--backup-drive`, rclone downloads the Drive first and a re-run
syncs into the previous backup rather than fetching everything again. If the
backup fails, the Drive transfer is held so the files stay with the leaver
for that re-run. Google
Forms and Sites cannot be exported and are reported as an accepted gap. Files
the leaver could access but did not own are skipped by GAM and reported with
a count and a verify instruction, not as a failure.

## Mail capture after suspension

Gmail-level forwarding stops the moment an account is suspended or deleted.
If mail to the leaver's address must keep arriving somewhere, that needs an
alias on the successor, a recipient address map, or a group, none of which
GAM can configure. The end-of-run MANUAL ACTION block prints the Admin
console steps for each option with the successor from `--forward-alias-to`
filled in.

## Already-suspended users

The script detects suspension at the start. With `--unsuspend` it validates
every destination first, unsuspends, verifies the change by reading it back,
runs the full offboarding, and re-suspends at the end. A guard re-suspends on
every other exit path too. Without the flag an interactive run asks; a
`--force` run continues without unsuspending and warns that the steps needing
an active account will fail. GYB's access to the mailbox is checked after the
unsuspend, since GYB cannot open a suspended mailbox; a run with mailbox work
that leaves the account suspended stops there, before any change. Restore-only
(`--reuse-email-backup`) checks GYB's access to the destination instead.

## Deleting the account

`--scorched-earth` takes the snapshot, runs the kill switch, removes groups
and licences, suspends, and then deletes the user. It refuses any backup or
transfer flag: run those first as a normal offboarding, confirm the data is
safe, then delete. It refuses to delete the sole organiser of a Shared Drive
unless told otherwise. Deleted Google Workspace users can be restored from the
Admin console for 20 days; after that the data is gone.

## How it compares to other offboarding tools

- **Offboarding by hand in the Admin console.** The console can do most of
  this, one screen at a time, with no record of what was done. This script
  does it in one run with a log, and in the order that does not break.
- **A folder of GAM one-liners.** Most admins have one. This is that folder
  after three years of production incidents turned into guards: destination
  validation before a multi-hour download, a licence that is not removed
  until the transfer verified, a suspended account that cannot be left active
  by a crash.
- **Commercial offboarding workflow products** such as Patronum, GAT Flow and
  Zenphi. Those are subscription platforms with scheduling and HR triggers.
  This is a free script you run from a terminal, with no agent in the tenant
  and nothing to license.
- **Identity-provider workflows** such as Okta Workflows. Those fit when the
  identity provider owns the lifecycle. This script fits the tenants that
  have GAM7 and an admin, which is most of them.

## Frequently asked questions

**Is it safe to run against a live tenant?**
It is dry-run by default and prints every command before you commit with
`--doit`. It has run in production on client tenants since 2023. Test against
a non-production domain first all the same; the
[test setup guide](offboarding_test_setup_guide.md) walks through building
one.

**Does it delete the user?**
Not unless you ask with `--scorched-earth`, `--doit` and `--force` together,
and type the address to confirm. The normal run ends with suspension.

**What does it not do?**
It does not revoke admin roles (it stops and tells you how). It does not move
Shared Drive content, which belongs to the drive. It cannot export Google
Forms or Sites. It cannot configure mail capture after suspension; it prints
the Admin console steps instead.

**Can it be scheduled or run from a ticketing system?**
Yes. `--force` with `--user` and the destination flags is fully
non-interactive, and the exit code reports the outcome. Every transfer phase
must have a destination or the run aborts before any change.

**Does it work with GAMADV-XTD3?**
It targets GAM7 (GAM ADV X), the successor to GAMADV-XTD3, and is verified
against the GAM7 command set. Upgrade first; the
[GAM7 Update](../gam7-update/README.md) wrapper in this repository does that.

**Does it work on Windows?**
Yes. Both test suites run on Windows and Ubuntu in GitHub Actions on every
push, because two shipped bugs were Windows-only.

**How long does an offboarding take?**
A full live offboarding of a small account took three to four minutes in our
test rounds. The mailbox is the variable: GYB downloads and restores at
Gmail's pace, and a large mailbox migration is an overnight job.

## Tests

Two offline suites, standard library only, no tenant needed:
`test_offboard_user.py` checks per-phase behaviour against captured GAM
7.48.01 output in `fixtures/`, and `test_offboard_main.py` drives `main()`
end to end and checks command order, exit code and summary. Both run in
GitHub Actions on Ubuntu and Windows. `TEST_PLAN.md` lists the live
scenarios and `LIVE_TEST_LOG.md` records each live round.

```bash
python3 test_offboard_user.py
python3 test_offboard_main.py
```

The command builder has its own jsdom test: `npm install && npm test`.

## Licence

Apache 2.0; see `LICENSE` at the repository root. Keep the attribution
header in `offboard_user.py` intact if you redistribute it.

## Credits

[Gavin-X](https://github.com/Gavin-X) read the script closely and filed
twelve defects across two rounds, most of them runs that ended in a state the
operator could not see. The admin-account gate and the suspension-state
guards came out of that work. Thank you.

## Author

Paul Ogier is a Google Workspace consultant and trainer at
[Outsource House](https://osh.co.za) in South Africa, and teaches the
[Taming GAM7 & GAMADV-XTD3](https://taming.tech/GAMCourse) course on Udemy.
Questions and bug reports are welcome as
[GitHub issues](https://github.com/PaulOgier/GoogleWorkspaceScripts/issues).
