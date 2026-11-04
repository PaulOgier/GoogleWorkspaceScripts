# Google Workspace Security Audit Script (GAM7, free and open source)

A free, open-source, **read-only Google Workspace (formerly G Suite) security
audit** in a single Python file, for a Google Workspace security assessment
you run yourself. `tenant_scope.py` collects tenant configuration and
security-posture data through [GAM7](https://github.com/GAM-team/GAM), runs a
findings engine over it, and renders a self-contained HTML report your client
(or your manager) can read: what was found, why it matters, what to do.

Use it to audit a Google Workspace tenant on day one of a new client, to
baseline a security uplift, to scope a Google Workspace migration or domain
move, or to produce the security section of an acquisition due-diligence pack.

Built and maintained by Paul Ogier, [Outsource House](https://osh.co.za).
Training at [Taming.Tech](https://taming.tech).

Quick start (full steps under [Install](#install) and [Usage](#usage)):

```
git clone https://github.com/PaulOgier/GoogleWorkspaceScripts.git
cd GoogleWorkspaceScripts/google-workspace-security-audit
python3 tenant_scope.py --admin admin@yourdomain.com
```

![Google Workspace security audit report showing severity tiles, a posture score and the top actions for public files, super admins without 2-step verification and Shared Drives with no manager](docs/sample-report.png)

## Contents

- [Who this is for](#who-this-is-for)
- [Why this exists](#why-this-exists)
- [What the audit checks](#what-the-audit-checks)
- [What you get](#what-you-get)
- [Safety posture: read-only by design](#safety-posture-read-only-by-design)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [How it compares to other Google Workspace audit tools](#how-it-compares-to-other-google-workspace-audit-tools)
- [Frequently asked questions](#frequently-asked-questions)
- [Tests](#tests)
- [Licence](#licence)

## Who this is for

- **Google Workspace administrators** who want a security review of their own
  tenant without clicking through every Admin console screen.
- **Managed service providers (MSPs) and IT consultants** who inherit tenants
  built by other people and need to know what is about to bite.
- **Security and compliance teams** who need evidence, not a screenshot: every
  finding traces back to a CSV of raw data.
- **Buyers and advisers** who need a Google Workspace security assessment as
  part of due diligence before an acquisition.

## Why this exists

We run IT for other companies, which means we regularly inherit Google
Workspace tenants that other people built. The same three situations kept
sending us into the Admin console with a checklist and a bad feeling:

- **A new client signs.** Day one, we need to know what is about to bite:
  which files are public on the web, whose mail quietly forwards off-domain,
  which admin left in 2019 but still holds the keys.
- **A client is preparing for something big**: a migration, a domain move, a
  security uplift. Before you change anything, you need an honest picture of
  what is there now.
- **A client is being acquired.** The buyer wants to know where the security
  gaps are before they sign, and "we clicked around the console for a day"
  is not an answer you can put in a due-diligence pack.

Clicking through the Admin console for that takes a day per tenant and still
misses things, because the console shows you settings one screen at a time
and never volunteers what you forgot to look at. This script pulls the data
in one pass, applies the checks we kept re-deriving by hand, and writes down
both the findings and the list of things it could not check.

Credit where it is due: we had been using this script on our own clients for
about six months when Dirk Grobler asked for help with his tenant-scoping
batch script on the
[google-apps-manager group](https://groups.google.com/g/google-apps-manager/c/9r_AeuiWOSg).
That question inspired us to open ours up to the Google admin community.
Thank you, Dirk.

## What the audit checks

Every check is graded **Critical**, **High**, **Medium** or **Info**. The
grade is shown in brackets below. Run `python3 tenant_scope.py --list` for
the full module registry with keys and tiers.

### Google Drive external sharing and public files

- Files **public on the web** [Critical]
- "Anyone with the link" sharing at scale [High]; fewer than 20 such files are
  listed for review [Info]
- Files shared with entire external domains [High]
- Files shared to named external people [Medium]
- Externally-owned files shared into the tenant [Info]
- Files opened to anyone in the last 30 days, from the Drive audit log [High]
- Files shared with outside people in the last 30 days, per user [Medium]
- Drive for desktop allowed on any computer, and Takeout per service [Info]

### Shared Drives

- Shared Drives with **no manager** (orphaned Shared Drives) [Critical],
  including drives whose every manager is suspended or archived; a drive
  managed through a group is not flagged
- Shared Drives open to external sharing, or holding external members [High]
- New Shared Drives defaulting to external sharing [Medium]
- Shared Drive creation and manager overrides left open, and per-drive copy
  and download controls [Info]
- Shared Drives the auditing admin could not scan are listed as **UNSCANNED**,
  never as clean

### Super admins, admin roles and 2-step verification

- Fewer than two super admins [Critical]
- Super admins **without 2-step verification** (2SV / MFA) [Critical]
- Admin accounts with app passwords [High]
- Admin accounts nobody has signed into for months [High]
- Delegates on admin mailboxes [High]
- Admin roles still held by suspended accounts [High]
- Organisational units where policy blocks 2SV enrolment [High]
- 2SV enrolment percentage across the tenant [Medium]
- 2SV that accepts text or phone-call codes [Medium]
- Super admins with 2SV but no security key or passkey [Medium]
- Super admins enrolled in 2SV but not held to it by policy [Medium]
- Super admins with no backup codes [Medium]
- Super admins who can reset their own password by phone or email [Medium]
- Super admins with personal recovery addresses or phone numbers [Medium]
- Admin role assignments pointing at deleted accounts [Medium]
- Admin rights spread across a large share of the userbase [Medium]
- The admin role map, the 2SV policy per organisational unit, the second
  factors (security keys, passkeys) each super admin holds, and super admins
  who also hold a paid licence [Info]

### Sign-in risk, alerts and admin activity

- Risky sign-in or account events Google recorded in the last 30 days
  (suspicious logins, leaked-password or hijack disables, government-backed
  attack warnings, forwarding out of the domain) [High]
- Sensitive actions Google blocked because the session looked risky, with
  the action named [Medium]
- High-severity Alert Center alerts in the last 30 days [Medium]
- Security alert rules switched off [Medium]
- Settings and admin-role changes, admin activity counts and failed sign-ins
  over the last 30 days [Info]

### Gmail: email forwarding, delegation, filters, POP and IMAP

- Mailboxes **forwarding outside the organisation** [Critical]
- Gmail filters forwarding externally [High]
- Gmail filters that hide mail about invoices or payments, or everything from
  one outside sender, the way a mailbox takeover does [High]
- Gmail phishing and malware protections switched off, listed per switch and
  per organisational unit [Medium]
- External forwarding addresses on file even where forwarding is off [Medium]
- Mailboxes that can send as an outside address [Medium]
- POP or IMAP enabled [Medium]
- Mailbox delegation involving suspended or dormant accounts [Medium]
- The full mailbox delegation map, and whether users may delegate their
  mailbox [Info]
- Out-of-office replies that answer anyone (`--full`) [Info]

### Google Groups

- Groups anyone can join, anyone can post to, or that allow external members
  [High]
- Groups with external members actually present, or whose message archive
  anyone can read [High]
- Groups with no owner, or owned by a suspended account [Medium]
- Groups anyone can find [Info]

### Accounts, licences and dormant users

- Unmanaged (personal) Google accounts on company domains [High]
- Accounts stacking multiple risk factors [Medium; High when an admin is
  among them]
- Accounts Google itself suspended for abuse or compromise [High]
- Users whose password Google rates weak or shorter than the tenant's own
  minimum [Medium]
- Licensed accounts that were never signed into, or dormant for more than
  90 days [Medium]
- Suspended accounts still holding paid licences [Medium]
- Licences owned but not assigned to anyone (licence waste) [Medium]. GAM
  reports owned seats only for G Suite Basic, Workspace Enterprise Plus,
  G Suite Business and Vault; on any other edition the check is not judged
  and is not listed as clean.
- Suspended accounts still holding data or Shared Drive roles [Info]
- Accounts created in the last 30 days, and users left in the root
  organisational unit [Info]

### Third-party OAuth apps

- Third-party apps holding full or read-everything Gmail or Drive access
  [Medium]
- Domain-wide delegation granted in the last 30 days, with broad scopes
  [Medium]. No API lists older grants, so they stay on the check-by-hand list.
- Every third-party app holding a token, with user counts and unidentified
  apps called out, plus third-party app access as the API reports it [Info]

### Domain DNS: MX, SPF, DKIM and DMARC

- Domains without DMARC or SPF [High]
- Domains without DKIM signing or with MX problems [Medium]
- MX, SPF, DKIM and DMARC checked per domain, including aliases

### Calendar, Chat and Meet

- Public primary calendars [Medium]
- Google Chat spaces open to every outside domain [Info]
- Google Meet safety settings [Info]

### Tenant policies

- Password policy below current practice (length, strength, reuse, not
  enforced at next sign-in, forced expiry) [Medium]
- Web sessions longer than Google's 14-day default [Medium]
- Paid-for edition security features left unused [Medium]
- The edition-only security features (DLP, Context-Aware Access, trust rules,
  security center, advanced mobile management) the tenant's licences include,
  shown only when they do [Info]
- Which Google services are switched on or off [Info]
- The security-checklist settings this audit does not judge, listed so they
  get checked by hand in the Admin console, and other checklist settings (Advanced
  Protection, passkeys, mail import and more) shown raw [Info]
- Settings looser than the CISA Google Workspace baseline: automatic
  forwarding allowed, 2-step verification skipped on trusted devices,
  internal apps trusted, any Marketplace app installable, Drive publishing to
  the web, Drive suggesting public sharing, new files open to the whole
  organisation, flagged attachments and spoofed mail left in the inbox, and
  anyone able to create groups [Medium]; lower-risk baseline items [Info].
  A setting nobody changed is judged at Google's documented default, and the
  report says so.

### Google Classroom (Education tenants only)

- Classes with members or invitations from outside the organisation [High]
- Classes owned by deleted or suspended accounts [Medium]
- Classroom open to anyone joining, or to unverified teachers creating classes [Medium]
- Guardians and pending guardian invitations, with their age [Info]
- Classroom settings and course counts [Info]

### Tenant inventory and Vault

- The tenant at a glance: users, licences, groups, Shared Drives, mobile and
  ChromeOS devices, Vault, SSO [Info]
- Vault exports on record [Info]

Anything that could not be checked (missing authorisation, module error,
unscanned drives) is listed in the report, and so is every check that ran
over real data and found nothing ("Checked and clean"). Absence of a finding
never means "checked and clean" unless the check appears in that list.
`findings_evidence.csv` carries every evidence row of every finding, so two
runs can be diffed by who was named, not just by counts.

## What you get

- `audit_report.html`: a single self-contained HTML file (no external
  assets), severity tiles up top, one section per finding with plain-English
  "what this means" and "what to do" copy, and evidence samples. Print it for
  a clean PDF.
- `findings.csv`: the findings list in machine-readable form, with whether
  each is new or carried over from last month, and the check that raised it.
- `findings_evidence.csv`: every evidence row of every finding, with a stable
  `evidence_id` for comparing months.
- The report's header and footer say it was made with the Google Workspace
  Security Audit by Outsource House (OSH.co.za), with the repository URL.
  The credit names the tool, not who prepared the
  report, so it stays true when you run it for your own clients. The report
  needs no JavaScript, so it opens in a sandboxed viewer or a mail preview.
- `qa_report.html`: for you, not the client. The delivery verdict.
- One CSV per collected module, so every finding can be traced back to raw
  data.
- `tenant_scope.log` + `gam_stderr.log`: the full audit trail.

## Safety posture: read-only by design

Every GAM command the script issues is a read (`print`, `report`, `info`,
`oauth info`, `check serviceaccount`), with one opt-in exception:
`--grant-temp-access`. GAM's `filelist` has no admin-access mode, so a
non-member scan silently returns zero rows and the drive would look clean.
Each Shared Drive is therefore listed as one of its own active members,
organizers first, and nobody's access changes. Only a drive that no member
can list (none active, or none with a Drive licence) needs the flag. It adds
the auditing admin as organizer, scans, and removes the grant again. Just
before granting, it checks the drive's live permissions: an admin who is
already a member (added since the ACLs were collected) is scanned as that
member, with no grant and no removal. Without the flag, those drives are
reported **UNSCANNED**.

Backup verification codes are never saved to the run directory: the
collector keeps only the per-user count. GAM's output passes through an
anonymous temporary file (no name on disk, removed when the command ends),
as every command's output does.

It is safe to run against a production tenant. Nothing is changed, suspended,
deleted or transferred.

## Requirements

- Python 3.9+ (standard library only, no packages to install)
- GAM7 (GAM ADV X) installed and authorised against the tenant you are
  auditing. The script finds it on PATH, at `~/bin/gam7/gam` (macOS
  installer), or `C:\GAM7\gam.exe` (Windows).
- Works on Windows, macOS and Linux.

## Install

Clone the repository, or download `tenant_scope.py` on its own; it has no
dependencies beyond Python and GAM7.

```
git clone https://github.com/PaulOgier/GoogleWorkspaceScripts.git
cd GoogleWorkspaceScripts/google-workspace-security-audit
python3 tenant_scope.py --admin admin@yourdomain.com
```

## Usage

```
python3 tenant_scope.py --admin admin@yourdomain.com
```

That is the whole thing: tiers 1 to 3 plus the DNS checks, into a new
timestamped run directory, with the report opened at the end.

### Every flag

| Flag | What it does |
|---|---|
| `--admin <email>` | The auditing admin. Verifies the service account's DWD scopes in the preflight, and is the account the Shared Drive scans run as. Without it those scans are skipped and per-user modules run unverified. With `--tenant` or `--all`, a tenant's `admin` in `tenants.json` is used when this is not given. |
| `--list` | Print the module registry (key, title, tier) and exit. |
| `--full` | Add the tier-4 modules: vacation responders, managed browsers, context-aware access, Gmail profile sizes and Drive file counts. |
| `--only <keys>` | Comma-separated module keys; everything else is skipped except `domains` and `domainaliases`, which always run because every external-sharing check needs the tenant's domain list. If the domain list cannot be read, no address is reported as external and the report is held for review. |
| `--skip <keys>` | Comma-separated module keys to skip. |
| `--skip-tier <n>` | Skip a whole tier, e.g. `--skip-tier 3` to leave out the heavy Drive scans. |
| `--no-dns` | Skip the DNS checks. |
| `--tenants <file>` | The tenants file (default `~/.osh/workspace-audit/tenants.json`). |
| `--tenant <key>` | Audit one tenant from the tenants file. |
| `--all` | Audit every enabled tenant in the tenants file, one after another. |
| `--compare-with <dir>` | Compare with this run instead of the newest completed earlier run of the same customer. |
| `--include-suspended` | Include suspended accounts in the per-user scans. Default is active accounts only, and the report says which. |
| `--skip-never-logged-in` | Exclude accounts that have never signed in from the per-user scans. |
| `--grant-temp-access` | The one write in the script. Needs `--admin`. See below. |
| `--output-dir <dir>` | Where run directories are created. Default `./tenant_audit_runs/`. |
| `--run-dir <dir>` | Resume an existing run. Completed modules are skipped. |
| `--render-only` | Re-run the checks and rebuild the report from a `--run-dir` (required), with no GAM calls at all. |
| `--dry-run` | Print every GAM command without executing it. The preflight still runs `gam version` and `gam info domain`; only `--render-only` makes no GAM call at all. |
| `--no-open` | Don't open the report in a browser when the run finishes. On Linux with no display (`DISPLAY` and `WAYLAND_DISPLAY` unset, as over ssh) the report is never opened, so a console browser cannot hold the run. |
| `--yes` | Skip the interactive tenant confirmation. The identity is still logged. |

### Worked examples

```
python3 tenant_scope.py --list
python3 tenant_scope.py --admin admin@yourdomain.com --full
python3 tenant_scope.py --admin admin@yourdomain.com --skip-tier 3
python3 tenant_scope.py --admin admin@yourdomain.com --only users,groups,dns
python3 tenant_scope.py --admin admin@yourdomain.com --run-dir <dir>
python3 tenant_scope.py --render-only --run-dir <dir>
python3 tenant_scope.py --admin admin@yourdomain.com --dry-run
python3 tenant_scope.py --admin admin@yourdomain.com --grant-temp-access
python3 tenant_scope.py --admin admin@yourdomain.com --skip-never-logged-in --no-open --yes
```

**Overnight on a large tenant.** `--skip-tier 3` first for the quick picture,
then the same run directory again without the skip so only the Drive scans
execute:

```
python3 tenant_scope.py --admin admin@yourdomain.com --skip-tier 3
python3 tenant_scope.py --admin admin@yourdomain.com --run-dir tenant_audit_runs/tenant_audit_<stamp>
```

**Re-render after a fix.** If a check itself was wrong, you do not need to
collect anything again:

```
python3 tenant_scope.py --render-only --run-dir tenant_audit_runs/tenant_audit_<stamp>
```

**Scheduled or headless.** `--yes` answers the tenant prompt, `--no-open`
leaves the browser alone:

```
python3 tenant_scope.py --admin admin@yourdomain.com --yes --no-open
```

**A tenant full of accounts nobody has ever used.** `--skip-never-logged-in`
drops them from the per-user scans, and the report states how many were
excluded. It is off by default because an admin-set forward on an account
nobody has ever signed into is exactly the thing an audit should find:

```
python3 tenant_scope.py --admin admin@yourdomain.com --skip-never-logged-in
```

**Shared Drives.** `filelist` has no admin-access mode, so a non-member scan
returns zero rows and looks clean. Each drive is listed as one of its own active
members instead (the `shareddrive.scannedAs` column says who), which works even
when the auditing admin has no Workspace licence. A member sees what membership
shows them, so a limited-access folder they are kept out of is not covered.
A drive no member can list is reported UNSCANNED unless you pass
`--grant-temp-access`, which adds the auditing admin as organizer, scans, and
removes the grant again:

```
python3 tenant_scope.py --admin admin@yourdomain.com --grant-temp-access --only shareddrive_external
```

### How a run behaves

The preflight confirms the tenant (primary domain + customer ID) with you
before anything is collected, because auditing the wrong tenant is the worst
silent failure this kind of tool can have. `--yes` skips the prompt but still logs
the identity.

Collection runs in three passes. The domain and user lists go first because
everything else depends on them. The tenant-level prints (OUs, groups, admins,
devices, policies, reports, DNS) then run four at a time, since each is one
short GAM process and the long ones (`report users`, `tokens`) hide the rest.
The per-mailbox modules and the Drive scans run one at a time. Each already
forks up to 20 GAM processes as a batch over an explicit list of the accounts
being audited. The tier-3 Drive sweeps use the same batch instead of one GAM
process per user.

Each per-mailbox batch runs up to 20 GAM workers (`SCAN_THREADS`), which want
about 4 GB of free memory. On a 130,000-file test tenant a full run took 5m51s
on a 4 GB machine and 10m49s on a 3 GB one, with no API rate-limit retries on
either. Memory runs out before Google's quota does. Set `SCAN_THREADS` to 10 on
a small box.

Since v1.7.0 the default run also reads every active user's Gmail filters, one
more per-mailbox sweep, so the check for filters that hide payment mail runs
every month. Skip it with `--skip filters` on a tenant where that is too slow.

Timeouts scale with the size of the tenant. GAM's own progress counters are
echoed to the console every 30 seconds during a long scan, so a Drive
enumeration that runs for hours doesn't look like a hang. If a command is
killed by its timeout, GAM and its batch children are all stopped, the rows
collected up to that point are kept, and the module is marked partial rather
than discarded.

Ctrl+C lets the module that is running finish (GAM runs in its own process
group, so the interrupt reaches the script and not GAM), then stops. The
report is still rendered over what was collected and the exit code is 130, so
a scheduled run can tell "complete" from "stopped". A second Ctrl+C (or a
second SIGTERM) kills everything and also exits 130, with no report. A
temporary organizer grant is recorded in `manifest.json` before
its removal runs and cleared only once the removal succeeds, so after either
kind of stop `qa_report.html` still names any grant left behind.

Each run writes into its own timestamped directory under
`./tenant_audit_runs/` (change with `--output-dir`). Runs are resumable:
`manifest.json` records completed modules, and `--run-dir` picks up where a
run stopped. An account with Gmail, Drive or Calendar switched off has nothing
to read, so it does not make a module partial; the report names those
accounts. A module marked partial for another reason is not re-run on resume,
since it would only end partial again; one cut short by a timeout is.

A default run on a small tenant takes a few minutes. The tier-3 Drive scans
are the expensive part on large tenants. Run them overnight, or start with
`--skip-tier 3` and fill in the blanks later. Run again with
`--run-dir <that dir>` and no skip flag, and only the missing modules run
before the report re-renders over the complete data set.

### Monthly runs and several tenants

Copy `tenants.example.json` to `~/.osh/workspace-audit/tenants.json` and add
one entry per client: its customer ID, and optionally the GAM config folder
for that tenant (`gamcfgdir`, used as `GAMCFGDIR`), emergency super admins
(`break_glass`) and the auditing admin for that tenant (`admin`, used when
`--admin` is not given). Keep the real file out of the
repository, since it names your clients.

- The run stops before collecting anything if `gam info domain` answers with
  a different customer ID from the one in the file.
- Runs go to `<output-dir>/<tenant key>/`, so each tenant's history stays
  separate.
- Break-glass accounts are left out of the dormancy checks and named in the
  report, rather than showing up every month as dormant admins.
- `--all` carries on when one tenant fails and returns the worst exit code.
- Give each entry its own `admin` for `--all`: without one the Shared Drive
  scans are skipped and the report is held. `--admin` with `--all` uses that
  one address for every tenant, and the script warns about it.

Exit codes: `0` complete, `1` preflight failed or wrong tenant, `2` complete
but some modules could not run, `130` interrupted.

### Reading the report

A finding looks like this in the HTML:

> **[CRITICAL] Mailboxes forwarding to addresses outside the organisation**
>
> *What this means:* All mail arriving in these mailboxes is being copied or
> moved to an external address. This is a common way company data quietly
> leaves the organisation, and one of the first things attackers set up
> after compromising an account.
>
> *What to do:* Confirm with each user whether the forward is legitimate
> business use. Remove any that are not, and review the account's recent
> sign-in activity if the forward was not set up knowingly.

Evidence tables show a sample (10 rows by default) with the true total in
the headline; the full list is always in the module's CSV next to the
report.

Under the severity tiles:

- **Posture score.** Google has no score of its own, so one is calculated
  from the findings: 15 points per critical, 7 per high and 3 per medium
  finding, and the score halves for every 70 points. It never reaches 0, so
  progress shows even on a badly set-up tenant. It uses the same formula as
  the Microsoft 365 audit.
- **Top actions.** The five most serious findings, each with the first step
  to take.
- **What changed since last month.** Each finding is marked new or carried
  over, rows within a finding are marked new, and resolved findings are
  listed. Only a completed earlier run of the same customer is used. A
  finding whose data was missing or only partly collected in either run, or
  whose check failed to run this time, is "not compared", never "resolved".
- **Upgrade opportunities.** Protections the tenant's edition does not
  include. They are never counted against the score.

`qa_report.html` says "Ready to send" or "Hold for review" with the reasons:
the run did not finish, or a module behind a critical check failed.

### DNS checks

Per domain, MX/SPF/DKIM/DMARC are checked through
[tamingdns.com](https://tamingdns.com). If it is unreachable, the module
falls back to dns.google with presence-only checks, and the report says
which path ran. An error reply from tamingdns counts as a failed check, never
a pass: when every check for a domain errors the domain falls back to
dns.google, and when only some do, the DNS module is marked partial and the
DNS checks are not listed as clean.

### Things the report states rather than hides

- GAM's `all users` iterates ACTIVE users only. Per-user checks cover active
  users unless you pass `--include-suspended`; the report says which.
- Usage-report figures (storage) lag roughly two days behind live state.
- Shared Drives the auditing admin cannot scan are listed as UNSCANNED.
- Policy checks report the *resolved* setting. The Policy API returns
  Google's defaults, the administrator's own policy and a copy per
  licence SKU for the same org unit; the highest `sortOrder` wins, per
  Google's Max reducer. Licence scoping is not modelled, so a setting
  that differs between two SKUs in one org unit shows only the
  winner. A policy applied to a group is reported on its own row as
  `group:<address>`, never merged into an org unit.

## How it compares to other Google Workspace audit tools

- **The Admin console security checklist and Security Center.** Google's own
  tools show one setting at a time and never tell you what you did not look
  at. This script checks the whole tenant in one pass and lists what it could
  not check.
- **Google Workspace security audit checklists** (the blog-post kind). Those
  tell you what to look for. This script looks, and writes the report.
- **Commercial auditing platforms** such as GAT Labs. Those are subscription
  products with continuous monitoring and remediation. This is a free,
  point-in-time audit you run yourself, with the raw CSVs next to the report.
- **Sheets-based checklists driven by the Admin SDK**, such as DoiT
  AdminPulse. Similar goals; this one runs locally through GAM7 you already
  have, adds Drive and Shared Drive sharing scans, Gmail forwarding and
  delegation, licence waste and DNS, and renders a client-ready HTML report.
- **Drive-only sharing audit scripts**. External file sharing is one section
  of this report, alongside admins, 2SV, Gmail, Groups, licences, OAuth apps
  and DNS.
- **CISA ScubaGoggles.** CISA's tool for checking a tenant against its SCuBA
  Google Workspace baselines. This script's baseline settings checks were
  written with ScubaGoggles as a guide (its rules are public domain), and run
  on the data GAM already collects, so you need no second tool or set of
  credentials. ScubaGoggles reports configuration; this script also reports
  the people-level findings it does not: who forwards mail outside, which
  files are public, dormant admins, risky app grants.

## Frequently asked questions

### Is it safe to run against a live production tenant?

Yes. Every command is a read. The only write, `--grant-temp-access`, is off
by default, is only used on a drive none of its members can list, and removes
its own grant when the scan finishes.

### Does it work with GAMADV-XTD3?

It is built and tested against GAM7 (GAM ADV X), the successor to
GAMADV-XTD3, and looks for the `gam7` binary. If you are still on
GAMADV-XTD3, upgrade first; the [GAM7 Update](../gam7-update/README.md) wrapper in
this repository does that safely on macOS and Linux.

### Do I need a service account with domain-wide delegation?

For the tenant-level modules, no. The per-mailbox modules (forwarding,
delegates, IMAP/POP, send-as) and the Drive scans do need domain-wide
delegation, which is the standard GAM7 setup. The preflight tells you which
scopes are missing, and the report lists any module that could not run.

### Can I use it before a Google Workspace to Google Workspace migration?

That is one of the reasons it exists. Run it on the source tenant to
inventory users, licences, groups, Shared Drives, external sharing and
forwarding before you move anything, and again on the target tenant when the
migration is done.

### How long does a Google Workspace audit take with this script?

A few minutes on a small tenant. On large tenants the Drive sharing scans are
the slow part; run them overnight with `--run-dir` resume, or skip tier 3 for
a quick first picture.

### Does it fix anything?

No. It reports. Fixing is a decision for a human with context, and the "what
to do" copy in each finding is written for that human.

### Which GAM commands does it run?

`--dry-run` prints every GAM command without executing it, so you can review
the whole list before the first real run. The preflight still runs
`gam version` and `gam info domain`.

### What does it connect to besides GAM?

At start it reads the latest version number from `raw.githubusercontent.com`
to say whether an update is out (not with `--list` or `--render-only`). The
preflight checks `www.googleapis.com` is reachable. The DNS module sends each
domain name, and the DKIM selector, to `tamingdns.com`, or queries
`dns.google` when tamingdns.com is unreachable. Nothing else leaves the
machine except GAM's own calls to Google.

### How do I find files shared publicly in Google Drive across the whole domain?

Run the default audit. The Drive scans read the sharing on every user's files
and every Shared Drive, and the report lists files public on the web,
"anyone with the link" files and files shared with outside domains or
people. The Drive audit log adds files opened to anyone in the last 30 days.

### How do I find users forwarding email outside the organisation in Google Workspace?

The Gmail section of the report lists every mailbox forwarding to an outside
address, Gmail filters that forward externally, and forwarding addresses on
file where forwarding is off. Each finding traces back to a CSV of the raw
rows.

### How do I check which super admins don't have 2-step verification?

The "Super admins, admin roles and 2-step verification" section reports super
admins without 2SV as Critical, and also lists super admins with 2SV but no
security key or passkey, and those enrolled but not held to it by policy.

### How do I find dormant Google Workspace accounts and wasted licences?

The "Accounts, licences and dormant users" section lists licensed accounts
never signed into or dormant for more than 90 days, suspended accounts still
holding licences, and licences owned but not assigned. Emergency accounts
listed under `break_glass` in `tenants.json` are left out of the dormancy
checks; `--skip-never-logged-in` leaves accounts that have never signed in
out of the per-user scans.

### Can I run a Google Workspace security audit every month and see what changed?

Yes. Each run is compared with the last completed run of the same customer
ID, and every finding is marked new, persisting or resolved, with a posture
score and its trend. `--compare-with <dir>` picks a different earlier run, and
`--tenants` with `--all` runs every tenant in one go (see
[Monthly runs and several tenants](#monthly-runs-and-several-tenants)).

### Does it check against the CISA Google Workspace baselines?

Yes, for the settings GAM can read. The "Tenant policies" section reports
settings looser than the CISA SCuBA Google Workspace baseline, each row citing
its requirement. It does not run ScubaGoggles itself.

## Tests

```
python3 -m unittest test_tenant_scope -v
```

362 tests, no GAM calls, no fixtures on disk beyond temp directories.
`python3 test_tenant_scope.py` runs the same tests.

## Licence

Apache 2.0; see `LICENSE` at the repository root. Keep the attribution
header in `tenant_scope.py` intact if you redistribute it.

## Author

Paul Ogier is a Google Workspace consultant and trainer at
[Outsource House](https://osh.co.za) in South Africa, and teaches the
[Taming GAM7 & GAMADV-XTD3](https://taming.tech/GAMCourse) course on Udemy.
Questions and bug reports are welcome as
[GitHub issues](https://github.com/PaulOgier/GoogleWorkspaceScripts/issues).
