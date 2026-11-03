# GAM Script Checker: know what a GAM command does before you run it

A free, offline safety checker for Google Workspace administrators. Paste a
`gam` command, or point it at a script (bash, PowerShell, batch, Python or a
gam batch file), and it tells you whether the command **reads, changes or
deletes** something in your Google Workspace tenant or on your computer,
before you run it. It never runs the script or gam, and it does not need GAM
installed.

It exists for the moment you have copied a GAM command from a forum post, a
blog, a colleague's script or an AI chat, and are not completely sure what it
will do to a live tenant.

> ⚠️ **This tool is in testing.** It reads a GAM script and tells you what the script would do, but it can miss things. A READ-ONLY result means the checker found nothing that changes your tenant. It is not a promise that the script is safe. If you are unsure about a script, do not run it: ask someone who knows GAM, and test on a non-production domain first.

Built and maintained by Paul Ogier, [Outsource House](https://osh.co.za).
Training at [Taming.Tech](https://taming.tech).

## Contents

- [Who this is for](#who-this-is-for)
- [What the result means](#what-the-result-means)
- [Before you start](#before-you-start)
- [Mac](#mac)
- [Windows](#windows)
- [Linux](#linux)
- [Try it first](#try-it-first)
- [Handy options](#handy-options)
- [What it can and cannot tell you](#what-it-can-and-cannot-tell-you)
- [What it reads](#what-it-reads)
- [Exit codes](#exit-codes)
- [Frequently asked questions](#frequently-asked-questions)
- [Maintaining it](#maintaining-it)
- [Licence](#licence)

## Who this is for

- **Google Workspace admins** about to run a GAM command they did not write.
- **Anyone using an AI assistant to write GAM scripts**, since a generated
  script can carry a `delete` where you asked for a `print`.
- **MSPs and helpdesks** that want a second pair of eyes on every script
  before it touches a client tenant, in a form a junior can run.
- **Course students** learning GAM7 who want to see what a command does
  before pointing it at a test domain.

## What the result means

Read the **VERDICT** line first. It is the worst thing the checker found anywhere in the script.

| Verdict | Meaning | What to do |
|---|---|---|
| READ-ONLY | Every command it found only reads | Fine to run |
| CHANGES | Creates, updates, suspends, moves or shares something | Read every CHANGES line before running |
| DESTRUCTIVE | Deletes, wipes, purges, trashes or removes something, or erases files on your computer | Stop. Be sure you want every DESTRUCTIVE line |
| CANNOT TELL | Something is only decided when the script runs, or no gam command was visible | Treat it as dangerous until someone checks it |
| SUSPICIOUS | Reads GAM's credential files and can send data out, or runs hidden or downloaded code | Do not run it |

Lines marked **SECURITY** weaken account protection or widen access (turning off 2-Step Verification, forwarding mail, adding delegates or admins, sharing files). They are listed whatever their level.

Where Google documents a way to undo something, the line carries an **UNDO** note, for example "an admin can restore a deleted user for 20 days", with the help page it came from. No UNDO line means Google documents no window, not that nothing can be recovered.

## Before you start

You need two things:

1. **The whole `gam-script-checker` folder**, not just `gamcheck.py`. The checker reads the `verbs` folder next to it and will not work without it. You can ignore the `developers` folder: it holds the tests and the tools that rebuild `verbs`. To get it, open the [GAM Script Checker releases](https://github.com/PaulOgier/GoogleWorkspaceScripts/releases?q=gam-script-checker&expanded=true), find the newest one, download the `.zip` file under **Assets** whose name starts with `gam-script-checker`, and unzip it:
   - **Mac:** double-click the zip (Safari may already have unzipped it).
   - **Windows:** right-click the zip and choose **Extract All**. Double-clicking only shows what is inside, and the checker cannot run from there.
   - **Linux:** right-click the zip and choose **Extract Here**.
2. **Python 3.9 or newer.** Nothing else to install.

There are two ways to use it:

- **Paste mode** checks a command or a few commands you copied from somewhere (a web page, a chat, an email).
- **File mode** checks a whole script saved as a file (`.sh`, `.ps1`, `.bat`, `.cmd`, `.py` or a gam batch `.txt`).

Use file mode for any script with blank lines in it: a blank line ends a paste.

## Mac

### Open Terminal in the checker folder

1. Press **Cmd+Space**, type `Terminal`, press **Enter**.
2. Type `cd` followed by a space. Do not press Enter yet.
3. Drag the `gam-script-checker` folder from Finder into the Terminal window. Its location appears after `cd`.
4. Press **Enter**.

If you have never used Python on this Mac, the first command below may ask to install the developer tools. Click **Install**, wait for it to finish, then run the command again.

### Paste mode

1. Type `python3 gamcheck.py` and press **Enter**.
2. Paste the command with **Cmd+V**.
3. Press **Enter twice**. The report appears.

### File mode

1. Type `python3 gamcheck.py` followed by a space. Do not press Enter yet.
2. Drag the script file from Finder into the Terminal window.
3. Press **Enter**. The report appears.

## Windows

### Get Python

Open the Start menu, type `cmd`, open **Command Prompt**, type `py --version` and press **Enter**. If it prints `Python 3.9` or higher, you are ready. If not, install Python from [python.org/downloads](https://www.python.org/downloads/) and run the check again.

### Open Command Prompt in the checker folder

1. Open the `gam-script-checker` folder in File Explorer.
2. Click the address bar at the top of the window, so the folder path turns blue.
3. Type `cmd` and press **Enter**. A Command Prompt window opens in that folder.

### Paste mode

1. Type `py gamcheck.py` and press **Enter**.
2. Paste the command with **Ctrl+V** (or right-click in the window). If Windows warns that the text has several lines, choose to paste anyway.
3. Press **Enter twice**. The report appears.

### File mode

1. Type `py gamcheck.py` followed by a space. Do not press Enter yet.
2. Drag the script file from File Explorer into the Command Prompt window.
3. Press **Enter**. The report appears.

If `py` is not recognised, use `python` instead of `py` in the commands above.

## Linux

### Open a terminal in the checker folder

1. Open the `gam-script-checker` folder in your file manager.
2. Right-click an empty part of the window and choose **Open in Terminal**. If your file manager has no such option, open a terminal, type `cd` and a space, drag the folder into the window and press **Enter**.

Check Python with `python3 --version`. Most distributions already have 3.9 or newer.

### Paste mode

1. Type `python3 gamcheck.py` and press **Enter**.
2. Paste the command with **Ctrl+Shift+V** (plain Ctrl+V does not paste in most Linux terminals).
3. Press **Enter twice**. The report appears.

### File mode

1. Type `python3 gamcheck.py` followed by a space. Do not press Enter yet.
2. Drag the script file into the terminal window, or type its name if it is in the same folder.
3. Press **Enter**. The report appears.

## Try it first

These commands are only for practising with the checker. **Do not run them in gam**: the last one deletes a user.

```
gam print users
gam update user bob@example.com suspended on
gam $VERB user bob@example.com
gam delete user bob@example.com
```

Paste all four in paste mode. The checker should say DESTRUCTIVE, with one line at each level: a read, a change, a cannot tell (the verb is in a variable, so it cannot be judged), and a delete carrying a 20-day UNDO note.

For file mode, check `developers/fixtures/offboard.sh` from inside the checker folder. It should also say DESTRUCTIVE (1 changes, 3 destructive).

### Checking it yourself on Windows, macOS and Linux

Save the four lines above as `demo.txt` and run the checker over it. One run shows all four levels, so it doubles as a test that the output renders properly on your machine.

macOS and Linux:

```
python3 gamcheck.py demo.txt
```

Windows, in cmd or PowerShell:

```
python -c "import sys;print('encoding:', sys.stdout.encoding)"
python gamcheck.py demo.txt
```

The encoding line matters on Windows. The report prefixes each level with a coloured dot, and a console that cannot encode those characters gets the plain ASCII report instead, which is the intended behaviour rather than a fault. So `utf-8` should show the dots and `cp1252` should show clean ASCII with no dots. **Either one is a pass.** What is not a pass is question marks, empty boxes, or a `UnicodeEncodeError`; report that as a bug.

Two places this bites: a Windows console on a legacy code page, where `chcp 65001` before the run switches it to UTF-8, and an SSH session into Windows, which reports `cp1252` even when the desktop console is UTF-8.

## Handy options

Add these after the file name:

```
python3 gamcheck.py cleanup.ps1 --quiet     # hide the read-only lines in a long script
python3 gamcheck.py script.py --json        # machine-readable output for other tools
```

In paste mode the checker also tidies what you pasted, and tells you when it does: it removes a copied prompt (`$ gam ...`, `> gam ...`), straightens curly quotes picked up from a web page or chat (gam will not accept them), and guesses PowerShell or batch from the text.

## What it can and cannot tell you

- **It reads text. It does not run anything.** Commands put together while the script runs (a verb held in a variable, a command typed at a prompt, a list built in a loop) come out as **CANNOT TELL**, never as READ-ONLY.
- **It reports what the script can do, not what one run will do.** GAM's own safety words are understood: a Gmail, calendar-event or device command without `doit`, or a group, licence or Drive-transfer command with `preview`, is reported as a dry run. Two exceptions, because GAM acts on them without `doit`: a mobile or device named by its ID (only a `query` waits for `doit`), and `purge events`, which deletes the events permanently while printing "Not Deleted". A script's own `--dry-run` switch is not a safety word: if the code path exists, it is reported.
- **A change with no tenant check above it gets a NOTE.** A script run under the wrong `gam.cfg` section changes the wrong organisation, so the checker says when nothing like `gam info domain` comes before the first change.
- **Checking for damage to your computer uses a list of known commands** (`rm -rf`, `Remove-Item -Recurse`, `format`, `diskpart` and so on). A determined author can get past a list. This catches careless or AI-generated scripts. It is not a sandbox against a malicious one.
- **A gam command handed to another program as text** (`bash -c "gam ..."`, `ssh host "gam ..."`, `Start-Process -ArgumentList "..."`, `"$(gam ...)"`) is reported as **CANNOT TELL** with the text shown. Check the inner command on its own. Wrappers that pass gam through directly (`sudo -u x gam`, `timeout 300 gam`, `python3 gam.py`, `$GAM`) are followed.
- **Obfuscated code is flagged, not decoded.**
- **Row counts need the file.** "Deletes every user in leavers.csv (212 rows)" only appears when the CSV is next to the script or in the current folder.
- **Placeholders read as CANNOT TELL.** A command copied from documentation with `<GOOGLE SHEET ID>` or `<UserTypeEntity>` still in it cannot be judged.
- **It says what a script would do, not whether it works.** A command GAM7 would reject can still get a verdict when its verb is valid. A green READ-ONLY is not a syntax check: `gam info cros crosquery "id:X"` reads as READ-ONLY although GAM7 rejects it, because `crosquery` is an entity word that belongs before the verb, not after `info cros`. Check the grammar in GAM's own wiki before you run something you have not run before.
- **Python that calls Google's APIs directly** (`googleapiclient`) without gam is not analysed.
- **The command tables go out of date.** They are built from GAM's own source (GAM7 7.48.20, GAMADV-XTD3 7.06.04, legacy GAM 6.58). A command they do not know is CANNOT TELL. A new safety switch added to a command GAM already had is not picked up automatically.

A command written for GAMADV-XTD3 or legacy GAM that GAM7 no longer accepts is named as such, because it will stop with an error on GAM7.

## What it reads

| File | How gam is found |
|---|---|
| `.sh`, no extension | `gam ...`, `$GAM ...` when `GAM=` holds its path, aliases, functions passing `"$@"` to gam |
| `.ps1` | `gam ...`, `& $gam ...`, `Set-Alias`, functions passing `@args` |
| `.bat`, `.cmd` | `gam ...`, `%GAM% ...` |
| `.py` | `subprocess` and `os.system` calls, wrapper functions such as `def gam(*args)`, gam command strings and argument lists kept as data |
| `.txt` | GAM batch files (`gam batch`, `gam tbatch`), including `execute` lines |

`gam csv`, `gam loop`, `gam batch` and `gam tbatch` are followed into the command they repeat or the file they run.

A line that runs another script (`python3 audit.py`, `bash ./offboard.sh`, `pwsh -File x.ps1`, `./x.sh`) is followed into that script when it exists on this computer, so a one-line paste that starts a script gets the script's verdict. `~` and `$HOME` are expanded; a path built from any other variable, or a script that is not there, reads as CANNOT TELL.

A shell script run with a mode word (`bash runbook.sh check`) is judged by the lines that mode runs. When the script reads the mode from its arguments (`MODE="${1:-check}"` or `$1` itself) and picks a branch with a plain compare (`if [ "$MODE" = "check" ]`, `case "$MODE" in check)`), the gam lines in the other branches are listed under NOT RUN IN THIS MODE and left out of the verdict. With no mode word, the default after `:-` is used. If the mode is tested any other way (a pattern, `&&`, a second assignment, `shift`, a mode decided at runtime), every line counts and a NOTE says why. Checked on its own (`gamcheck.py runbook.sh`), the whole script counts.

## Exit codes

For use in other scripts: the exit code is the verdict.

| Exit | Verdict |
|---|---|
| 0 | READ-ONLY |
| 1 | CHANGES |
| 2 | CANNOT TELL |
| 3 | DESTRUCTIVE |
| 4 | SUSPICIOUS |

## Frequently asked questions

**Is a READ-ONLY verdict a guarantee the script is safe?**
No. It means the checker found nothing that changes your tenant or your
computer. It can miss things, and it does not check that the commands are
valid GAM syntax. Test on a non-production domain first.

**Does it need GAM installed?**
No. It reads the script as text and never calls gam. Python 3.9 or newer is
the only requirement.

**Does it understand GAMADV-XTD3 and legacy GAM commands?**
Yes. The command tables are built from the source of GAM7, GAMADV-XTD3 and
legacy GAM, and a command that GAM7 no longer accepts is named as such.

**Can it check a script an AI assistant wrote for me?**
That is one of the main reasons it exists. Paste the script in, or save it and
use file mode. Generated scripts are where an unexpected `delete` or a variable
verb turns up most often.

**Can I use it in a pipeline or a pre-commit hook?**
Yes. The exit code is the verdict, and `--json` gives machine-readable output.

**Does it send my script anywhere?**
No. It runs offline and makes no network connection.

## Maintaining it

Everything except `gamcheck.py` and `verbs/` lives in `developers/`. Run these from the `gam-script-checker` folder:

```
python3 developers/test_gamcheck.py                        # fixtures, GAM gates, trigger-word attacks, verb coverage
python3 developers/real-world/score.py gamcheck.py         # hand-labelled real commands; fails on any under-warning (corpora are not shipped: build one with fetch_group_corpus.py and label it)
python3 developers/real-world/blind-adversarial-2026-09-13/blind_run.py gamcheck.py   # 178 hostile commands with expected levels from GAM source
git clone --depth 1 https://github.com/GAM-team/GAM.git
python3 developers/build_verb_table.py GAM/src/gam > verbs/gam7.json   # after a GAM release
git clone --depth 1 https://github.com/GAM-team/GAM.wiki.git
python3 developers/build_verb_table.py --wiki GAM.wiki verbs/gam7.json > verbs/wiki.json
python3 developers/test_gamcheck.py                        # fails if a new verb has no danger level
```

A new verb with no danger level fails the test instead of defaulting to read-only. Give it a level in `VERB_LEVEL` in `gamcheck.py`.

`developers/ttypaste.py` pastes lines into the checker through a real terminal, the way a person would, for testing paste mode on other machines.

Fixtures use example.com addresses only. Real scripts for local testing go in `developers/local-samples/`, which is never shipped.

## Licence

Apache License 2.0, copyright (c) 2026 Paul Ogier, Outsource House. Keep the attribution block at the top of `gamcheck.py` if you redistribute it. Provided as is, without warranty.

GAM training from Taming.Tech: [GAM7 course](https://taming.tech/GAMCourse), [Google Workspace Admin course](https://www.taming.tech/GoogleWorkspaceAdmin), [Google Workspace End-User course](https://www.taming.tech/TheCompleteWorkspaceCourse).
