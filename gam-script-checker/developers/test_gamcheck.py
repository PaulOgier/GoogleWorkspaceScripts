#!/usr/bin/env python3
"""Self-checks for gamcheck.py. Run: python3 developers/test_gamcheck.py

Each fixture declares its expected verdict on an 'expect:' line. The verb
coverage test fails when a GAM release adds a verb with no danger level, so a
new verb can never default to read-only.
"""
import json
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


def test_checker_is_inert():
    """gamcheck itself imports nothing that runs programs or opens the network, and calls no exec/eval."""
    import ast
    tree = ast.parse((ROOT / 'gamcheck.py').read_text(encoding='utf-8'))
    allowed = {'argparse', 'ast', 'csv', 'json', 're', 'shlex', 'sys', 'dataclasses', 'pathlib', 'readline',
               'contextlib', 'io'}
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
    print(f'ok: {n} fixtures, details, verb coverage, positive control, paste, gates, adversarial, inert, invariants')


if __name__ == '__main__':
    try:
        main()
    except AssertionError as e:
        print(f'FAIL: {e}')
        sys.exit(1)
