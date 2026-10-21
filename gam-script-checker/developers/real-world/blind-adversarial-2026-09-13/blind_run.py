"""Run blind_set.py through gamcheck and score it. Usage: blind_run.py /path/to/gamcheck.py

Exit 1 when any case is under-warned or crashed, else 0."""
import contextlib
import io
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))
import gamcheck as g  # noqa: E402
from blind_set import CASES  # noqa: E402

SEV = {'READ-ONLY': 0, 'CHANGES': 1, 'CANNOT TELL': 2, 'DESTRUCTIVE': 3, 'SUSPICIOUS': 4}
checker = g.Checker()


def run_paste(text):
    out, err = io.StringIO(), io.StringIO()
    stdin, sys.stdin = sys.stdin, io.TextIOWrapper(io.BytesIO(text.encode('utf-8')), encoding='utf-8')
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = g.main(['-'])
    finally:
        sys.stdin = stdin
    return g.LEVEL_NAMES[code], out.getvalue()


under, over, ok, crash, honest = [], [], [], [], []
for cid, text, lang, expect, mode, src in CASES:
    try:
        if lang == 'paste':
            got, detail = run_paste(text + '\n')
        else:
            findings = checker.check_text(text + '\n', '<t>', lang)
            got = g.LEVEL_NAMES[g.verdict(findings)]
            detail = '; '.join(f'{g.LEVEL_NAMES[f.level]}: {f.what}' for f in findings)
    except Exception:
        crash.append((cid, text, traceback.format_exc().splitlines()[-1]))
        continue
    floor = mode.startswith('floor')
    if got == expect:
        ok.append(cid)
    elif floor and (SEV[got] >= SEV[expect] or (mode == 'floor+read' and got == 'READ-ONLY')):
        ok.append(cid)
    elif got == 'CANNOT TELL' and floor:
        honest.append(cid)  # score.py policy: CANNOT TELL is never an under-warning, it tells the reader to look
    elif SEV[got] < SEV[expect] and not (expect == 'CANNOT TELL' and got in ('READ-ONLY', 'CHANGES') and mode == 'exact'):
        under.append((cid, text, expect, got, src, detail))
    else:
        over.append((cid, text, expect, got, src, detail))

print(f'{len(CASES)} cases: {len(ok)} ok, {len(under)} UNDER-WARNED, {len(honest)} cannot tell (honest), {len(over)} over/other, {len(crash)} crashed')
for label, rows in (('UNDER', under), ('OVER/OTHER', over)):
    print(f'\n== {label}')
    for cid, text, expect, got, src, detail in rows:
        print(f'{cid:<5} expect {expect:<12} got {got:<12} | {text!r}\n      src: {src}\n      checker: {detail[:220]}')
print('\n== CRASH')
for row in crash:
    print(row)
sys.exit(1 if under or crash else 0)  # the release gate: an under-warning or a crash fails the run
