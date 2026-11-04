"""CHK-01 check: paste a block with a blank line into gamcheck under an interactive bash, and see whether the shell runs the rest.

gam is a shell function that only echoes and PATH holds only the python3 in BINDIR, so nothing
real can run. Never put a real gam in BINDIR. PAYLOAD sets the paste (\\r for Enter, |GAP| for a
pause of GAP seconds, default 0.6). Usage: python3 pastetail.py <gamcheck.py> <BINDIR> [-v]
"""
import os, pty, select, sys, time
checker, bindir = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.environ.clear()
    os.environ.update(PATH=bindir, HOME='/nonexistent', TERM='dumb', PS1='PROMPT$ ')
    os.execv('/bin/bash', ['bash', '--norc', '--noprofile', '-i'])
out = b''
def pump(secs):
    global out
    end = time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                c = os.read(fd, 65536)
            except OSError:
                return
            if not c:
                return
            out += c
pump(1)
os.write(fd, b'gam() { echo "FAKE-GAM-RAN $*"; }\r')
pump(0.5)
os.write(fd, f'python3 {checker}\r'.encode())
pump(2)
# one write, as a terminal paste delivers it
pl = os.environ.get("PAYLOAD", "gam print users\r\recho PASTED-TAIL-RAN; gam delete user bob@example.com\r\r").encode().replace(b"\\r", b"\r")
parts = pl.split(b"|GAP|")
for i, part in enumerate(parts):
    if i: pump(float(os.environ.get("GAP", "0.6")))
    os.write(fd, part)
pump(4)
os.write(fd, b'exit\r')
pump(1)
os.kill(pid, 9); os.waitpid(pid, 0)
t = out.decode(errors='replace')
tail_ran = 'PASTED-TAIL-RAN\r\n' in t or 'FAKE-GAM-RAN delete' in t
verdict = t[t.find('VERDICT'):].split('\n')[0] if 'VERDICT' in t else 'no verdict'
print(f'verdict: {verdict.strip()} | tail ran in shell: {tail_ran} | extra-lines note: {"more pasted line" in t}')
if '-v' in sys.argv: print(t)
