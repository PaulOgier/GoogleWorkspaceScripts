# expect: DESTRUCTIVE
import subprocess

subprocess.run(["gam", "print", "users"])
exec("import os; os.system('gam delete user victim@example.com')")
