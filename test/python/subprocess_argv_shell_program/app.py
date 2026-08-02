"""An argv list that LAUNCHES a shell is still command injection.

No shell=True, but argv[0] re-interprets what follows. Contrast
subprocess_argv_safe, whose argv[0] is `ls`.
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    subprocess.run(["sh", "-c", cmd])  # argv[0] is a shell: re-interpreted
    return "ok"


@app.route("/run-abs")
def run_abs():
    cmd = request.args.get("cmd")
    subprocess.run(["/bin/bash", "-c", "ls " + cmd])  # absolute path, same thing
    return "ok"
