"""An argv list that LAUNCHES a shell is still command injection.

`subprocess.run(["sh", "-c", cmd])` passes no shell=True, so the argv-list
suppression would clear it on shape alone -- but argv[0] is a shell, which
re-interprets the remaining arguments, so the untrusted value is executed. The
guard therefore requires argv[0] to be a known program that is not itself a
shell before it suppresses.

Contrast test/python/subprocess_argv_safe, whose argv[0] is `ls`.
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
