"""Command injection via a shell-string subprocess call. The untrusted value is
concatenated into a command string run with shell=True, so it is interpreted by
the shell — the dangerous form (contrast subprocess_argv_safe).
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    subprocess.check_output("grep " + cmd + " /etc/hosts", shell=True)  # sink
    return "ok"
