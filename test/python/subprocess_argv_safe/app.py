"""Safe subprocess usage: the untrusted value is passed as a single element of a
direct argv list (no shell), so it is an argument to `ls`, not shell-interpreted
— this is NOT command injection and must produce ZERO findings. Guards against a
future container-taint change spuriously flagging the safe argv form.
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ls")
def ls():
    name = request.args.get("name")
    subprocess.run(["ls", "-la", name])  # direct argv, no shell: safe
    return "ok"
