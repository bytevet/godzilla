# Safe control for the loop-carried case: same shape as
# loop_carried_command_injection, but the value carried across iterations is a
# CONSTANT, never the tainted request parameter. The header PHI merges two
# constants ("whoami" and "id"), so no untrusted data reaches the shell and
# nothing fires — the false-positive guard for the loop-carried CFG.
from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = "whoami"
    i = 0
    while i < 3:
        os.system(cmd)
        cmd = "id"
        i += 1
    return "ok"
