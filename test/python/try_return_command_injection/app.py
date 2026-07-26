"""Taint must survive a try body that TERMINATES (return/raise).

When the try body ends in a return, its only non-terminating successor is the
exception handler, so that edge must still be wired -- otherwise the handler
block has no predecessor, every variable read there resolves to the SSA
builder's undefined value, and taint bound BEFORE the try is silently lost.
`cmd` is bound before the try and reaches the sink inside the handler.
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("c")
    try:
        return "fast path"
    except ValueError:
        subprocess.run(cmd, shell=True)
    return "done"
