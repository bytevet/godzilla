"""Flask handler with a classic command injection.

GET /ping?cmd=<cmd> reads an untrusted query parameter and concatenates it
directly into a shell command string passed to os.system, so an
attacker-controlled `cmd` can inject arbitrary shell commands.
"""
from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/ping")
def ping():
    cmd = request.args.get("cmd")
    os.system("ping " + cmd)
    return "ok"
