"""Flask handler with a command injection sourced via bracket subscript
access (`request.args["cmd"]`) rather than `.get("cmd")`.

This exercises converters/python/lower.go's opaque-root-chain handling of
Subscript reads (see the Subscript case of funcState.lowerExpr): the base of
the subscript, `request.args`, is rooted at `request`, an unbound
module-level import (an "opaque" root, not a local variable), so it lowers to
a synthetic source CALL with callee "py:request.args.__getitem__" instead of
a plain OP_CODE_INDEX. That callee matches the
"py:*request.args.__getitem__" source glob already declared (but previously
dead) in internal/rules/loader/builtin/py-command-injection.yaml.

GET /ping?cmd=<cmd> reads an untrusted query parameter and concatenates it
directly into a shell command string passed to os.system, so an
attacker-controlled `cmd` can inject arbitrary shell commands.
"""
from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/ping")
def ping_via_subscript():
    cmd = request.args["cmd"]
    os.system("ping " + cmd)
    return "ok"
