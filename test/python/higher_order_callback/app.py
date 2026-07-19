# ENG: higher-order-callback taint. Untrusted input is handed to a generic helper
# that invokes a callback passed by reference; the tainted argument reaches the
# callback's body and the sink inside it. The engine tracks which concrete
# function was passed (function-value points-to) and resolves the indirect call.
import os

from flask import Flask, request

app = Flask(__name__)


def run_cmd(cmd):
    os.system(cmd)  # command-injection sink, reached only via the callback


def apply(data, fn):
    fn(data)  # indirect call through the callback parameter


@app.route("/run")
def handler():
    q = request.args.get("q")
    apply(q, run_cmd)  # tainted q + callback run_cmd -> os.system(q)
    return "ok"
