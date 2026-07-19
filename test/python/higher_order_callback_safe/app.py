# FP guards for higher-order-callback taint:
#  (1) the generic helper is called with TWO distinct callbacks, so the callback
#      parameter's function-value set is ambiguous and the singleton gate binds
#      nothing (a context-insensitive union cannot be soundly resolved);
#  (2) a single-callback helper whose callback sanitizes before the sink.
import os
import shlex

from flask import Flask, request

app = Flask(__name__)


def run_cmd(cmd):
    os.system(cmd)  # a sink, but never reached with taint under the gate


def log_it(msg):
    print(msg)  # benign


def apply(data, fn):
    fn(data)  # AMBIGUOUS: fn resolves to {run_cmd, log_it} -> no binding


@app.route("/a")
def handler_a():
    q = request.args.get("q")
    apply(q, run_cmd)  # suppressed: apply is multi-callback
    return "ok"


@app.route("/b")
def handler_b():
    apply("constant", log_it)  # the second callback that makes the set ambiguous
    return "ok"


def safe_run(cmd):
    os.system(shlex.quote(cmd))  # sanitized before the sink


def apply_one(data, fn):
    fn(data)


@app.route("/c")
def handler_c():
    q = request.args.get("q")
    apply_one(q, safe_run)  # single callback, but it sanitizes -> no finding
    return "ok"
