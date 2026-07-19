# FP guards for higher-order-callback taint:
#  (1) the generic helper is called with TWO distinct resolvable callbacks, so the
#      callback parameter's function-value set is ambiguous and the singleton gate
#      binds nothing (a context-insensitive union cannot be soundly resolved);
#  (2) a single-callback helper whose callback sanitizes before the sink;
#  (3) the OPAQUE cross-context case: a helper receives a RESOLVABLE callback with
#      a clean argument at one site and an UNRESOLVABLE callback with a tainted
#      argument at another — binding the resolvable one to the other site's taint
#      would be an unsound cross-context pairing, so the opaque contribution
#      disables the singleton gate and nothing fires.
import os
import shlex

from flask import Flask, request

from thirdparty import get_handler  # unresolvable (unmodeled) callback source

app = Flask(__name__)


def run_cmd(cmd):
    os.system(cmd)  # a sink, but never reached with taint under the gate


def log_it(msg):
    print(msg)  # benign


def apply(data, fn):
    fn(data)  # AMBIGUOUS across sites -> no binding


@app.route("/a")
def handler_a():
    q = request.args.get("q")
    apply(q, run_cmd)  # suppressed: apply is multi-callback (run_cmd + log_it)
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


def dispatch(cb, x):
    cb(x)  # opaque channel: resolvable at /d, unresolvable at /e


@app.route("/d")
def handler_d():
    dispatch(run_cmd, "safe")  # resolvable callback, CLEAN argument
    return "ok"


@app.route("/e")
def handler_e():
    q = request.args.get("q")
    dispatch(get_handler(), q)  # UNRESOLVABLE callback, tainted arg -> opaque, no bind
    return "ok"
