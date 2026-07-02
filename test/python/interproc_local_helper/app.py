"""Inter-procedural taint through a bare-named local helper.

The untrusted id enters build_query() (arg -> param), which returns a string
containing it (return-taint), and that result reaches the execute() sink. The
helper is invoked by a bare name (build_query(...)), not a module-qualified one
— the case whose callee ("py:<module>.build_query") must match the function's
CanonicalName for taint to flow through the local helper at all.
"""
from flask import Flask, request

app = Flask(__name__)
_cursor = None


def build_query(uid):
    return "SELECT * FROM users WHERE id = " + uid  # returns tainted string


@app.route("/u")
def u():
    uid = request.args.get("id")  # source
    q = build_query(uid)          # bare local call: arg -> param, then return-taint
    _cursor.execute(q)            # sink
    return "ok"
