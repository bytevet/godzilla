"""SQL injection through a ternary (IfExp): the untrusted value is one branch
of `raw if raw else "0"`, so taint must flow through the conditional expression.
"""
from flask import Flask, request

app = Flask(__name__)
_cursor = None


@app.route("/u")
def u():
    raw = request.args.get("id")
    uid = raw if raw else "0"  # ternary — result may be the tainted branch
    _cursor.execute("SELECT * FROM users WHERE id = " + uid)  # sink
    return "ok"
