"""SQL injection where the untrusted value passes through an `or` default
(request.args.get("id") or "0"), an extremely common Python idiom. Taint must
flow through the BoolOp, or the injection is missed.
"""
from flask import Flask, request

app = Flask(__name__)
_cursor = None


@app.route("/u")
def u():
    uid = request.args.get("id") or "0"  # `or` default — result may be the tainted value
    _cursor.execute("SELECT * FROM users WHERE id = " + uid)  # sink
    return "ok"
