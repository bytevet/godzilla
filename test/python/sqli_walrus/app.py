"""SQL injection where the untrusted value is captured by a walrus (:=) in an
if condition. The condition expression must be lowered (and the walrus binding
must carry taint) for the sink in the body to be flagged.
"""
from flask import Flask, request

app = Flask(__name__)
_cursor = None


@app.route("/u")
def u():
    if uid := request.args.get("id"):  # walrus in condition
        _cursor.execute("SELECT * FROM users WHERE id = " + uid)  # sink
    return "ok"
