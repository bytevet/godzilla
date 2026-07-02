"""SQL injection where the execute() sink is evaluated INSIDE a list
comprehension, once per untrusted element. The comprehension's element
expression and iterable must be lowered (and the loop target must inherit the
iterable's taint) for the sink to be flagged.
"""
from flask import Flask, request

app = Flask(__name__)
_cursor = None


@app.route("/u", methods=["POST"])
def u():
    ids = request.get_json()  # untrusted JSON array (source)
    # execute() runs for each element inside the comprehension:
    [_cursor.execute("SELECT * FROM users WHERE id = " + x) for x in ids]
    return "ok"
