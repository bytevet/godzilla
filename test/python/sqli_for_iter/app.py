"""SQL injection where the loop variable is bound by iterating an untrusted
iterable (a JSON array from the request body). Taint on the iterable must reach
the loop variable (element taint == container taint) for the per-iteration sink
to be flagged.
"""
from flask import Flask, request

app = Flask(__name__)
_cursor = None


@app.route("/u", methods=["POST"])
def u():
    ids = request.get_json()  # untrusted JSON array (source)
    for uid in ids:           # iterate tainted iterable -> loop var tainted
        _cursor.execute("SELECT * FROM users WHERE id = " + uid)  # sink
    return "ok"
