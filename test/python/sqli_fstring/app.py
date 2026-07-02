"""SQL injection built with an f-string (the dominant Python idiom) rather
than "+" concatenation. Taint must propagate through the `{uid}` interpolation
into the execute() sink, or every f-string injection is missed.
"""
from flask import Flask, request

app = Flask(__name__)
_cursor = None


@app.route("/u")
def u():
    uid = request.args.get("id")
    _cursor.execute(f"SELECT name FROM users WHERE id = {uid}")  # f-string into sink
    return "ok"
