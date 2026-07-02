"""SQL injection where the untrusted value is obtained by tuple unpacking from a
tainted iterable (a, b = request.get_json()). Each unpacked name inherits the
iterable's taint (element taint == container taint).
"""
from flask import Flask, request

app = Flask(__name__)
_cursor = None


@app.route("/u", methods=["POST"])
def u():
    a, b = request.get_json()  # unpack from an untrusted JSON array (source)
    _cursor.execute("SELECT * FROM users WHERE id = " + a)  # sink
    return "ok"
