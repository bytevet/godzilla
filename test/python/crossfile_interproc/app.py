"""Request handler whose untrusted input flows through a cross-file call.

The taint engine must follow `uid` from the request source, across the
`db.run(...)` call into db.py, and into the execute() sink there — proving
inter-procedural taint works across module (file) boundaries, not just within
one file.
"""
import db

from flask import Flask, request

app = Flask(__name__)


@app.route("/u")
def u():
    uid = request.args.get("id")                       # source
    db.run("SELECT * FROM users WHERE id = " + uid)    # cross-file call to the sink wrapper
    return "ok"
