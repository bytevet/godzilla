"""SQL injection through SQLAlchemy's raw-SQL wrapper.

`text(sql)` does not execute anything: it returns a TextClause carrying the
string verbatim, which `session.execute()` then runs unparameterized. The
wrapper is therefore a propagator, not a sink -- without it modeled, taint dies
inside the call and the execute sink sees a clean argument, which is why
ORM-backed apps reported no SQL injection at all.
"""
from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)
session = None


@app.route("/user")
def get_user():
    name = request.args.get("name")
    session.execute(text("SELECT id FROM users WHERE name = '" + name + "'"))
    return "ok"
