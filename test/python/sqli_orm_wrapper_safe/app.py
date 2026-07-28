"""Control for sqli_orm_wrapper: the same ORM wrapper used correctly.

The query text is a constant with a bound placeholder and the untrusted value
travels in the params dict, so the SQL string never carries taint. Modeling
text() as a propagator must not make this fire -- the `#0` pin means only the
statement argument counts, not the bind values.
"""
from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)
session = None


@app.route("/user")
def get_user():
    name = request.args.get("name")
    session.execute(text("SELECT id FROM users WHERE name = :name"), {"name": name})
    return "ok"
