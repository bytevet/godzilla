"""Flask handler with a classic string-formatting SQL injection.

GET /user?id=<id> reads an untrusted query parameter and splices it directly
into a SQL query string, then hands the query to a cursor. There is no
parameterization, so an attacker-controlled `id` can break out of the string
literal.
"""
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    id = request.args.get("id")
    query = "SELECT name FROM users WHERE id = '%s'" % id
    cursor.execute(query)
    return "ok"
