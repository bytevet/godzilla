"""Flask handler with a parameterized SQL query.

GET /user?id=<id> reads an untrusted query parameter, but hands it to the
cursor as a bound placeholder parameter (pyodbc's execute(sql, *parameters)
form) rather than splicing it into the query text, so the value can never
break out of the query structure. This must produce ZERO findings.
"""
from flask import Flask, request
import pyodbc

app = Flask(__name__)
conn = pyodbc.connect("DSN=mydb")


@app.route("/user")
def get_user():
    id = request.args.get("id")
    cursor = conn.cursor()
    query = "SELECT name FROM users WHERE id = ?"
    cursor.execute(query, id)
    return "ok"
