# FP guards for thread/async dispatch:
#  (1) the worker is dispatched with a CONSTANT argument (no taint);
#  (2) the worker parameterizes its query, so even a tainted argument is not a
#      SQL-injection sink (the bound-parameter form is safe).
import sqlite3
import threading

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("app.db")


def run_const(q):
    db.cursor().execute(q)  # sink, but only ever dispatched with a constant


def run_safe(ident):
    db.cursor().execute("SELECT * FROM t WHERE id = ?", (ident,))  # parameterized


@app.route("/const")
def via_const():
    threading.Thread(target=run_const, args=("SELECT 1",)).start()
    return "ok"


@app.route("/param")
def via_param():
    ident = request.args.get("id")
    threading.Thread(target=run_safe, args=(ident,)).start()  # tainted but safe sink
    return "ok"
