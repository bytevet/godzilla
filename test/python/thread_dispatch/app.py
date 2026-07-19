# ENG: thread/async dispatch taint. Untrusted input is handed to a worker the
# runtime invokes later — threading.Thread(target=..., args=(...)) and
# Executor.submit(...). The frontend rewrites the dispatch to a deferred call so
# taint flows into the worker's parameters and reaches the sink there.
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("app.db")
pool = ThreadPoolExecutor()


def run_query(q):
    db.cursor().execute(q)  # SQL-injection sink inside the worker


@app.route("/thread")
def via_thread():
    ident = request.args.get("id")
    t = threading.Thread(target=run_query, args=(ident,))
    t.start()
    return "ok"


@app.route("/submit")
def via_submit():
    ident = request.args.get("id")
    pool.submit(run_query, ident)  # executor dispatch
    return "ok"
