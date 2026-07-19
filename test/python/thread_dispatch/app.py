# ENG: thread/process dispatch taint. Untrusted input is handed to a worker the
# runtime invokes later — threading.Thread(target=..., args=(...)) and
# multiprocessing.Process(target=..., args=(...)). The frontend rewrites the
# dispatch to a deferred call so taint flows into the worker's parameters and
# reaches the sink there. (Recognition is scoped to the distinctive
# Thread/Process target=/args= keyword shape; Executor.submit is a follow-up.)
import multiprocessing
import sqlite3
import threading

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("app.db")


def run_thread(q):
    db.cursor().execute(q)  # SQL-injection sink reached via a Thread worker


def run_proc(q):
    db.cursor().execute(q)  # SQL-injection sink reached via a Process worker


@app.route("/thread")
def via_thread():
    ident = request.args.get("id")
    threading.Thread(target=run_thread, args=(ident,)).start()
    return "ok"


@app.route("/process")
def via_process():
    ident = request.args.get("id")
    multiprocessing.Process(target=run_proc, args=(ident,)).start()
    return "ok"
