"""Taint stored INTO a container and read back out again.

`d[k] = tainted` followed by a read of the same container must keep the taint.
Both forms are exercised: an element assigned into an empty dict, and a list
literal indexed straight back. The empty-dict case is the reason the container
needs a register of its own -- a store whose destination is a constant has no
address register for the engine to mark.
"""
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/store")
def store():
    host = request.args.get("host")
    opts = {}
    opts["host"] = host
    os.system("ping " + opts["host"])
    return "ok"


@app.route("/index")
def index():
    host = request.args.get("host")
    hosts = [host]
    os.system("ping " + hosts[0])
    return "ok"
