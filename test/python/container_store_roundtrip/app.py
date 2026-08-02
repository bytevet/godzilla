"""Taint stored INTO a container and read back out again.

An element assigned into an empty dict, and a list literal indexed straight
back; both must keep the taint.
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
