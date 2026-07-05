"""Untrusted value from a request HEADER reaches os.system (COV-6)."""
from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.headers.get("X-Run")  # untrusted header
    os.system(cmd)                      # sink
    return "ok"
