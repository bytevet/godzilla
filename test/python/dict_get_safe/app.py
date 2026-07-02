"""False-positive sentinel: looking up a dict with an untrusted key is benign —
not SSRF, not injection. This ubiquitous pattern must produce ZERO findings, so
an over-broad sink (e.g. a bare "py:*.get") that collides with dict.get would
fail this test.
"""
from flask import Flask, request

app = Flask(__name__)
_config = {"a": 1, "b": 2}


@app.route("/cfg")
def cfg():
    key = request.args.get("key")   # untrusted key
    return str(_config.get(key))    # benign dict lookup
