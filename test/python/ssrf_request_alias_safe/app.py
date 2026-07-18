"""FP guard for the request-attribute alias: a variable first bound to
`request.args` but then REBOUND to a safe local dict must not keep the request
alias, so `cfg.get(...)` after the rebind is not an untrusted source and no SSRF
is reported.
"""
from flask import Flask, request
import os
import requests

app = Flask(__name__)


@app.route("/proxy_safe")
def proxy_safe():
    cfg = request.args            # aliases request.args ...
    cfg = {"gateway_path": "health"}  # ... but is rebound to a safe constant dict
    gateway_path = cfg.get("gateway_path")              # NOT untrusted anymore
    target_uri = os.environ.get("TARGET_URI")
    resp = requests.request("GET", f"{target_uri}/{gateway_path}")  # no finding
    return resp.text
