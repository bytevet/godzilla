"""SSRF through requests.request(method, url, ...) — the generic verb-dispatching
call (the shape of CVE-2025-52967 in mlflow's gateway_proxy_handler).

An untrusted query parameter is concatenated onto a NON-constant base URL (read
from the environment), so the attacker controls a path segment appended to a
host that is not provable at analysis time. Because the host prefix is not a
constant, the SSRF host-fixed suppression must NOT fire and the finding stands.
The URL is the SECOND argument to requests.request (arg #0 is the HTTP method).
"""
from flask import Flask, request
import os
import requests

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    gateway_path = request.args.get("gateway_path")     # untrusted (source)
    target_uri = os.environ.get("TARGET_URI")           # non-constant base
    resp = requests.request("GET", f"{target_uri}/{gateway_path}", json=None)  # SSRF sink (arg #1)
    return resp.text
