"""SSRF where the request accessor is reached through a LOCAL ALIAS, not inline
(the exact shape of CVE-2025-52967 in mlflow's gateway_proxy_handler):

    args = request.args if request.method == "GET" else request.json
    gateway_path = args.get("gateway_path")

`args` aliases a request sub-object, so `args.get(...)` is the untrusted
`request.args.get` source. The path is appended to a NON-constant base URL, so
the SSRF host-fixed suppression must not fire. URL is arg #1 of requests.request.
"""
from flask import Flask, request
import os
import requests

app = Flask(__name__)


@app.route("/gateway/proxy", methods=["GET", "POST"])
def gateway_proxy():
    args = request.args if request.method == "GET" else request.json
    gateway_path = args.get("gateway_path")             # untrusted, via alias
    target_uri = os.environ.get("TARGET_URI")           # non-constant base
    resp = requests.request("GET", f"{target_uri}/{gateway_path}")  # SSRF sink (arg #1)
    return resp.text
