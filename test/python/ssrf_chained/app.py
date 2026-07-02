"""SSRF where the requests.get sink is the INNER call of a chained expression
(requests.get(url).json()). The chained .json() must not hide the inner
requests.get from the analysis — the taint reaches the outbound request URL.
"""
import requests

from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")     # source
    return str(requests.get(url).json())  # inner requests.get is the SSRF sink
