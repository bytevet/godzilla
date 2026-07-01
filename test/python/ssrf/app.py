"""Flask handler with a server-side request forgery (SSRF) vulnerability.

GET /fetch?url=<url> reads an untrusted query parameter and passes it
directly as the destination of an outbound HTTP request, so an
attacker-controlled `url` can make the server issue requests to internal or
unintended hosts (e.g. url=http://169.254.169.254/latest/meta-data/).
"""
from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    resp = requests.get(url)
    return resp.text
