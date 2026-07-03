"""Safe SSRF sentinel: the untrusted value reaches only the PATH of a fixed host
(via f-string and concatenation), so the request cannot be redirected to an
attacker host. Must produce ZERO findings."""
from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    path = request.args.get("path")
    r1 = requests.get(f"https://api.internal.example.com/v1/{path}")
    r2 = requests.get("https://api.internal.example.com/items/" + path)
    return r1.text + r2.text
