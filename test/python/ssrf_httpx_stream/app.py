"""SSRF through httpx's streaming client API — client.stream("GET", url, ...)
(the sink shape of CVE-2024-48052 in gradio's save_url_to_cache).

An untrusted query parameter is used directly as the URL of an outbound httpx
streaming request that follows redirects, so an attacker can point the server at
internal or unintended hosts. The URL is the SECOND argument to .stream (arg #0
is the HTTP method), so the sink pins arg #1.
"""
from flask import Flask, request
import httpx

app = Flask(__name__)
client = httpx.Client()


@app.route("/download")
def download():
    url = request.args.get("url")                       # untrusted (source)
    with client.stream("GET", url, follow_redirects=True) as r:  # SSRF sink (arg #1)
        return b"".join(r.iter_raw())
