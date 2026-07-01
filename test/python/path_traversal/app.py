"""Flask handlers with a classic path traversal vulnerability.

GET /read?filename=<filename> and GET /download?filename=<filename> read an
untrusted query parameter and pass it straight to open()/send_file() without
normalizing or containing ".." sequences, so an attacker-controlled
`filename` can escape the intended directory and read arbitrary files on the
server (e.g. filename=../../etc/passwd).

Note: the file is opened without a `with` block on purpose -- pyast.py (the
embedded AST-to-JSON helper) does not currently capture a `with` statement's
context-manager expression, only its body, so `with open(x) as f: ...` would
silently drop the open() call from the converted IR.
"""
from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/read")
def read_file():
    filename = request.args.get("filename")
    f = open(filename)
    data = f.read()
    f.close()
    return data


@app.route("/download")
def download():
    filename = request.args["filename"]
    return send_file(filename)
