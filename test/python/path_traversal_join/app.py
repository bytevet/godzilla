"""Path traversal where the untrusted filename reaches the sink THROUGH a
propagator (os.path.join), not by direct use.

os.path.join("/var/data", "../../etc/passwd") -> "/var/data/../../etc/passwd",
which still escapes the intended directory, so os.path.join must propagate
taint (it is a propagator, not a sanitizer). This exercises the propagator
edge of py-path-traversal that the direct-use sample does not.
"""
import os

from flask import Flask, request

app = Flask(__name__)

BASE_DIR = "/var/data"


@app.route("/read")
def read_file():
    filename = request.args.get("filename")   # untrusted (source)
    path = os.path.join(BASE_DIR, filename)    # taint flows through propagator
    f = open(path)                             # sink
    data = f.read()
    f.close()
    return data
