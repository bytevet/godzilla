"""Flask ``@app.route`` handler with a path-traversal vulnerability.

Unlike ``@app.get``/``@router.get``, the method-agnostic ``@app.route``
decorator is the dominant Flask/Bottle/Sanic registration form. Its URL
capture (``<path:fname>``) is delivered to the handler as a FUNCTION
PARAMETER, which is untrusted: it is concatenated onto a base directory and
passed straight to ``open()``, so an attacker can escape ``base`` and read
arbitrary files (e.g. fname=../../etc/passwd).
"""
from flask import Flask

app = Flask(__name__)


@app.route("/files/<path:fname>")
def read_file(fname):
    f = open("/srv/files/" + fname)  # path traversal (sink)
    data = f.read()
    f.close()
    return data
