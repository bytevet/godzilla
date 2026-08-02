"""An argv list is NOT safe once a shell is involved.

Guards the `argvList()` suppression from over-reaching: with shell=True the list
is joined into a single string and handed to /bin/sh, so the untrusted element is
shell-interpreted after all. The sibling sentinel subprocess_argv_safe covers the
same call WITHOUT shell, which must stay silent.
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ls")
def ls():
    name = request.args.get("name")
    subprocess.run(["ls", "-la", name], shell=True)  # shell: the list is joined
    return "ok"
