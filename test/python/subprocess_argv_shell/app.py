"""An argv list is NOT safe once a shell is involved.

With shell=True the list is joined into one string and handed to /bin/sh.
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ls")
def ls():
    name = request.args.get("name")
    subprocess.run(["ls", "-la", name], shell=True)  # shell: the list is joined
    return "ok"
