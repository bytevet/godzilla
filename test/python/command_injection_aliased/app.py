# FE-2: aliased and from-imported sink modules must still match. Both handlers
# were false negatives before import-alias resolution.
import subprocess as sp
from os import system

from flask import Flask, request

app = Flask(__name__)


@app.route("/a")
def a():
    cmd = request.args.get("cmd")
    sp.call(cmd, shell=True)   # `import subprocess as sp`
    return "ok"


@app.route("/b")
def b():
    name = request.args.get("host")
    system("ping " + name)     # `from os import system`
    return "ok"
