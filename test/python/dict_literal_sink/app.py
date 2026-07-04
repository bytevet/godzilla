# FE-7: a source/sink inside a dict (or set) literal must be lowered and fire.
# Previously ast.Dict lowered to py.unsupported, dropping the inner call.
from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/x")
def x():
    payload = {"out": os.system("ping " + request.args.get("host"))}
    return payload
