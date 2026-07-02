import json

from flask import Flask, request

app = Flask(__name__)


@app.route("/load")
def load():
    blob = request.get_data()  # untrusted request body (source)
    obj = json.loads(blob)     # safe: JSON has no code-execution semantics
    return str(obj)
