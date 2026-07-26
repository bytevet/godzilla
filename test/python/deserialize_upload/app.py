"""Flask endpoint with an insecure-deserialization RCE via file upload.

An uploaded file's bytes are read and handed straight to pickle.loads, so an
attacker who uploads a crafted pickle achieves arbitrary code execution. The
untrusted bytes enter through request.files (a modeled upload source) and reach
the sink across the .read() hop (a rule-scoped propagator).
"""
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_model():
    payload = request.files["model"].read()
    obj = pickle.loads(payload)
    return repr(obj)
