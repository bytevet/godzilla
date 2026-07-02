import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/load")
def load():
    blob = request.get_data()  # untrusted request body (source)
    obj = pickle.loads(blob)   # insecure deserialization -> RCE (sink)
    return str(obj)
