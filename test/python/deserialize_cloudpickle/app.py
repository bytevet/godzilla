"""Flask endpoint deserializing an untrusted request body with cloudpickle.

cloudpickle.loads has the same arbitrary-code-execution risk as pickle.loads;
here the raw request body flows directly into it, so a crafted body is RCE.
Exercises the cloudpickle sink added to the deserialization rule.
"""
import cloudpickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/task", methods=["POST"])
def run_task():
    data = request.get_data()
    fn = cloudpickle.loads(data)
    return repr(fn)
