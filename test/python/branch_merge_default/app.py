# FE-5: the "default if empty" pattern must not drop taint. Before branch-merge
# PHI flattening, the reassignment inside the `if` killed the tainted binding on
# the merge path (a false negative). Now both incoming values are PHI-merged, so
# the tainted branch keeps the flow live into the sink.
from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    if not host:
        host = "localhost"
    os.system("ping -c 1 " + host)
    return "ok"
