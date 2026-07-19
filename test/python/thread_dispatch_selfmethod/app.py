# ENG (regression): a Thread whose target is a bound method — target=self.run —
# must forward the receiver as param 0 so the tuple args line up with params
# 1..n. A benign hardcoded field read off the receiver must NOT be tainted; the
# real tainted worker argument MUST reach the sink.
import os
import threading

from flask import Flask, request

app = Flask(__name__)


class Worker:
    def __init__(self):
        self.base = "constant"

    def run(self, data):
        os.system(self.base)  # receiver field, hardcoded -> must NOT fire
        os.system(data)       # the forwarded worker argument -> MUST fire

    def handle(self, ident):
        threading.Thread(target=self.run, args=(ident,)).start()


w = Worker()


@app.route("/x")
def route():
    return w.handle(request.args.get("id"))
