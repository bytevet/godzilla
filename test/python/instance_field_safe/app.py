"""FP guard for instance-field heap: a DIFFERENT, untainted field (self.other) is
read into the sink, while the tainted field (self.cmd) never reaches it. The
per-field key must keep self.other clean even though self.cmd is tainted.
"""
from flask import Flask, request
import subprocess

app = Flask(__name__)


class Job:
    def load(self):
        self.cmd = request.args.get("cmd")   # tainted, but never used at a sink
        self.other = "ls -la"                # constant

    def execute(self):
        subprocess.run(self.other, shell=True)  # reads the CLEAN field only


job = Job()


@app.route("/run")
def run():
    job.load()
    job.execute()
    return "ok"
