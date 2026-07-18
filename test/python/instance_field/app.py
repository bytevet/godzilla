"""Cross-method instance-field taint: one method stashes untrusted input into an
instance field (self.cmd), a SEPARATE method later reads self.cmd and passes it to
a shell sink. Before instance-field heap modeling, taint dropped between methods.
"""
from flask import Flask, request
import subprocess

app = Flask(__name__)


class Job:
    def load(self):
        self.cmd = request.args.get("cmd")   # untrusted, stashed on the instance

    def execute(self):
        subprocess.run(self.cmd, shell=True)  # command-injection sink


job = Job()


@app.route("/run")
def run():
    job.load()
    job.execute()
    return "ok"
