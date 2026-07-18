"""FP guard for cross-object method dispatch: a CONSTANT command passed to the
same Runner.go method must not fire — the CHA edge exists but no taint flows.
"""
from flask import Flask, request
import subprocess

app = Flask(__name__)


class Runner:
    def go(self, cmd):
        subprocess.run(cmd, shell=True)


runner = Runner()


@app.route("/safe")
def safe():
    _ = request.args.get("ignored")
    runner.go("ls -la")   # constant argument, not tainted
    return "ok"
