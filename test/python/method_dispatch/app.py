"""Cross-object method dispatch: untrusted input passed to a method on a NON-self
object flows into that class's method (resolved by CHA / OP_CODE_INVOKE) and on to
a shell sink. Before Python method-call resolution, taint dropped at `runner.go`.
"""
from flask import Flask, request
import subprocess

app = Flask(__name__)


class Runner:
    def go(self, cmd):
        subprocess.run(cmd, shell=True)  # command-injection sink


runner = Runner()


@app.route("/run")
def run():
    cmd = request.args.get("cmd")   # untrusted
    runner.go(cmd)                  # object-method call -> CHA -> Runner.go -> sink
    return "ok"
