# Loop-CARRIED command injection (CWE-78). `cmd` is passed to os.system at the
# TOP of the while body — BEFORE it is reassigned from the tainted request
# parameter lower in the same body. On the first iteration cmd is the safe
# constant; only the loop's back-edge carries the tainted value from one
# iteration into the next, so the shell call is reachable-tainted ONLY because
# the loop carries cmd across iterations. The old single-block lowering
# flattened the body once, in source order, and saw only the safe constant at
# the sink (a false negative); the real CFG's header PHI (pre-loop value merged
# with the back-edge value) makes the tainted value reach the sink.
from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = "whoami"
    i = 0
    while i < 3:
        os.system(cmd)
        cmd = request.args.get("host")
        i += 1
    return "ok"
