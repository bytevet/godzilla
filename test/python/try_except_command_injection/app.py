# Command injection whose taint crosses an exception edge (CWE-78). The
# untrusted request parameter is read in the `try` body; the sink runs in the
# `except` handler. In the real CFG the handler block has the try-body block as
# a predecessor (the conservative exception edge), so the value assigned in the
# try body reaches the handler and os.system() fires. A CFG that dropped the
# exception edge would leave `host` undefined in the handler (a false negative).
from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    try:
        host = request.args.get("host")
        raise RuntimeError("boom")
    except Exception:
        os.system("ping -c 1 " + host)
    return "ok"
