"""Precision control for redirect_guarded_safe: SAME validator (is_safe_url) on
the SAME untrusted value, but the check is on a branch that does NOT dominate the
sink — the redirect is after the if/merge and is reached whether or not the check
passed (the boolean result is ignored). So the taint still reaches the sink and
the finding MUST still fire. This proves the dominator suppression is precise
(tied to dominance), not a blanket "a validator was called somewhere" mute.
"""
from flask import Flask, request, redirect
from myapp.security import is_safe_url

app = Flask(__name__)


@app.route("/go")
def go():
    nxt = request.args.get("next")
    if is_safe_url(nxt):
        print("target looked safe")   # result ignored; branch does not gate the sink
    return redirect(nxt)              # post-merge: neither branch dominates -> fires
