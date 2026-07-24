"""Flow-sensitive FP guard (ENG-9), intra-procedural dominator case — proves the
dominator-based guard analysis (internal/analysis/guards.go) now engages for the
Python frontend's real CFG (Phase 4). The untrusted `next` target is checked with
is_safe_url on an IF whose TRUE branch DOMINATES the redirect sink, so the redirect
is reached only after the value was validated. A flow-insensitive engine would
flag it; with the real CFG + dominators it is correctly suppressed.
"""
from flask import Flask, request, redirect
from myapp.security import is_safe_url

app = Flask(__name__)


@app.route("/go")
def go():
    nxt = request.args.get("next")
    if is_safe_url(nxt):
        return redirect(nxt)   # sink dominated by the validated (true) branch
    return redirect("/home")   # constant target, not tainted
