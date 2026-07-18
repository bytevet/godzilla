"""FP guard for the interprocedural validator (ENG-9, linear case): a helper that
checks the target with Django's url_has_allowed_host_and_scheme and returns "" when
it fails is NOT taint-returning, so a redirect to its result is not an open redirect.
Mirrors the ubiquitous get_valid_next_url_from_request idiom (e.g. wagtail).
"""
from flask import Flask, request, redirect
from django.utils.http import url_has_allowed_host_and_scheme

app = Flask(__name__)


def valid_next(req):
    nxt = req.args.get("next")
    if not nxt or not url_has_allowed_host_and_scheme(url=nxt, allowed_hosts={"self"}):
        return ""
    return nxt


@app.route("/go")
def go():
    return redirect(valid_next(request))   # target validated -> not an open redirect
