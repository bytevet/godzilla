"""Scanned from a root ABOVE the package, which is the ordinary `src/` layout.

The import path is shorter than the module's scan-root-relative path, so
resolving a cross-module call has to match the callee against a SUFFIX of the
function's logical path. Matching full paths only, the call never links and the
taint stops here — silently, and only for some scan roots."""
from flask import request

from pkg.net.client import fetch


def handler():
    url = request.args.get("u")
    return fetch(url)
