"""Taint whose ONLY route to the sink is a keyword argument."""
import subprocess

from flask import request


def keyword_only():
    subprocess.run(args=request.args.get("cmd"), shell=True)


# Passed through a **splat: the keyword the author wrote is still the route.
def splat():
    opts = {"args": request.args.get("cmd"), "shell": True}
    subprocess.run(**opts)
