import os

from flask import request


def run_chosen():
    prog = request.args.get("p")
    os.execv(prog, ["x"])


def spawn_chosen():
    prog = request.args.get("p")
    os.spawnl(os.P_WAIT, prog, "x")


# A fixed program with a tainted argv element: the attacker supplies data, not
# the binary, so this must stay clean.
def fixed_program():
    os.execv("/bin/ls", [request.args.get("a")])
