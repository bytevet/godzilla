"""Chained string-method propagators must forward taint through the whole chain.
An untrusted handler param passes through `.strip().split()` (a call result is the
receiver of the next method) before reaching a shell sink. Before chained-receiver
capture, taint dropped at the second method in the chain.
"""
import subprocess
from fastapi import FastAPI

app = FastAPI()


@app.get("/run/{cmd}")
def run(cmd: str):
    part = cmd.strip().split(" ")[0]      # chained propagators: strip() -> split()
    subprocess.run(part, shell=True)      # command-injection sink
    return "ok"
