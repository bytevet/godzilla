"""FP guard for chained method propagators: the same `.strip().split()` chain on a
CONSTANT string carries no taint, so the sink must not fire — capturing the chained
receiver must not invent taint where the root value is untainted.
"""
import subprocess
from fastapi import FastAPI

app = FastAPI()


@app.get("/run/{cmd}")
def run(cmd: str):
    _ = cmd                               # param untrusted, but unused at the sink
    part = "ls -la".strip().split(" ")[0]  # chained methods on a constant
    subprocess.run(part, shell=True)      # constant argument, not tainted
    return "ok"
