"""FastAPI route with a path traversal vulnerability (Gradio CVE-2023-51449
shape).

The route-decorated handler receives the URL path segment ``name`` as a
FUNCTION PARAMETER (not a ``request.X`` accessor call). It is untrusted and is
joined onto a base directory with ``os.path.join`` -- which does NOT contain
``..`` sequences -- and passed straight to ``open()``, so an attacker can
escape ``base`` and read arbitrary files (e.g. name=../../etc/passwd).
"""
import os

from fastapi import FastAPI

app = FastAPI()

base = "/srv/data"


@app.get("/file/{name}")
def read_file(name: str):
    path = os.path.join(base, name)
    f = open(path)  # path traversal (sink)
    data = f.read()
    f.close()
    return data
