"""FastAPI safe sample -- guards against over-tainting handler parameters.

Three shapes that must NOT produce a finding:

  1. `echo`      -- a route param that is untrusted but only echoed back in a
                    JSON response, never used as a filesystem path.
  2. `load_local`-- a PLAIN (non-route) function whose parameter has the same
                    name as a handler param and DOES reach open(); because it is
                    not a route handler its param must not be treated as a source
                    (it is only ever called with a constant).
  3. `read_cfg`  -- a route whose dangerous argument is a Depends()-injected
                    dependency, not raw request input, so it must be excluded
                    from the taint sources even though it reaches open().
"""
import os

from fastapi import Depends, FastAPI

app = FastAPI()

base = "/srv/data"


@app.get("/echo/{name}")
def echo(name: str):
    # Untrusted, but only reflected into a JSON response -> not path traversal.
    return {"name": name}


def load_local(name):
    # NOT a route handler: `name` is an ordinary parameter, not a taint source,
    # even though it flows into open(). Called only with a constant below.
    path = os.path.join(base, name)
    f = open(path)
    data = f.read()
    f.close()
    return data


CONFIG = load_local("config.txt")


def get_config_path():
    return os.path.join(base, "settings.ini")


@app.get("/cfg/{name}")
def read_cfg(name: str, cfgfile=Depends(get_config_path)):
    # cfgfile is dependency-injected (Depends), not untrusted, so reading it is
    # safe; `name` is untrusted but unused as a path.
    f = open(cfgfile)
    data = f.read()
    f.close()
    return {"name": name, "data": data}
