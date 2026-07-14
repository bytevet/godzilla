"""Tornado RequestHandler with a path traversal vulnerability (Streamlit
CVE-2022-35918 shape).

The ``get`` handler receives the URL route capture ``path`` as a positional
method PARAMETER (not a ``request.X`` accessor call). It is untrusted and is
joined onto a base directory with ``os.path.join`` -- which does NOT contain
``..`` sequences -- and passed straight to ``open()``, so an attacker can
escape ``root`` and read arbitrary files (e.g. path=../../etc/passwd).
"""
import os

import tornado.web

root = "/srv/static"


class FileHandler(tornado.web.RequestHandler):
    def get(self, path):
        full = os.path.join(root, path)
        f = open(full)  # path traversal (sink)
        data = f.read()
        f.close()
        self.write(data)
