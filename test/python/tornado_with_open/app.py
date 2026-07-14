"""Tornado handler path traversal through a `with open(...)` sink (the dominant
file-handling idiom). The route capture `path` is an untrusted method parameter;
it is joined onto a base dir and opened inside a `with` statement. Mirrors the
sink shape of Streamlit CVE-2022-35918."""
import os
import tornado.web

root = "/srv/static"


class FileHandler(tornado.web.RequestHandler):
    def get(self, path):
        with open(os.path.join(root, path), "rb") as f:  # path traversal (sink)
            data = f.read()
        self.write(data)
