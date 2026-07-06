"""Django REST Framework view with SQL and command injection via request.data.

DRF parses the request body into ``request.data`` (a dict-like), so reading a
value from it is untrusted input. Here it is formatted straight into a raw SQL
string and a shell command with no parameterization -- matched by the widened
``py:*request.data*`` request-source globs (PR3).
"""
import os


def create_user(request):
    name = request.data["name"]
    query = "INSERT INTO users (name) VALUES ('%s')" % name
    cursor.execute(query)  # noqa: F821 -- DB-API cursor (sink)
    return {"ok": True}


def run_task(request):
    cmd = request.data.get("cmd")
    os.system("run %s" % cmd)  # command injection (sink)
    return {"ok": True}
