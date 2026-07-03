"""FastAPI endpoints with SQL injection and command injection.

Untrusted input is read from the Starlette ``Request`` object
(``request.query_params``, ``await request.json()``) and formatted straight into
a raw SQL string and a shell command with no parameterization.
"""
import os


async def get_user(request):
    id = request.query_params["id"]
    query = "SELECT name FROM users WHERE id = '%s'" % id
    cursor.execute(query)  # noqa: F821 -- DB-API cursor (sink)
    return {"ok": True}


async def run_cmd(request):
    data = await request.json()
    os.system("echo %s" % data["cmd"])  # command injection (sink)
    return {"ok": True}
