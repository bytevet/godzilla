"""Django views with SQL injection and command injection.

Django exposes untrusted request data via ``request.GET`` / ``request.POST``.
Here the values are formatted straight into a raw SQL string and a shell command
with no parameterization or validation.
"""
import os


def get_user(request):
    id = request.GET["id"]
    query = "SELECT name FROM users WHERE id = '%s'" % id
    cursor.execute(query)  # noqa: F821 -- DB-API cursor (sink)
    return "ok"


def run_ping(request):
    host = request.POST.get("host")
    os.system("ping -c1 %s" % host)  # command injection (sink)
    return "ok"
