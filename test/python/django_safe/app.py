"""Django views that read untrusted input but use it safely — a false-positive
control. The analyzer must stay silent here.
"""


def get_user(request):
    id = request.GET["id"]
    # Safe: parameterized query. ``id`` is a bound placeholder value, not part
    # of the SQL text (execute's logical arg 0 is the constant query string).
    cursor.execute("SELECT name FROM users WHERE id = %s", [id])  # noqa: F821
    return "ok"


def list_users(request):
    q = request.GET.get("q")
    # Safe: the Django ORM builds a parameterized query; .filter is not a raw
    # SQL sink.
    return User.objects.filter(name=q)  # noqa: F821
