"""DRF view that reads request.data but hands it to a parameterized DB-API
query -- a false-positive control for the widened ``py:*request.data*`` source
globs: the source is recognized, but the bound placeholder keeps the flow safe,
so nothing must fire.
"""


def create_user(request):
    name = request.data["name"]
    # Safe: %s here is a DB-API bind parameter (2nd arg), not string-formatted
    # SQL text -- the value cannot break out of the query structure.
    cursor.execute("INSERT INTO users (name) VALUES (%s)", [name])  # noqa: F821
    return {"ok": True}
