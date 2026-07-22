"""Django class-based view, parameterized query (safe twin of django_cbv).

The same ``username`` URL capture reaches the DB, but as a bound placeholder
parameter (arg 1), not concatenated into the query text (arg 0). The py-sql-
injection sink is pinned to logical arg 0, so this parameterized call does not
fire -- a true negative that keeps the Django-CBV source from over-reporting.
"""
from django.views import View


class UserView(View):
    def get(self, request, username):
        cursor.execute(  # noqa: F821 -- DB-API cursor (parameterized, safe)
            "SELECT id, email FROM users WHERE name = %s", [username]
        )
        return "ok"
