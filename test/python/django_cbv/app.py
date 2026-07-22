"""Django class-based view with SQL injection via a URL capture.

The URL conf maps ``path("user/<str:username>/", UserView.as_view())``, so the
``username`` capture arrives as a verb-method parameter after ``(self, request)``
-- untrusted route input. It is formatted straight into a raw SQL string with no
parameterization, so an attacker-controlled ``username`` injects arbitrary SQL.
"""
from django.views import View


class UserView(View):
    def get(self, request, username):
        query = "SELECT id, email FROM users WHERE name = '%s'" % username
        cursor.execute(query)  # noqa: F821 -- DB-API cursor (sink)
        return "ok"
