"""SQL injection across methods of a class: the request handler reads the
untrusted id and passes it to a sibling method (self.query) that runs the query.
`self.method(x)` calls must resolve to the sibling method for taint to flow.
"""
from flask import request

_cursor = None


class UserService:
    def query(self, uid):
        _cursor.execute("SELECT * FROM users WHERE id = " + uid)  # sink

    def handle(self):
        uid = request.args.get("id")  # source
        self.query(uid)               # self.method() — cross-method call
        return "ok"
