"""Sink wrapper in a separate module from the request handler."""
_cursor = None


def run(q):                # q is tainted by the caller in app.py
    _cursor.execute(q)     # SQL sink lives in a DIFFERENT file
