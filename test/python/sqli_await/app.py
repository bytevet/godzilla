"""SQL injection in an async handler where the untrusted value is obtained via
`await`. `await` is transparent for taint (it yields the coroutine's resolved
value), so taint must flow through it into the query.
"""
from flask import Flask, request

app = Flask(__name__)
_cursor = None


async def fetch_id():
    return request.args.get("id")  # untrusted (source)


@app.route("/u")
async def u():
    uid = await fetch_id()  # await of a tainted coroutine result
    _cursor.execute("SELECT * FROM users WHERE id = " + uid)  # sink
    return "ok"
