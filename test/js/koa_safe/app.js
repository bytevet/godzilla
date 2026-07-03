// Koa handler that reads untrusted input but uses it safely — a false-positive
// control. The analyzer must stay silent here.

const Koa = require("koa");
const Router = require("@koa/router");
const db = require("./db");

const app = new Koa();
const router = new Router();

router.get("/user", async (ctx) => {
  const id = ctx.query.id;
  // Safe: parameterized query — id is a bound "?" placeholder (arg 1), not part
  // of the SQL text (arg 0).
  const rows = await db.query("SELECT * FROM users WHERE id = ?", [id]);
  // ctx.body assignment is a store, not a response-write call sink.
  ctx.body = rows;
});

app.use(router.routes());
module.exports = app;
