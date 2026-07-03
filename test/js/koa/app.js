// Koa handlers with SQL injection and command injection.
//
// Untrusted input is read from Koa's context (ctx.query, ctx.request.body) and
// concatenated into a database query and a shell command with no sanitization.

const Koa = require("koa");
const Router = require("@koa/router");
const child_process = require("child_process");
const db = require("./db");

const app = new Koa();
const router = new Router();

router.get("/user", async (ctx) => {
  const id = ctx.query.id;
  const sql = "SELECT * FROM users WHERE id = " + id;
  const rows = await db.query(sql);
  ctx.body = rows;
});

router.post("/ping", async (ctx) => {
  const host = ctx.request.body.host;
  child_process.exec("ping -c1 " + host);
  ctx.body = "ok";
});

app.use(router.routes());
module.exports = app;
