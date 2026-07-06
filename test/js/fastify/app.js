// Fastify handlers: untrusted request input reaches a SQL query and a shell
// command with no sanitization. Fastify (and Hapi) expose the request as a
// `request` handler parameter — an opaque base — so request.query / request.body
// are matched by the base-scoped `js:*request.*` source globs (PR3).

const fastify = require("fastify")();
const child_process = require("child_process");
const db = require("./db");

fastify.get("/user", async (request, reply) => {
  const id = request.query.id;
  const rows = await db.query("SELECT * FROM users WHERE id = " + id);
  reply.send(rows);
});

fastify.post("/ping", async (request, reply) => {
  const host = request.body.host;
  child_process.exec("ping -c1 " + host);
  reply.send("ok");
});

module.exports = fastify;
