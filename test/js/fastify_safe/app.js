// Fastify handler that reads untrusted input (request.query) but uses a
// parameterized query — a false-positive control for the widened
// `js:*request.*` request-source globs: the source is recognized, but the
// bound placeholder keeps the flow safe, so nothing must fire.

const fastify = require("fastify")();
const db = require("./db");

fastify.get("/user", async (request, reply) => {
  const id = request.query.id;
  // Safe: id is a bound "?" placeholder (arg 1), not part of the SQL text.
  const rows = await db.query("SELECT * FROM users WHERE id = ?", [id]);
  reply.send(rows);
});

module.exports = fastify;
