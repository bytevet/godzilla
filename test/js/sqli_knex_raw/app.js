// Express + Knex: SQL injection through a raw query fragment.
//
// GET /user?id=<id> reads an untrusted query parameter and concatenates it
// directly into knex.raw(), so the whole WHERE clause is attacker-controlled.
// Knex's raw() is the ORM's escape hatch; unlike a parameterized `?` binding it
// does no quoting, so this is a classic CWE-89.

var express = require("express");
var knex = require("knex")({ client: "pg" });
var app = express();

function handleUser(req, res) {
  var id = req.query.id;
  knex.raw("SELECT * FROM users WHERE id = " + id).then(function (rows) {
    res.send(rows);
  });
}

app.get("/user", handleUser);

module.exports = app;
