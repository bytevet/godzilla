// Express + Knex: parameterized raw query (safe twin of sqli_knex_raw).
//
// The untrusted `id` is passed as a positional bind parameter (arg 1), not
// concatenated into the SQL text (arg 0). Knex substitutes `?` with a properly
// escaped parameter, so there is no injection. The js-sqli sink is pinned to
// logical arg 0, so this parameterized call does not fire.

var express = require("express");
var knex = require("knex")({ client: "pg" });
var app = express();

function handleUser(req, res) {
  var id = req.query.id;
  knex.raw("SELECT * FROM users WHERE id = ?", [id]).then(function (rows) {
    res.send(rows);
  });
}

app.get("/user", handleUser);

module.exports = app;
