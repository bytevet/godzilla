// Safe: a PARAMETERIZED query. The untrusted id is passed as a bound parameter
// (the [id] array, argument 1), not concatenated into the query string
// (argument 0), so this is not SQL injection. js-sqli pins the injection point
// to arg 0 (#0), so this must produce ZERO findings — the false-positive guard
// for parameterized JS queries.
var express = require("express");
var db = require("some-db");
var app = express();

app.get("/u", function (req, res) {
  var { id } = req.query;
  res.send(db.query("SELECT * FROM users WHERE id = ?", [id])); // bound param: safe
});

module.exports = app;
