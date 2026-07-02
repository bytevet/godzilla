// SQL injection where the untrusted value is obtained by object destructuring
// (const { id } = req.query) — the dominant modern Express idiom. Taint must
// flow from req.query through the destructured binding into the query.
var express = require("express");
var db = require("some-db");
var app = express();

app.get("/u", function (req, res) {
  var { id } = req.query; // destructure from an untrusted source
  res.send(db.query("SELECT * FROM users WHERE id = " + id)); // sink
});

module.exports = app;
