// SQL injection built with a TEMPLATE LITERAL (the modern JS idiom) rather
// than "+" concatenation. Taint must propagate through the interpolation
// `${uid}` into the query sink, or every template-literal injection is missed.
var express = require("express");
var db = require("some-db");
var app = express();

app.get("/u", function (req, res) {
  var uid = req.query.id;
  var q = `SELECT name FROM users WHERE id = ${uid}`;
  res.send(db.query(q));
});

module.exports = app;
