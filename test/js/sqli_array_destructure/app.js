// SQL injection where the untrusted value is obtained by array destructuring
// (const [id] = req.query.ids). Each destructured element inherits the
// initializer's taint (element taint == container taint).
var express = require("express");
var db = require("some-db");
var app = express();

app.get("/u", function (req, res) {
  var [id] = req.query.ids; // array destructuring from an untrusted source
  res.send(db.query("SELECT * FROM users WHERE id = " + id)); // sink
});

module.exports = app;
