// SQL injection where the untrusted value is read via optional chaining
// (req.body?.user?.name), ubiquitous in modern JS/TS. `?.` only short-circuits
// on null/undefined; taint must flow through it as through a normal member read.
var express = require("express");
var db = require("some-db");
var app = express();

app.post("/u", function (req, res) {
  var name = req.body?.user?.name; // optional chaining off an untrusted source
  res.send(db.query("SELECT * FROM users WHERE name = '" + name + "'")); // sink
});

module.exports = app;
