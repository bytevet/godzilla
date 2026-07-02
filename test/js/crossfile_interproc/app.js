// Request handler whose untrusted input flows through a cross-file call:
// req.query.id -> db.run(...) in db.js -> _conn.query(...) sink there.
var express = require("express");
var db = require("./db");
var app = express();

app.get("/u", function (req, res) {
  var uid = req.query.id;                                     // source
  res.send(db.run("SELECT * FROM users WHERE id = " + uid));  // cross-file call to sink wrapper
});

module.exports = app;
