// Express handler with a classic SQL injection.
//
// GET /user?id=<id> reads an untrusted query parameter and splices it
// directly into a SQL string handed to the database driver's query() call,
// so an attacker-controlled `id` can inject arbitrary SQL.

var express = require("express");
var mysql = require("mysql");
var app = express();
var db = mysql.createConnection({ host: "localhost" });

function handleUser(req, res) {
  var id = req.query.id;
  var sql = "SELECT * FROM users WHERE id = " + id;
  db.query(sql, function (err, results) {
    res.send(results);
  });
}

app.get("/user", handleUser);

module.exports = app;
