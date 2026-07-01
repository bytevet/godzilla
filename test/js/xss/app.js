// Express handler with a classic reflected XSS.
//
// GET /hello?name=<name> reads an untrusted query parameter and splices it
// directly into an HTML response body without any encoding/escaping, so an
// attacker-controlled `name` can inject arbitrary markup/script.

var express = require("express");
var app = express();

function handleName(req, res) {
  var name = req.query.name;
  res.send("<h1>" + name + "</h1>");
}

app.get("/hello", handleName);

module.exports = app;
