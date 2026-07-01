// Express handler with a classic reflected XSS, used alongside broken.js
// (an unparseable sibling file in this same directory) to prove that a
// single bad .js file does not prevent this valid, vulnerable file from
// still being converted and analyzed.

var express = require("express");
var app = express();

function handleGreeting(req, res) {
  var greeting = req.query.greeting;
  res.send("<p>" + greeting + "</p>");
}

app.get("/greet", handleGreeting);

module.exports = app;
