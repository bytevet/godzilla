// Express handler with a path traversal via a route parameter.
//
// GET /files/:name reads an untrusted route parameter (req.params) and passes
// it straight to res.sendFile, so a "../" sequence can escape the intended
// directory.

var express = require("express");
var app = express();

app.get("/files/:name", function (req, res) {
  var name = req.params.name;
  res.sendFile(name);
});

module.exports = app;
