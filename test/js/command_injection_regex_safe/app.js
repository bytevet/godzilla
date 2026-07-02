// False-positive guard: RegExp.prototype.exec on untrusted input is benign
// pattern matching, NOT command execution. js-command-injection must NOT flag
// it (a broad "*.exec" sink would collide with regex.exec and fire a critical
// false positive). This sample must produce ZERO findings.
var express = require("express");
var app = express();

var EMAIL = /^[^@]+@[^@]+$/;

app.get("/validate", function (req, res) {
  var email = req.query.email;
  var m = EMAIL.exec(email); // regex match — not a shell command
  res.send(m ? "valid" : "invalid");
});

module.exports = app;
