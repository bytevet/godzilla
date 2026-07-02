// False-positive guard: sending untrusted input to a NON-response object (an
// email client here; likewise a message queue or socket) is not reflected XSS
// — it never reaches an HTTP response body. js-xss must NOT flag it (a bare
// "*.send" sink would collide with mailer.send and fire a false positive). This
// sample must produce ZERO findings.
var express = require("express");
var mailer = require("some-mailer");
var app = express();

app.get("/notify", function (req, res) {
  var body = req.query.body;
  mailer.send(body); // not an HTTP response — not XSS
  res.end("queued");
});

module.exports = app;
