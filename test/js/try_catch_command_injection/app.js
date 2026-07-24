// Command injection whose taint crosses an exception edge (CWE-78). The
// untrusted request parameter is read in the `try` body; the sink runs in the
// `catch` handler. In the real CFG the catch block has the try-body block as a
// predecessor (the conservative exception edge), so the value assigned in the
// try body reaches the handler and child_process.exec() fires. A CFG that
// dropped the exception edge would leave `host` undefined in the handler (a
// false negative).

var express = require("express");
var child_process = require("child_process");
var app = express();

function handleLookup(req, res) {
  var host;
  try {
    host = req.query.host;
    throw new Error("boom");
  } catch (e) {
    child_process.exec("ping -c 1 " + host);
  }
  res.send("ok");
}

app.get("/lookup", handleLookup);

module.exports = app;
