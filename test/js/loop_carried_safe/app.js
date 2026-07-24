// Safe control for the loop-carried lowering (the false-positive guard). The
// value carried across the loop's back-edge is always a constant, so even
// though the real CFG now models loop-carried values through the header PHI,
// no tainted value ever reaches child_process.exec() and NO finding must be
// produced. The handler's request object is present but never flows to the
// sink.

var express = require("express");
var child_process = require("child_process");
var app = express();

function handleRun(req, res) {
  var cmd = "whoami";
  var i = 0;
  while (i < 3) {
    child_process.exec(cmd);
    cmd = "id";
    i = i + 1;
  }
  res.send("ok");
}

app.get("/run", handleRun);

module.exports = app;
