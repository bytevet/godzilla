// FE-5 (JS): the statement-level "default if empty" pattern must not drop
// taint. Before branch-merge PHI flattening the reassignment inside the `if`
// body killed the tainted binding on the merge path (a false negative); now
// both incoming values are PHI-merged so the tainted branch stays live into
// the sink. The expression-level `cond ? a : b` form already merged correctly.
var express = require("express");
var cp = require("child_process");
var app = express();

app.get("/ping", function (req, res) {
  var host = req.query.host;
  if (!host) {
    host = "localhost";
  }
  cp.execSync("ping -c 1 " + host);
  res.end();
});

module.exports = app;
