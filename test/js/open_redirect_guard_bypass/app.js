// Precision control for open_redirect_guarded_safe: SAME validator (isSafeUrl) on
// the SAME untrusted value, but with no early return — the check only guards a
// benign log, and the redirect after the merge is reached whether or not the
// check passed. Neither branch dominates the sink, so the taint still reaches it
// and the finding MUST still fire. Proves the dominator suppression is precise.
var express = require("express");
var app = express();

function isSafeUrl(u) {
  return typeof u === "string" && u.charAt(0) === "/";
}

app.get("/go", function (req, res) {
  var dest = req.query.next;
  if (isSafeUrl(dest)) {
    console.log("target looked safe");
  }
  res.redirect(dest); // post-merge: neither branch dominates -> fires
});

module.exports = app;
