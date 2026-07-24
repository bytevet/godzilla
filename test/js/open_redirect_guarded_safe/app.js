// Flow-sensitive FP guard (ENG-9), false-branch-return idiom — proves the
// dominator-based guard analysis (internal/analysis/guards.go) now engages for
// the JS frontend's real CFG (Phase 4). The untrusted `next` target is checked
// with isSafeUrl; on the failing branch the handler returns, so the redirect is
// reached only on the fall-through where the check PASSED (that block dominates
// the sink). Correctly suppressed; a flow-insensitive engine would flag it.
var express = require("express");
var app = express();

function isSafeUrl(u) {
  return typeof u === "string" && u.charAt(0) === "/";
}

app.get("/go", function (req, res) {
  var dest = req.query.next;
  if (!isSafeUrl(dest)) {
    res.status(400).end();
    return;
  }
  res.redirect(dest); // dominated by the false/fall-through (validated) block
});

module.exports = app;
