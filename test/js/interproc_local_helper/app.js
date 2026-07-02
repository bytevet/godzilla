// Inter-procedural taint through a bare-named top-level local helper.
//
// The untrusted id enters buildQuery() (arg -> param), which returns a string
// containing it (return-taint), and that result reaches the query() sink. The
// helper is invoked by a bare name (buildQuery(...)), whose callee
// ("js:<module>.buildQuery") must match the function's CanonicalName for taint
// to flow through the local helper at all.
var express = require("express");
var db = require("some-db");
var app = express();

function buildQuery(uid) {
  return "SELECT * FROM users WHERE id = " + uid; // returns tainted string
}

app.get("/u", function (req, res) {
  var uid = req.query.id;     // source
  var q = buildQuery(uid);    // bare local call: arg -> param, then return-taint
  res.send(db.query(q));      // sink
});

module.exports = app;
