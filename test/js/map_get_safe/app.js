// False-positive sentinel: looking up a Map/cache with an untrusted key is
// benign — not SSRF (js-ssrf sinks are http.get/https.get/axios/fetch, not a
// bare .get) and not injection. This ubiquitous pattern must produce ZERO
// findings.
var express = require("express");
var app = express();
var cache = new Map();

app.get("/x", function (req, res) {
  var key = req.query.key;      // untrusted key
  res.json({ val: cache.get(key) }); // benign Map lookup
});

module.exports = app;
