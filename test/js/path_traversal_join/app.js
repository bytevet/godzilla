// Path traversal where the untrusted filename reaches the sink THROUGH a
// propagator (path.join), not by direct use. path.join does NOT contain input
// to a base directory ("/var/data" + "../../etc/passwd" resolves out of the
// base), so it must propagate taint (propagator, not sanitizer). This
// exercises the propagator edge of js-path-traversal.

var express = require("express");
var fs = require("fs");
var path = require("path");
var app = express();

function handleDownload(req, res) {
  var filename = req.query.filename;             // untrusted (source)
  var full = path.join("/var/data", filename);   // taint flows through propagator
  fs.readFile(full, function (err, data) {       // sink
    res.send(data);
  });
}

app.get("/download", handleDownload);

module.exports = app;
