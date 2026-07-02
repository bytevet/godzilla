// Express handler that contains an untrusted filename with path.basename
// before filesystem access.
//
// path.basename() strips every directory component (including "../"
// sequences), so the value handed to fs.readFile can no longer escape the
// intended "/var/data" directory. js-path-traversal.yaml lists path.basename
// as a sanitizer, so this handler must produce ZERO findings — the
// false-positive guard for that sanitizer.

var express = require("express");
var fs = require("fs");
var path = require("path");
var app = express();

function handleDownload(req, res) {
  var filename = req.query.filename;
  var safe = path.basename(filename); // sanitized: directory components stripped
  fs.readFile("/var/data/" + safe, function (err, data) {
    res.send(data);
  });
}

app.get("/download", handleDownload);

module.exports = app;
