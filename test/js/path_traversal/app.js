// Express handlers with classic path traversal.
//
// Each route reads an untrusted query parameter and splices it directly
// into a filesystem path without validation/containment, so an
// attacker-controlled `filename` (e.g. "../../etc/passwd") can escape the
// intended "/var/data" directory. Three separate handlers exercise the
// three filesystem-access sinks js-path-traversal.yaml watches for:
// fs.readFile, fs.createReadStream, and res.sendFile.

var express = require("express");
var fs = require("fs");
var app = express();

function handleDownload(req, res) {
  var filename = req.query.filename;
  fs.readFile("/var/data/" + filename, function (err, data) {
    res.send(data);
  });
}

function handleStream(req, res) {
  var filename = req.query.filename;
  var stream = fs.createReadStream("/var/data/" + filename);
  stream.pipe(res);
}

function handleServe(req, res) {
  var filename = req.query.filename;
  res.sendFile("/var/data/" + filename);
}

app.get("/download", handleDownload);
app.get("/stream", handleStream);
app.get("/serve", handleServe);

module.exports = app;
