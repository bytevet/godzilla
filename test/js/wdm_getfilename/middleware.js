// Reproduces the shape of CVE-2024-29180 (webpack-dev-middleware): the raw
// request target `req.url` flows through a CROSS-MODULE default-export call
// (`const getFilenameFromUrl = require("./getFilenameFromUrl")`) into a helper
// that builds a filesystem path and stat()s it, with no containment check.
const express = require("express");
const getFilenameFromUrl = require("./getFilenameFromUrl");
const outputFileSystem = require("memfs");
const app = express();

app.get("/*", function (req, res) {
  // req.url is attacker-controlled (source). It is handed to a helper defined
  // in another file via a bare default-import call (blocker 1: cross-module
  // default-export resolution).
  getFilenameFromUrl(outputFileSystem, req.url);
  res.end("ok");
});

module.exports = app;
