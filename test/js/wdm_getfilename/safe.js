// Safe control: a stat() on a constant, fully in-code path (no untrusted input
// reaches the filesystem call), so it must NOT produce a path-traversal finding.
const fs = require("fs");
const path = require("path");

function readConfig(outputFileSystem) {
  const filename = path.join("/etc/app", "config.json");
  return outputFileSystem.statSync(filename);
}

module.exports = readConfig;
