// Express handler with a classic OS command injection.
//
// GET /ping?cmd=<cmd> reads an untrusted query parameter and hands it
// directly to child_process.exec, so an attacker-controlled `cmd` can
// inject arbitrary shell commands.

var express = require("express");
var child_process = require("child_process");
var app = express();

function handleCmd(req, res) {
  var cmd = req.query.cmd;
  child_process.exec(cmd);
}

app.get("/ping", handleCmd);

module.exports = app;
