// FE-2 (JS): aliased, destructured, and require().member sink bindings must all
// resolve to child_process.* so the command-injection sinks match. All three
// were false negatives before require-alias resolution.
var express = require("express");
var cp = require("child_process");
var { exec } = require("child_process");
var ex = require("child_process").execSync;
var app = express();

app.get("/a", function (req, res) { cp.exec(req.query.cmd); res.end(); });
app.get("/b", function (req, res) { exec(req.query.cmd); res.end(); });
app.get("/c", function (req, res) { ex(req.query.cmd); res.end(); });
module.exports = app;
