// FP sentinel: spawn/execFile take a program plus an argument array and never
// reach a shell, so an untrusted element is one argv entry. ZERO findings.
// A call passing an options object still fires — `{shell: true}` is unreadable
// here. Vulnerable counterpart: command_injection (child_process.exec).
const cp = require("child_process");
const express = require("express");

const app = express();

app.get("/ls", function (req, res) {
  cp.spawn("ls", ["-la", req.query.name]); // fixed program, argv element
  cp.execFile("/bin/echo", [req.query.name]);
  res.end("ok");
});
