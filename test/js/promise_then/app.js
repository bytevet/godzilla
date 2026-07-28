// A promise is a boundary taint has to cross: the handler READS the request and
// returns a value, and a separate `.then` callback consumes it. In modern Node
// this shape carries most request handling — parse-server routes every response
// through it — so a promise that stops taint hides whole applications.
const express = require("express");
const app = express();

function loadName(req) {
  return req.query.name;
}

app.get("/hello", (req, res) => {
  loadName(req).then(name => {
    res.send("<h1>" + name + "</h1>");
  });
});
