// Control: the `.then` callback's parameter comes from a promise carrying only
// constants, so modeling the continuation must not invent taint. Guards the
// direction the promise change could go wrong — a callback parameter marked
// tainted because a callback exists rather than because a value reached it.
const express = require("express");
const app = express();

function loadBanner() {
  return Promise.resolve("welcome");
}

app.get("/hello", (req, res) => {
  loadBanner().then(banner => {
    res.send("<h1>" + banner + "</h1>");
  });
});
