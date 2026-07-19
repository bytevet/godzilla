// COV-11: an Express route handler that destructures its request object in the
// signature — `({ query }, res) => ...` instead of `(req, res) => ...` — still
// has the destructured properties treated as taint sources. The destructured
// local IS `req.query`, so it seeds request taint the same way an in-body
// `req.query` member read would.
const cp = require("child_process");
const app = require("express")();

app.get("/run", ({ query }, res) => {
  cp.exec(query.cmd); // request source via destructured handler param
  res.end();
});

// Renamed destructuring (`{ body: b }`) binds the local `b` to `req.body`.
app.post("/save", ({ body: b }, res) => {
  cp.exec(b.path); // tainted through the renamed local
  res.end();
});
