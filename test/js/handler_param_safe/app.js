// FP guards for JS handler-param synthesis: (1) a non-route `.get(fn)` (e.g. a
// lodash-style call) must NOT turn its callback's first arg into a request
// source; (2) a real handler that never passes request data to a sink is clean.
const cp = require("child_process");
const _ = require("lodash");
const app = require("express")();

// Not a route: a first arg that happens to expose `.query` is not untrusted here.
_.get(config, (opts, k) => {
  cp.exec(opts.query.cmd); // opts is NOT a request object -> no finding
});

app.get("/ok", (rq, res) => {
  const _unused = rq.query.cmd; // read but never reaches a sink
  cp.exec("ls -la"); // constant argument, not tainted
  res.end();
});
