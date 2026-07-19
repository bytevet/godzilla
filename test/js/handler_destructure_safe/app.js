// FP guard for destructured handler-param synthesis: (1) a non-route call that
// destructures its callback's first arg must NOT treat those properties as
// request sources; (2) a real handler whose destructured props never reach a
// sink is clean.
const cp = require("child_process");
const _ = require("lodash");
const app = require("express")();

// Not a route: `{ query }` here is destructured off an ordinary options object.
_.forEach(items, ({ query }) => {
  cp.exec(query.cmd); // query is NOT a request object -> no finding
});

app.get("/ok", ({ query }, res) => {
  const _unused = query.cmd; // read but never reaches a sink
  cp.exec("ls -la"); // constant argument, not tainted
  res.end();
});
