// COV-11: an Express route handler whose request parameter is named something
// other than the conventional `req` still has its request accessors treated as
// taint sources — the handler's first parameter IS the request object.
const cp = require("child_process");
const app = require("express")();

app.get("/run", (rq, res) => {
  const cmd = rq.query.cmd; // request source via an arbitrarily-named handler param
  cp.exec(cmd); // command-injection sink
  res.end();
});
