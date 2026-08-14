// A function literal in a loop HEADER, not its body. The lowering visits the
// header, so the collector must too: an uncollected literal there is unnamed,
// resolves to nothing, and its body goes unanalyzed while the file still reports
// as converted. Both sinks below live inside such a literal.
const { exec } = require("child_process");

function handleBatch(req, res) {
  for (const row of req.query.rows.filter((v) => v.ok)) {
    exec(row.cmd);
  }
  for (let i = 0, run = (c) => exec(c); i < 1; i++) {
    run(req.query.cmd);
  }
  res.send("ok");
}

module.exports = handleBatch;
