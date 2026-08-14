// Command injection reached from a function literal in a loop HEADER, not its
// body (see expected.yaml).
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
