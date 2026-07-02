// Sink wrapper in a separate module from the request handler.
var _conn = require("some-db");

function run(q) {          // q is tainted by the caller in app.js
  return _conn.query(q);   // SQL sink lives in a DIFFERENT file
}

module.exports = { run: run };
