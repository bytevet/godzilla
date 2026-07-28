// Request data usually stops being a bare string the moment it crosses a function
// boundary: a helper wraps it in an object and the consumer reads a property back
// off its parameter. The property read off a PARAMETER lowers to a synthetic call
// (so `req.query.x` can match a source glob), and that call used to discard its
// base — so a tainted object read clean and the flow ended at the boundary.
const express = require("express");
const app = express();

function buildResult(req) {
  return { html: req.query.name };
}

app.get("/hello", (req, res) => {
  const result = buildResult(req);
  res.send(result.html);
});
