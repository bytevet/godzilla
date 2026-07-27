// Control: the object handed across the boundary carries only constants, so a
// property read off the parameter must stay clean. Guards the direction this
// change could go wrong — a member read marked tainted because a base exists
// rather than because the base carries taint.
//
// Note what this does NOT assert: JS has no field identity (the frontend sets no
// FieldIndex), so a clean field of a PARTLY tainted object does read as tainted.
// That imprecision is accepted and pre-existing for local bases; this sample
// pins the case the engine can actually decide.
const express = require("express");
const app = express();

function buildBanner() {
  return { html: "<h1>welcome</h1>" };
}

app.get("/hello", (req, res) => {
  const result = buildBanner();
  res.send(result.html);
});
