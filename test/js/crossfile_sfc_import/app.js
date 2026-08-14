// A relative import of a .vue component. The specifier keeps its extension while
// the walk names the module without one, so the two only meet if the resolver
// strips exactly the extensions IsJSFamily recognizes — SFCs included. Get that
// wrong and the cross-module edge silently disappears: no error, no skipped
// file, just a finding that stops being reported.
import express from "express";
import render from "./Renderer.vue";

const app = express();

app.get("/r", function (req, res) {
  const id = req.query.id; // source
  res.send(render("SELECT * FROM users WHERE id = " + id)); // cross-file call into Renderer.vue
});

export default app;
