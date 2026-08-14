// Cross-file taint into a sink inside a .vue component, imported by a specifier
// that keeps its extension (see expected.yaml).
import express from "express";
import render from "./Renderer.vue";

const app = express();

app.get("/r", function (req, res) {
  const id = req.query.id; // source
  res.send(render("SELECT * FROM users WHERE id = " + id)); // cross-file call into Renderer.vue
});

export default app;
