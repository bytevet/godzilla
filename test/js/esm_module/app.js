// ES-module syntax in a plain .js file, as Babel-transpiled Node projects and
// anything with "type": "module" write it. The extension says nothing about the
// dialect, so only trying the ladder's rungs finds this one -- and losing the
// file would be SILENT, since a sibling converting still reports coverage=ok.
import express from "express";
import { exec } from "child_process";

export const app = express();

app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host);
  res.send("ok");
});
