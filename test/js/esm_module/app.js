// ES-module syntax in a plain .js file, as Babel-transpiled Node projects and
// anything with "type": "module" write it. goja cannot parse the import, so
// judging the esbuild path by extension alone dropped the whole file -- and the
// language still reported coverage=ok because other files in the tree converted.
import express from "express";
import { exec } from "child_process";

export const app = express();

app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host);
  res.send("ok");
});
