var express = require('express');
var app = express();

app.get('/run', function (req, res) {
  var raw = req.query.data;      // untrusted input (source)
  var result = JSON.parse(raw);  // safe: parses data, does not execute code
  res.send(String(result.ok));
});
