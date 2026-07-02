var express = require('express');
var app = express();

app.get('/run', function (req, res) {
  var code = req.query.code;  // untrusted input (source)
  var result = eval(code);    // code injection -> RCE (sink)
  res.send(String(result));
});
