var express = require('express');
var app = express();

app.get('/go', function (req, res) {
  var target = req.query.url;  // untrusted input
  res.redirect(target);        // open redirect
});
