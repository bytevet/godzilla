// Express handlers with classic Server-Side Request Forgery.
//
// Each route reads an untrusted query parameter and hands it directly to an
// outbound HTTP client as the request URL/host, so an attacker-controlled
// `url` can redirect the server into fetching internal or unintended hosts.
// Three separate handlers exercise the three outbound-HTTP-client families
// js-ssrf.yaml watches for: Node's built-in http module, axios, and fetch.

var express = require("express");
var http = require("http");
var axios = require("axios");
var app = express();

function handleProxyHttp(req, res) {
  var target = req.query.url;
  http.get(target, function (proxyRes) {
    proxyRes.pipe(res);
  });
}

function handleProxyAxios(req, res) {
  var target = req.query.url;
  axios.get(target).then(function (response) {
    res.send(response.data);
  });
}

function handleProxyFetch(req, res) {
  var target = req.query.url;
  fetch(target).then(function (response) {
    res.send(response.body);
  });
}

app.get("/proxy/http", handleProxyHttp);
app.get("/proxy/axios", handleProxyAxios);
app.get("/proxy/fetch", handleProxyFetch);

module.exports = app;
