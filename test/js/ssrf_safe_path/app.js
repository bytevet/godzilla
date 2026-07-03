// Safe SSRF sentinel: the untrusted value reaches only the PATH of a fixed host
// (via template literal and concatenation), so the request cannot be redirected
// to an attacker host. Must produce ZERO findings.
var axios = require("axios");

function handleProxy(req, res) {
  var path = req.query.path;
  axios.get(`https://api.internal.example.com/v1/${path}`).then(function (r) {
    res.send(r.data);
  });
  axios.get("https://api.internal.example.com/items/" + path).then(function (r) {
    res.send(r.data);
  });
}

module.exports = handleProxy;
