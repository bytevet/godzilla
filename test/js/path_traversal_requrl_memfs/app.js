// Path traversal modeled on CVE-2024-29180 (webpack-dev-middleware): the raw
// request target `req.url` (pathname + query) flows -- through URL-decoding and
// path.join, with NO "../" containment -- into a filesystem read. The read is
// NOT on the literal `fs` module but on an injected filesystem abstraction
// (here `context.outputFileSystem`, a memfs-style object in the real CVE), so
// the sink is matched by method name (`*.statSync` / `*.createReadStream`), not
// an `fs.`-anchored glob. querystring.unescape decodes the tainted pathname and
// must PROPAGATE taint (decoding `%2e%2e` -> `..` only widens the traversal).
var http = require("http");
var path = require("path");
var querystring = require("querystring");

function serve(context, req, res) {
  var pathname = req.url;                                 // untrusted (source)
  var decoded = querystring.unescape(pathname);           // propagator (decode)
  var filename = path.join(context.outputPath, decoded);  // propagator (no containment)

  var stats = context.outputFileSystem.statSync(filename); // sink (memfs stat)
  if (stats.isFile()) {
    context.outputFileSystem.createReadStream(filename).pipe(res); // sink (memfs read)
  }
}

var server = http.createServer(function (req, res) {
  serve({ outputPath: "/dist", outputFileSystem: require("memfs") }, req, res);
});

module.exports = server;
