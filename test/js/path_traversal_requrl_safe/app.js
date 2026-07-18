// Safe counterpart to path_traversal_requrl_memfs: the same req.url-derived
// pathname is CONTAINED with path.basename before the filesystem read.
// path.basename strips every directory component (including "../" sequences),
// so the value handed to the memfs read can no longer escape the base dir.
// js-path-traversal.yaml lists path.basename as a sanitizer, so this handler
// must produce ZERO findings -- the false-positive guard for the memfs sinks
// and the req.url source added for CVE-2024-29180.
var http = require("http");
var path = require("path");
var querystring = require("querystring");

function serve(context, req, res) {
  var decoded = querystring.unescape(req.url);
  var safe = path.basename(decoded);                    // sanitized: dir components stripped
  var filename = path.join(context.outputPath, safe);

  var stats = context.outputFileSystem.statSync(filename); // NOT a finding (contained)
  if (stats.isFile()) {
    context.outputFileSystem.createReadStream(filename).pipe(res);
  }
}

var server = http.createServer(function (req, res) {
  serve({ outputPath: "/dist", outputFileSystem: require("memfs") }, req, res);
});

module.exports = server;
