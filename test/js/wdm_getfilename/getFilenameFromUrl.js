// The vulnerable helper, in its own module (module.exports = getFilenameFromUrl,
// a DEFAULT export). The parsed URL's pathname is joined onto a base directory
// and stat()ed on an injected filesystem, so "../" sequences escape the base.
const path = require("path");
const querystring = require("querystring");
const mem = require("mem");

const { parse } = require("url"); // parse -> url.parse (a path-traversal propagator)

// Blocker 2: an identity/memoize wrapper. `memoizedParse(x)` behaves like
// `parse(x)`, but the wrapper hides that from a syntactic callee resolver, so
// taint would drop here without the identity-wrapper alias.
const memoizedParse = mem(parse);

const outputPath = "/public";

function getFilenameFromUrl(outputFileSystem, reqUrl) {
  const urlObject = memoizedParse(reqUrl); // taint via url.parse
  const pathname = querystring.unescape(urlObject.pathname); // taint via querystring.unescape
  const filename = path.join(outputPath, pathname); // taint via path.join (no containment)
  return outputFileSystem.statSync(filename); // SINK: js:*.statSync
}

module.exports = getFilenameFromUrl;
