// `new URL(x)` is the natural way to build a request target, so a taint wall
// there hides the flow it most often sits in. next.js CVE-2026-64649 is the
// shape: the Host header reaches fetch through a helper, an object field, a
// template literal, and finally the URL constructor.
function parseHostHeader(headers) {
  const hostHeader = headers['host'];
  return {type: 'host', value: hostHeader};
}

export async function forwardAction(req) {
  const host = parseHostHeader(req.headers);
  const origin = `https://${host.value}`;
  return await fetch(new URL(`${origin}/worker`));
}

export async function directURL(req) {
  return await fetch(new URL(`https://${req.query.target}/x`));
}

// Control: a constant host is not tainted, and hostFixed() keeps the query
// string in the path from firing -- new URL must not manufacture taint.
export async function fixedHost(req) {
  return await fetch(new URL(`https://api.internal.example/x?q=${req.query.q}`));
}

// The two-argument form resolves against a BASE whose host wins, so Args[0] is
// not the value's text and the identity marker is deliberately withheld. That
// costs precision rather than recall: a tainted base fires (right), and a fixed
// base fires too (a known false positive, pinned here so making hostFixed() read
// the base shows up as a diff instead of passing silently).
export async function taintedBase(req) {
  return await fetch(new URL('/worker', req.query.base));
}

export async function fixedBase(req) {
  return await fetch(new URL('/worker?q=' + req.query.q, 'https://api.internal.example'));
}
