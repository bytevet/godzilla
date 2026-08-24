// Client-side navigation from browser-controlled input. Unlike a server's
// Location header -- which browsers refuse to follow to a `javascript:` URL --
// each of these executes one, so every case is XSS, not just an open redirect.

function go() {
  const next = window.location.search;

  // Assignment: no callee to match, mirrored by the frontend.
  location.href = next;

  // Calls.
  location.assign(next);
  window.location.replace(next);
  window.open(next);
}

go();
