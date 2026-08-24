// Controls for dom_nav_xss: none of these may fire.

function isSafeUrl(u) {
  return u.startsWith("/app/");
}

function go() {
  const next = new URLSearchParams(window.location.search).get("next");

  // A constant scheme+host prefix fixes the scheme, so no attacker-chosen
  // `javascript:` is reachable (hostFixed).
  location.href = "https://example.com/" + next;

  // Gated by an application allowlist predicate that dominates the navigation.
  if (isSafeUrl(next)) {
    window.location.assign(next);
  }

  // A path-only property cannot carry a scheme or a host.
  location.pathname = next;

  // Not navigation: an ordinary object field that happens to be named href.
  const link = { href: next };
  return link;
}

go();
