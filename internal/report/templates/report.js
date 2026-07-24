/* Godzilla SAST report — client-side interaction.
   Static: contains NO finding data. It reads data-* attributes and textContent
   already rendered (and escaped) by html/template and toggles visibility /
   selection. The wide-screen detail pane is produced with cloneNode(true),
   which copies already-escaped DOM nodes without re-parsing, so it cannot
   introduce an XSS vector. With JS disabled every finding body stays reachable
   via the inline accordion, so the report degrades gracefully. */
/* Theme toggle: overrides the OS preference by stamping data-theme on <html>,
   persisted in localStorage. The button shows the icon of the theme the click
   switches to. No finding data involved. */
(function () {
  "use strict";
  var root = document.documentElement;
  var btn = document.getElementById("theme-toggle");
  if (!btn) return;
  var KEY = "godzilla-theme";
  var mq = window.matchMedia("(prefers-color-scheme: dark)");
  function effective() { return root.getAttribute("data-theme") || (mq.matches ? "dark" : "light"); }
  function refresh() { btn.setAttribute("data-eff", effective()); }
  try {
    var saved = localStorage.getItem(KEY);
    if (saved === "dark" || saved === "light") root.setAttribute("data-theme", saved);
  } catch (e) {}
  refresh();
  btn.addEventListener("click", function () {
    var next = effective() === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem(KEY, next); } catch (e) {}
    refresh();
  });
  if (mq.addEventListener) mq.addEventListener("change", refresh);
  else if (mq.addListener) mq.addListener(refresh);
})();

(function () {
  "use strict";
  var findings = Array.prototype.slice.call(document.querySelectorAll(".finding"));
  var sevBoxes = Array.prototype.slice.call(document.querySelectorAll(".controls input[data-sev]"));
  var ruleSel = document.getElementById("f-rule");
  var search = document.getElementById("f-search");
  var counter = document.getElementById("f-count");
  var detail = document.querySelector(".detail");
  var empty = detail ? detail.querySelector(".pane-empty") : null;
  if (!findings.length) return;

  var wideMQ = window.matchMedia("(min-width: 960px)");
  var active = null;

  function isWide() { return wideMQ.matches; }

  function renderPane() {
    if (!detail) return;
    var prev = detail.querySelector(".pane");
    if (prev) prev.remove();
    if (active && isWide()) {
      var clone = active.querySelector(".body").cloneNode(true);
      clone.classList.remove("body");
      clone.classList.add("pane");
      detail.appendChild(clone);
      if (empty) empty.hidden = true;
    } else if (empty) {
      empty.hidden = false;
    }
  }

  function setActive(f) {
    active = f;
    findings.forEach(function (x) {
      var on = x === f;
      x.classList.toggle("active", on);
      var btn = x.querySelector(".item");
      if (btn) btn.setAttribute("aria-expanded", on && !isWide() ? "true" : String(on && isWide()));
    });
    renderPane();
  }

  function onClick(f) {
    if (isWide()) {
      setActive(f);
    } else {
      // Narrow: inline accordion — toggle this finding open/closed.
      var openNow = !f.classList.contains("open");
      f.classList.toggle("open", openNow);
      var btn = f.querySelector(".item");
      if (btn) btn.setAttribute("aria-expanded", String(openNow));
      active = openNow ? f : null;
      findings.forEach(function (x) { x.classList.toggle("active", x === f && openNow); });
    }
  }

  function firstVisible() {
    for (var i = 0; i < findings.length; i++) if (!findings[i].hidden) return findings[i];
    return null;
  }

  function apply() {
    var sev = {};
    sevBoxes.forEach(function (b) {
      sev[b.getAttribute("data-sev")] = b.checked;
      var lab = b.closest("label");
      if (lab) lab.classList.toggle("off", !b.checked);
    });
    var rule = ruleSel ? ruleSel.value : "";
    var q = search ? search.value.trim().toLowerCase() : "";
    var shown = 0;
    findings.forEach(function (f) {
      var ok = sev[f.getAttribute("data-severity")] !== false;
      if (ok && rule && f.getAttribute("data-rule") !== rule) ok = false;
      if (ok && q && f.textContent.toLowerCase().indexOf(q) === -1) ok = false;
      f.hidden = !ok;
      if (ok) shown++;
    });
    if (counter) counter.textContent = shown + " / " + findings.length + " shown";
    // Keep a sensible selection on wide screens.
    if (isWide()) {
      if (!active || active.hidden) setActive(firstVisible());
    } else if (active && active.hidden) {
      active.classList.remove("open", "active");
      active = null;
    }
  }

  function onBreakpoint() {
    if (isWide()) {
      // Entering wide: ensure a pane is shown.
      findings.forEach(function (x) { x.classList.remove("open"); });
      if (!active || active.hidden) active = firstVisible();
      setActive(active);
    } else {
      // Entering narrow: drop the cloned pane; reflect selection as an open row.
      var prev = detail ? detail.querySelector(".pane") : null;
      if (prev) prev.remove();
      if (empty) empty.hidden = false;
      if (active) {
        active.classList.add("open");
        var btn = active.querySelector(".item");
        if (btn) btn.setAttribute("aria-expanded", "true");
      }
    }
  }

  findings.forEach(function (f) {
    var btn = f.querySelector(".item");
    if (btn) btn.addEventListener("click", function () { onClick(f); });
  });
  sevBoxes.forEach(function (b) { b.addEventListener("change", apply); });
  if (ruleSel) ruleSel.addEventListener("change", apply);
  if (search) {
    var timer = null;
    search.addEventListener("input", function () {
      if (timer) clearTimeout(timer);
      timer = setTimeout(apply, 120);
    });
  }
  if (wideMQ.addEventListener) wideMQ.addEventListener("change", onBreakpoint);
  else if (wideMQ.addListener) wideMQ.addListener(onBreakpoint);

  apply();
  if (isWide()) setActive(firstVisible());
})();
