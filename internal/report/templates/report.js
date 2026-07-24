/* Godzilla SAST report — client-side filtering.
   This script is static: it contains NO finding data. It only reads data-*
   attributes and textContent already rendered (and escaped) by html/template,
   and toggles card visibility. It never writes finding data into the DOM via
   innerHTML, so it cannot reintroduce an XSS vector. With JS disabled every
   card stays visible, so the report degrades gracefully. */
(function () {
  "use strict";
  var cards = Array.prototype.slice.call(document.querySelectorAll(".finding"));
  var sevBoxes = Array.prototype.slice.call(document.querySelectorAll(".controls input[data-sev]"));
  var ruleSel = document.getElementById("f-rule");
  var search = document.getElementById("f-search");
  var counter = document.getElementById("f-count");
  if (!cards.length) return;

  function activeSeverities() {
    var on = {};
    sevBoxes.forEach(function (b) {
      on[b.getAttribute("data-sev")] = b.checked;
      var lab = b.closest("label");
      if (lab) lab.classList.toggle("off", !b.checked);
    });
    return on;
  }

  function apply() {
    var sev = activeSeverities();
    var rule = ruleSel ? ruleSel.value : "";
    var q = search ? search.value.trim().toLowerCase() : "";
    var shown = 0;
    for (var i = 0; i < cards.length; i++) {
      var c = cards[i];
      var ok = sev[c.getAttribute("data-severity")] !== false;
      if (ok && rule && c.getAttribute("data-rule") !== rule) ok = false;
      if (ok && q && c.textContent.toLowerCase().indexOf(q) === -1) ok = false;
      c.hidden = !ok;
      if (ok) shown++;
    }
    if (counter) counter.textContent = shown + " / " + cards.length + " shown";
  }

  var timer = null;
  function debounced() {
    if (timer) clearTimeout(timer);
    timer = setTimeout(apply, 120);
  }

  sevBoxes.forEach(function (b) { b.addEventListener("change", apply); });
  if (ruleSel) ruleSel.addEventListener("change", apply);
  if (search) search.addEventListener("input", debounced);
  apply();
})();
