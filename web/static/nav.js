// The side nav (templates/layout.html), no dependencies. Without JS the
// groups are plain <details>, open on the current page's group. With it,
// the other groups remember being opened in this browser, and a filter
// box narrows the links, opening every group with a match. On narrow
// screens the nav folds away behind the Menu button in the top bar.
(function () {
  "use strict";

  var nav = document.querySelector("[data-nav]");
  if (!nav) return;
  var KEY = "baseline.nav.open";
  var groups = Array.prototype.slice.call(nav.querySelectorAll("[data-nav-group]"));
  var filter = nav.querySelector("[data-nav-filter]");
  var empty = nav.querySelector("[data-nav-empty]");

  var saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY)) || {}; } catch (e) { saved = {}; }
  function save() {
    try { localStorage.setItem(KEY, JSON.stringify(saved)); } catch (e) { /* storage off */ }
  }

  // filtering opens and closes groups too; only the user's toggles count.
  var filtering = false;
  groups.forEach(function (g) {
    var key = g.getAttribute("data-nav-group");
    if (!g.hasAttribute("data-nav-current") && saved[key]) g.open = true;
    g.addEventListener("toggle", function () {
      if (filtering || g.hasAttribute("data-nav-current")) return;
      if (g.open) saved[key] = true; else delete saved[key];
      save();
    });
  });

  var before = null; // open state before the filter, put back when it is cleared
  function apply() {
    var q = filter.value.trim().toLowerCase();
    filtering = true;
    if (q && !before) before = groups.map(function (g) { return g.open; });
    var any = false;
    nav.querySelectorAll("li").forEach(function (li) {
      var group = li.closest("[data-nav-group]");
      var text = li.textContent.toLowerCase() + " " + (group ? group.querySelector("summary").textContent.toLowerCase() : "");
      var hit = !q || text.indexOf(q) !== -1;
      li.hidden = !hit;
      if (hit) any = true;
    });
    groups.forEach(function (g, i) {
      var hits = g.querySelectorAll("li:not([hidden])").length;
      g.hidden = !!q && hits === 0;
      if (q) g.open = hits > 0;
      else if (before) g.open = before[i];
    });
    if (!q) before = null;
    empty.hidden = any;
    // toggle events fire after this returns, so stop ignoring them later.
    setTimeout(function () { filtering = false; }, 0);
  }

  // The Menu button: CSS hides it and the folded nav on wide screens, so
  // this only has to track open and closed.
  var toggle = document.querySelector("[data-nav-toggle]");
  if (toggle) {
    nav.classList.add("collapsible");
    toggle.hidden = false;
    var setOpen = function (open) {
      nav.classList.toggle("open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    };
    // No focus on the filter when opening: on a phone that pops the keyboard.
    toggle.addEventListener("click", function () {
      setOpen(!nav.classList.contains("open"));
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && nav.classList.contains("open")) {
        setOpen(false);
        toggle.focus();
      }
    });
  }

  filter.hidden = false;
  filter.addEventListener("input", apply);
  filter.addEventListener("keydown", function (e) {
    // Escape clears the filter first, and closes the menu once it is empty.
    if (e.key === "Escape" && filter.value) { e.stopPropagation(); filter.value = ""; apply(); }
    if (e.key === "Enter") {
      var first = nav.querySelector("li:not([hidden]) a");
      if (first) { e.preventDefault(); first.click(); }
    }
  });
})();

// Drop-down menus built on <details> (the host page's "More" tab) close
// when you click elsewhere or press Escape.
(function () {
  "use strict";
  function closeAll(except) {
    document.querySelectorAll("details.tab-more[open]").forEach(function (d) {
      if (d !== except) d.open = false;
    });
  }
  document.addEventListener("click", function (e) {
    closeAll(e.target.closest ? e.target.closest("details.tab-more") : null);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeAll(null);
  });
})();
