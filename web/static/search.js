// Global search (templates/layout.html, docs/search.md), no dependencies.
// Without JS the top bar's box is a GET form to /search. With it, Ctrl-K,
// Cmd-K or "/" anywhere (or focusing the box) opens a palette that finds
// pages from the side nav as you type, and records through /search.json.
(function () {
  "use strict";

  var form = document.querySelector("[data-search]");
  if (!form || typeof HTMLDialogElement !== "function") return;
  var base = form.getAttribute("data-search") || "";
  var topInput = form.querySelector("input[name=q]");
  var mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  var keyHint = form.querySelector("[data-search-key]");
  if (keyHint && mac) keyHint.textContent = "⌘K";

  // Pages: the side nav's links, labelled with their group.
  var pages = [];
  document.querySelectorAll("[data-nav] a").forEach(function (a) {
    var group = a.closest("[data-nav-group]");
    var summary = group && group.querySelector("summary");
    pages.push({ title: a.textContent.trim(), detail: summary ? summary.textContent.trim() : "", url: a.getAttribute("href") });
  });

  var dlg = document.createElement("dialog");
  dlg.className = "palette";
  dlg.setAttribute("aria-label", "Search");
  dlg.innerHTML =
    '<div class="palette-box">' +
    '<input type="search" class="palette-input" placeholder="Search hosts, containers, stacks, CIs, work items, changes…" ' +
    'role="combobox" aria-expanded="true" aria-controls="palette-list" aria-autocomplete="list" autocomplete="off" spellcheck="false">' +
    '<div class="palette-list" id="palette-list" role="listbox" aria-label="Results"></div>' +
    '<div class="palette-foot small muted"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>Enter</kbd> open</span>' +
    '<span><kbd>Esc</kbd> close</span><a class="palette-all" href="' + base + '/search">All results</a></div>' +
    "</div>";
  document.body.appendChild(dlg);
  var input = dlg.querySelector(".palette-input");
  var listEl = dlg.querySelector(".palette-list");
  var allLink = dlg.querySelector(".palette-all");

  var options = []; // the result links, in order
  var active = -1;
  var timer = null;
  var ctrl = null; // aborts a stale request
  var seq = 0;
  var shown = null; // the text the shown results are for

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text) e.textContent = text;
    return e;
  }

  function setActive(i) {
    if (active >= 0 && options[active]) options[active].removeAttribute("aria-selected");
    active = options.length ? (i + options.length) % options.length : -1;
    if (active < 0) {
      input.removeAttribute("aria-activedescendant");
      return;
    }
    var o = options[active];
    o.setAttribute("aria-selected", "true");
    input.setAttribute("aria-activedescendant", o.id);
    o.scrollIntoView({ block: "nearest" });
  }

  function addGroup(label, results, more) {
    var g = el("div", "palette-group");
    g.setAttribute("role", "group");
    var h = el("div", "palette-head", label);
    h.id = "palette-g" + listEl.children.length;
    g.setAttribute("aria-labelledby", h.id);
    g.appendChild(h);
    results.forEach(function (r) {
      var a = el("a", "palette-item" + (r.dim ? " dim" : ""));
      a.href = r.url;
      a.id = "palette-o" + options.length;
      a.setAttribute("role", "option");
      a.tabIndex = -1;
      if (r.ref) a.appendChild(el("span", "palette-ref mono", r.ref));
      a.appendChild(el("span", "palette-title", r.title || "(no name)"));
      if (r.detail) a.appendChild(el("span", "palette-detail muted small", r.detail));
      var n = options.length;
      a.addEventListener("mousemove", function () { if (active !== n) setActive(n); });
      options.push(a);
      g.appendChild(a);
    });
    if (more) {
      var m = el("a", "palette-item palette-more small", "All matching " + label.toLowerCase());
      m.href = more;
      m.id = "palette-o" + options.length;
      m.setAttribute("role", "option");
      m.tabIndex = -1;
      var k = options.length;
      m.addEventListener("mousemove", function () { if (active !== k) setActive(k); });
      options.push(m);
      g.appendChild(m);
    }
    listEl.appendChild(g);
  }

  function matchPages(q) {
    q = q.toLowerCase();
    var hits = pages.filter(function (p) {
      return (p.title + " " + p.detail).toLowerCase().indexOf(q) !== -1;
    });
    hits.sort(function (a, b) {
      return (a.title.toLowerCase().indexOf(q) === 0 ? 0 : 1) - (b.title.toLowerCase().indexOf(q) === 0 ? 0 : 1);
    });
    return hits.slice(0, 5);
  }

  function note(text) {
    listEl.appendChild(el("p", "palette-note muted small", text));
  }

  // render draws the page matches, then the server's groups once known
  // (groups is null while the request is out).
  function render(q, groups, failed) {
    listEl.textContent = "";
    options = [];
    active = -1;
    shown = groups || !q ? q : null;
    if (!q) {
      note("Type a name or reference, such as a hostname, a container, OPS-12 or CHG-000042.");
      addGroup("Pages", pages.slice(0, 8));
      setActive(0);
      return;
    }
    var p = matchPages(q);
    if (p.length) addGroup("Pages", p);
    if (groups) {
      groups.forEach(function (g) { addGroup(g.label, g.results, g.more ? g.all : ""); });
    }
    if (failed) note("Search failed. Try again, or open all results.");
    else if (!groups) note("Searching…");
    else if (!options.length) note("Nothing you can see matches “" + q + "”.");
    setActive(0);
  }

  function search() {
    var q = input.value.trim();
    allLink.href = base + "/search" + (q ? "?q=" + encodeURIComponent(q) : "");
    if (ctrl) ctrl.abort();
    ctrl = null;
    if (!q) {
      render("", null);
      return;
    }
    render(q, null);
    var mine = ++seq;
    ctrl = typeof AbortController === "function" ? new AbortController() : null;
    fetch(base + "/search.json?q=" + encodeURIComponent(q), {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      signal: ctrl ? ctrl.signal : undefined,
    })
      .then(function (r) {
        if (!r.ok) throw new Error(String(r.status));
        return r.json();
      })
      .then(function (data) {
        if (mine === seq) render(q, data.groups || []);
      })
      .catch(function (e) {
        if (e && e.name === "AbortError") return;
        if (mine === seq) render(q, [], true);
      });
  }

  function open(text) {
    if (dlg.open) {
      input.select();
      return;
    }
    input.value = text || "";
    dlg.showModal();
    input.focus();
    input.select();
    search();
  }

  input.addEventListener("input", function () {
    clearTimeout(timer);
    timer = setTimeout(search, 120);
  });

  input.addEventListener("keydown", function (e) {
    if (e.key === "ArrowDown" || (e.key === "n" && e.ctrlKey)) {
      e.preventDefault();
      setActive(active + 1);
    } else if (e.key === "ArrowUp" || (e.key === "p" && e.ctrlKey)) {
      e.preventDefault();
      setActive(active - 1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      // Before the results for what was typed are in, Enter opens the
      // full results page for it rather than a stale match.
      var q = input.value.trim();
      var o = options[active];
      if (q && (q !== shown || !o)) {
        window.location.href = base + "/search?q=" + encodeURIComponent(q);
        return;
      }
      if (!o) return;
      if (e.ctrlKey || e.metaKey) window.open(o.href, "_blank");
      else window.location.href = o.href;
    }
  });

  // A click outside the box (on the backdrop) closes it.
  dlg.addEventListener("click", function (e) {
    if (e.target === dlg) dlg.close();
  });
  dlg.addEventListener("close", function () {
    clearTimeout(timer);
    if (ctrl) ctrl.abort();
  });

  function typing(t) {
    return t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
  }

  document.addEventListener("keydown", function (e) {
    if ((e.key === "k" || e.key === "K") && (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey) {
      e.preventDefault();
      open(dlg.open ? input.value : "");
    } else if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !typing(e.target) && !dlg.open) {
      e.preventDefault();
      open("");
    }
  });

  // The top bar's box opens the palette instead of taking input itself.
  topInput.addEventListener("focus", function () {
    var v = topInput.value;
    topInput.blur();
    open(v);
  });
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    open(topInput.value);
  });
})();
