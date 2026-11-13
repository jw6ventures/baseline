// The toolbar above a log (logview_parts.html, on the container and pod log
// pages): filters the lines to those containing some text and marks the
// matches, switches line wrapping, downloads the lines as a file and jumps
// to the latest line. It works on <pre data-logview>, whose children are one
// <span> per line; a log given as plain text is split into lines first.
// logs.js, which streams a followed log, announces the lines it adds with a
// "logview:lines" event so they are filtered too and kept in view.
(function () {
  "use strict";
  var pre = document.querySelector("pre[data-logview]");
  var bar = document.querySelector("[data-logview-bar]");
  if (!pre || !bar) return;
  var q = bar.querySelector("[data-logview-q]");
  var count = bar.querySelector("[data-logview-count]");
  var wrap = bar.querySelector("[data-logview-wrap]");
  var download = bar.querySelector("[data-logview-download]");
  var latest = document.querySelector("[data-logview-latest]");

  // A log given as one text node becomes a span per line.
  if (!pre.firstElementChild && pre.textContent) {
    var parts = pre.textContent.split("\n");
    if (parts[parts.length - 1] === "") parts.pop();
    var frag = document.createDocumentFragment();
    parts.forEach(function (t) {
      var span = document.createElement("span");
      span.textContent = t + "\n";
      frag.appendChild(span);
    });
    pre.textContent = "";
    pre.appendChild(frag);
  }

  // Lines are the spans that aren't notes such as "(empty)" or "Waiting…".
  function isLine(n) {
    return n.nodeType === 1 && !n.classList.contains("info");
  }
  function lines() {
    return Array.prototype.filter.call(pre.children, isLine);
  }
  function text(span) {
    if (span.logText === undefined) span.logText = span.textContent;
    return span.logText;
  }

  var needle = "";
  // Shows or hides one line for the current filter, marking the matches.
  function apply(span) {
    var t = text(span);
    if (!needle) {
      if (span.marked) { span.textContent = t; span.marked = false; }
      span.classList.remove("logview-miss");
      return true;
    }
    var lower = t.toLowerCase();
    var at = lower.indexOf(needle);
    if (at < 0) {
      if (span.marked) { span.textContent = t; span.marked = false; }
      span.classList.add("logview-miss");
      return false;
    }
    span.classList.remove("logview-miss");
    span.textContent = "";
    var from = 0;
    while (at >= 0) {
      if (at > from) span.appendChild(document.createTextNode(t.slice(from, at)));
      var mark = document.createElement("mark");
      mark.textContent = t.slice(at, at + needle.length);
      span.appendChild(mark);
      from = at + needle.length;
      at = lower.indexOf(needle, from);
    }
    if (from < t.length) span.appendChild(document.createTextNode(t.slice(from)));
    span.marked = true;
    return true;
  }

  var total = 0, shown = 0;
  function showCount() {
    var noun = total === 1 ? " line" : " lines";
    if (!needle) count.textContent = total + noun;
    else if (!shown) count.textContent = "No lines match (of " + total + ")";
    else count.textContent = shown + " of " + total + noun + " match";
    download.textContent = needle ? "Download matches" : "Download";
  }
  function filterAll() {
    var ls = lines();
    total = ls.length;
    shown = 0;
    ls.forEach(function (s) { if (apply(s)) shown++; });
    showCount();
    keepInView();
  }

  var timer = null;
  q.addEventListener("input", function () {
    clearTimeout(timer);
    timer = setTimeout(function () {
      needle = q.value.toLowerCase();
      filterAll();
    }, 120);
  });
  q.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && q.value) {
      e.preventDefault();
      q.value = "";
      needle = "";
      filterAll();
    }
  });
  // "/" focuses the filter, as in many log viewers.
  document.addEventListener("keydown", function (e) {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    var t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    e.preventDefault();
    q.focus();
  });

  // Wrapping long lines is on by default and remembered per browser.
  var wrapKey = "baseline.logview.wrap";
  var wrapOn = true;
  try { wrapOn = localStorage.getItem(wrapKey) !== "0"; } catch (e) { /* storage blocked */ }
  function setWrap(on) {
    wrap.checked = on;
    pre.classList.toggle("logview-nowrap", !on);
  }
  setWrap(wrapOn);
  wrap.addEventListener("change", function () {
    setWrap(wrap.checked);
    try { localStorage.setItem(wrapKey, wrap.checked ? "1" : "0"); } catch (e) { /* storage blocked */ }
  });

  // Download the lines read so far, or only the matches while filtering.
  download.addEventListener("click", function () {
    var out = lines().filter(function (s) { return !needle || !s.classList.contains("logview-miss"); })
      .map(text).join("");
    var stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*/, "");
    var name = (pre.dataset.logview || "log").replace(/[^\w.-]+/g, "_") + "-" + stamp + ".log";
    var url = URL.createObjectURL(new Blob([out], { type: "text/plain;charset=utf-8" }));
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  });

  // Jump to latest: shown while the end of the log is below the window.
  // While it's in view, new lines keep it in view.
  var stuck = true, unseen = 0;
  function endInView() {
    return pre.getBoundingClientRect().bottom <= window.innerHeight + 40;
  }
  function showLatest() {
    latest.hidden = stuck;
    latest.textContent = unseen ? "Jump to latest (" + unseen + " new)" : "Jump to latest";
  }
  function toEnd() {
    window.scrollTo(0, document.documentElement.scrollHeight);
  }
  function keepInView() {
    if (stuck) toEnd();
    showLatest();
  }
  window.addEventListener("scroll", function () {
    stuck = endInView();
    if (stuck) unseen = 0;
    showLatest();
  }, { passive: true });
  window.addEventListener("resize", function () { stuck = endInView(); showLatest(); });
  latest.addEventListener("click", function () {
    stuck = true;
    unseen = 0;
    toEnd();
    showLatest();
  });

  // New lines from a followed log.
  pre.addEventListener("logview:lines", function (e) {
    var added = (e.detail && e.detail.nodes) || [];
    added.forEach(function (s) {
      if (!isLine(s)) return;
      if (apply(s) && !stuck) unseen++;
    });
    // Old lines are trimmed from the top, so count again.
    var ls = lines();
    total = ls.length;
    if (needle) shown = ls.filter(function (s) { return !s.classList.contains("logview-miss"); }).length;
    else shown = total;
    showCount();
    keepInView();
  });

  bar.hidden = false;
  stuck = endInView();
  filterAll();
})();
