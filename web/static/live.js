// Live status (docs/architecture.md §6): a page that shows changing status
// names a URL with data-live-src and marks its changing regions with
// data-live and an id. While the tab is visible this fetches that URL every
// data-live-every seconds (30 by default) and swaps each region whose HTML
// changed. A region holding the focus or a text selection is left alone
// until the next round. Without JS the page is as fresh as its last load.
(function () {
  "use strict";
  var root = document.querySelector("[data-live-src]");
  if (!root || !window.fetch || !window.DOMParser) return;
  var src = root.getAttribute("data-live-src");
  var every = (parseInt(root.getAttribute("data-live-every"), 10) || 30) * 1000;
  var note = document.getElementById("live-note");
  var timer = null, busy = false, stopped = false, last = Date.now();

  function say(text) {
    if (!note) return;
    note.textContent = text;
    note.hidden = !text;
  }

  // inUse reports whether the user is working in el: focused on a control
  // or link in it, or selecting its text.
  function inUse(el) {
    var a = document.activeElement;
    if (a && a !== document.body && el.contains(a)) return true;
    var sel = window.getSelection && window.getSelection();
    return !!(sel && !sel.isCollapsed && sel.rangeCount && el.contains(sel.getRangeAt(0).commonAncestorContainer));
  }

  function swap(doc) {
    var els = document.querySelectorAll("[data-live][id]");
    for (var i = 0; i < els.length; i++) {
      var el = els[i], next = doc.getElementById(el.id);
      if (!next || next.outerHTML === el.outerHTML || inUse(el)) continue;
      el.replaceWith(document.adoptNode(next));
    }
  }

  function schedule() {
    clearTimeout(timer);
    if (!stopped && document.visibilityState === "visible") timer = setTimeout(poll, every);
  }

  function poll() {
    if (busy || stopped) return;
    busy = true;
    fetch(src, { headers: { "X-Baseline-Live": "1" }, credentials: "same-origin", cache: "no-store", redirect: "manual" })
      .then(function (res) {
        if (res.status === 401 || res.type === "opaqueredirect") {
          stopped = true;
          say("Live updates stopped: your session has ended. Reload the page to sign in again.");
          return;
        }
        if (!res.ok) throw new Error(res.status);
        return res.text().then(function (html) {
          swap(new DOMParser().parseFromString(html, "text/html"));
          last = Date.now();
          say("");
        });
      })
      .catch(function () { say("Live updates paused: Baseline can't be reached. Retrying."); })
      .then(function () { busy = false; schedule(); });
  }

  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState !== "visible") { clearTimeout(timer); return; }
    if (Date.now() - last >= every) poll(); else schedule();
  });
  schedule();
})();
