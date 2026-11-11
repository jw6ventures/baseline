// The list engine's helpers (web/templates/list_parts.html), no
// dependencies besides the vendored htmx. Every list works without them:
// these add the cell menu, operator narrowing in the condition builder,
// select-all and auto-submitting selects. Handlers are delegated from the
// document, so they keep working after htmx swaps the list.
(function () {
  "use strict";

  // Cell menu: clicking a cell offers "Show matching" and "Filter out",
  // which add a condition on the cell's value to every OR group.
  var menu = null;
  function closeMenu() {
    if (menu) menu.remove();
    menu = null;
  }

  function listURL(root, cond) {
    var params = new URLSearchParams(root.dataset.query || "");
    params.delete("page");
    params.delete("list");
    var groups = Math.max(parseInt(root.dataset.groups || "0", 10), 1);
    for (var g = 0; g < groups; g++) {
      params.append("cf", cond.field);
      params.append("co", cond.op);
      params.append("cv", cond.value || "");
      params.append("cg", String(g));
    }
    return root.dataset.path + "?" + params.toString();
  }

  function openMenu(td, value, x, y) {
    closeMenu();
    var root = td.closest("#list");
    if (!root) return;
    var field = td.dataset.f;
    menu = document.createElement("div");
    menu.className = "cell-menu";
    menu.setAttribute("role", "menu");
    [["Show matching", td.dataset.op], ["Filter out", td.dataset.nop]].forEach(function (item) {
      var a = document.createElement("a");
      a.textContent = item[0];
      a.setAttribute("role", "menuitem");
      a.href = listURL(root, { field: field, op: item[1], value: value });
      menu.appendChild(a);
    });
    root.appendChild(menu);
    if (window.htmx) window.htmx.process(menu); // boosted like the other links
    var box = root.getBoundingClientRect();
    menu.style.left = Math.max(0, x - box.left) + "px";
    menu.style.top = (y - box.top + 4) + "px";
    menu.querySelector("a").focus();
  }

  document.addEventListener("click", function (e) {
    if (menu && !menu.contains(e.target)) closeMenu();
    var td = e.target.closest("td[data-f]");
    if (!td || e.target.closest("a, button, input, select, form")) return;
    var value = td.dataset.v || "";
    var tag = e.target.closest("[data-v]");
    if (tag && td.contains(tag)) value = tag.dataset.v;
    var needsValue = ["empty", "not_empty", "true", "false"].indexOf(td.dataset.op) < 0;
    if (needsValue && value === "") return; // a tags cell, clicked beside its tags
    openMenu(td, value, e.clientX, e.clientY);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeMenu();
  });
  document.addEventListener("htmx:beforeSwap", closeMenu);

  // The list is boosted: a link or form in it fetches the next page and
  // swaps in that page's #list. A row's link leads to a record page, which
  // has none, so open it as a whole page. Any other response without a
  // #list (an error) is loaded as a whole page too, rather than leaving an
  // empty list under the new URL.
  document.addEventListener("htmx:beforeRequest", function (e) {
    var a = e.detail.elt;
    if (!e.detail.boosted || a.tagName !== "A" || !a.closest("#list td")) return;
    e.preventDefault();
    window.location.assign(a.href);
  });
  document.addEventListener("htmx:beforeSwap", function (e) {
    var d = e.detail;
    if (!d.boosted || !d.target || d.target.id !== "list") return;
    var doc = new DOMParser().parseFromString(d.xhr.responseText || "", "text/html");
    if (doc.getElementById("list")) return;
    d.shouldSwap = false;
    window.location.assign(d.xhr.responseURL || d.pathInfo.finalRequestPath);
  });

  // Builder: show only the operators that fit the chosen field, and a
  // select of values for enum fields.
  function fitRow(row) {
    var field = row.querySelector("[data-cond-field]");
    var op = row.querySelector("[data-cond-op]");
    if (!field || !op) return;
    var opt = field.options[field.selectedIndex];
    var type = opt && opt.dataset.type;
    var firstFit = null;
    Array.prototype.forEach.call(op.options, function (o) {
      var fits = !type || (" " + o.dataset.types + " ").indexOf(" " + type + " ") >= 0;
      o.hidden = !fits;
      o.disabled = !fits;
      if (fits && !firstFit) firstFit = o;
    });
    if (op.selectedOptions[0] && op.selectedOptions[0].disabled && firstFit) firstFit.selected = true;

    var value = row.querySelector("[data-cond-value]");
    var choices = opt && opt.dataset.options ? JSON.parse(opt.dataset.options) : null;
    var current = value.value;
    var next;
    if (choices) {
      next = document.createElement("select");
      choices.forEach(function (c) {
        var o = document.createElement("option");
        o.value = c.v;
        o.textContent = c.l;
        if (c.v === current) o.selected = true;
        next.appendChild(o);
      });
    } else if (value.tagName === "SELECT") {
      next = document.createElement("input");
      next.placeholder = "value";
    } else {
      return;
    }
    next.name = "cv";
    next.setAttribute("aria-label", "Value");
    next.setAttribute("data-cond-value", "");
    value.replaceWith(next);
  }

  document.addEventListener("change", function (e) {
    var t = e.target;
    if (t.matches("[data-cond-field]")) fitRow(t.closest(".cond-row"));
    if (t.matches("[data-autosubmit]") && t.form) t.form.requestSubmit();
    if (t.matches("[data-select-all]")) {
      var table = t.closest("table");
      table.querySelectorAll('tbody input[type=checkbox][name=id], tbody input[type=checkbox][data-row]').forEach(function (box) {
        box.checked = t.checked;
      });
    }
    if (t.matches("[data-bulk-action]")) fitBulk(t.form);
  });

  // Bulk form: offer only the values of the chosen action.
  function fitBulk(form) {
    var action = form.querySelector("[data-bulk-action]").value;
    var value = form.querySelector("select[name=value]");
    var first = null;
    value.querySelectorAll("optgroup").forEach(function (g) {
      var on = g.dataset.action === action;
      g.hidden = !on;
      g.disabled = !on;
      if (on && !first) first = g.querySelector("option");
    });
    if (value.selectedOptions[0] && value.selectedOptions[0].parentElement.disabled && first) first.selected = true;
    // An action without values (acknowledge) needs no second select.
    value.hidden = value.disabled = !first;
  }

  // Quick search: the list follows the box as you type, after a short
  // pause. The box keeps its id so htmx gives it focus back after the swap.
  var searchTimer = null;
  document.addEventListener("input", function (e) {
    var t = e.target;
    if (!t.matches("[data-live-search]") || !t.form) return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function () {
      if (t.value === t.dataset.sent) return;
      t.dataset.sent = t.value;
      t.form.requestSubmit();
    }, 350);
  });

  function init(root) {
    root.querySelectorAll(".cond-row").forEach(function (row) {
      var field = row.querySelector("[data-cond-field]");
      if (field && field.value === "") fitRow(row);
    });
    root.querySelectorAll("form.bulk").forEach(fitBulk);
  }
  init(document);
  document.addEventListener("htmx:afterSettle", function (e) { init(e.target); });
})();
