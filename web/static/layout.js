// The layout editor (templates/pages/layout.html), no dependencies.
// Without JS the page edits the sections as JSON in a textarea; with it,
// sections and their items are edited here and written back to that
// textarea as JSON when the form is submitted. The server checks
// whatever arrives.
(function () {
  "use strict";

  var form = document.querySelector("[data-layout-form]");
  if (!form) return;
  var root = form.querySelector("[data-layout-editor]");
  var raw = form.querySelector("[data-layout-raw]");
  var textarea = raw.querySelector("textarea");
  var palette, sections;
  try {
    palette = JSON.parse(form.querySelector("[data-layout-palette]").textContent) || [];
    sections = JSON.parse(textarea.value) || [];
  } catch (e) {
    return; // leave the JSON editor
  }

  function key(it) {
    return it.kind + ":" + (it.field || it.group_id || it.field_id);
  }
  var byKey = {};
  palette.forEach(function (p) { byKey[key(p)] = p; });

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "class") e.className = attrs[k];
      else e.setAttribute(k, attrs[k]);
    });
    if (text != null) e.textContent = text;
    return e;
  }

  function button(label, title, fn) {
    var b = el("button", { type: "button", class: "small", title: title || label }, label);
    b.addEventListener("click", function () { fn(); render(); });
    return b;
  }

  function move(arr, i, by) {
    var j = i + by;
    if (j < 0 || j >= arr.length) return;
    var x = arr[i];
    arr[i] = arr[j];
    arr[j] = x;
  }

  // placed lists what the layout already places, so the pickers can say so.
  function placed() {
    var out = {};
    sections.forEach(function (s) { (s.items || []).forEach(function (it) { out[key(it)] = true; }); });
    return out;
  }

  function render() {
    root.textContent = "";
    var used = placed();
    sections.forEach(function (sec, si) {
      sec.items = sec.items || [];
      var box = el("section", { class: "layout-section" });
      var head = el("header");
      var title = el("input", { type: "text", value: sec.title || "", placeholder: "Section title (optional)", "aria-label": "Section title" });
      title.addEventListener("input", function () { sec.title = title.value; });
      var cols = el("select", { "aria-label": "Columns" });
      [1, 2].forEach(function (n) {
        var o = el("option", { value: n }, n === 1 ? "One column" : "Two columns");
        if ((sec.columns || 1) === n) o.selected = true;
        cols.appendChild(o);
      });
      cols.addEventListener("change", function () { sec.columns = +cols.value; });
      var collapsed = el("input", { type: "checkbox" });
      collapsed.checked = !!sec.collapsed;
      collapsed.addEventListener("change", function () { sec.collapsed = collapsed.checked; });
      var cl = el("label", { class: "check" });
      cl.appendChild(collapsed);
      cl.appendChild(document.createTextNode(" Collapsed"));
      head.appendChild(title);
      head.appendChild(cols);
      head.appendChild(cl);
      head.appendChild(button("↑", "Move section up", function () { move(sections, si, -1); }));
      head.appendChild(button("↓", "Move section down", function () { move(sections, si, 1); }));
      head.appendChild(button("Remove", "Remove section", function () { sections.splice(si, 1); }));
      box.appendChild(head);

      var list = el("ul", { class: "layout-items" });
      sec.items.forEach(function (it, ii) {
        var p = byKey[key(it)] || { label: "(deleted)", note: "" };
        var li = el("li");
        li.appendChild(el("span", { class: "kind" }, it.kind));
        var what = el("span", { class: "what" }, p.label);
        if (p.note) {
          what.appendChild(document.createTextNode(" "));
          what.appendChild(el("span", { class: "muted small" }, p.note));
        }
        li.appendChild(what);
        li.appendChild(button("↑", "Move up", function () { move(sec.items, ii, -1); }));
        li.appendChild(button("↓", "Move down", function () { move(sec.items, ii, 1); }));
        li.appendChild(button("×", "Remove", function () { sec.items.splice(ii, 1); }));
        list.appendChild(li);
      });
      box.appendChild(list);

      var add = el("select", { "aria-label": "Add to section" });
      add.appendChild(el("option", { value: "" }, "Add a field or group…"));
      [["core", "Core fields"], ["group", "Field groups"], ["field", "Custom fields"]].forEach(function (g) {
        var og = el("optgroup", { label: g[1] });
        palette.forEach(function (p) {
          if (p.kind !== g[0]) return;
          og.appendChild(el("option", { value: key(p) }, p.label + (used[key(p)] ? " (placed)" : "")));
        });
        if (og.children.length) add.appendChild(og);
      });
      add.addEventListener("change", function () {
        var p = byKey[add.value];
        if (!p) return;
        var it = { kind: p.kind };
        if (p.field) it.field = p.field;
        if (p.group_id) it.group_id = p.group_id;
        if (p.field_id) it.field_id = p.field_id;
        sec.items.push(it);
        render();
      });
      box.appendChild(add);
      root.appendChild(box);
    });
    root.appendChild(button("Add a section", "", function () { sections.push({ title: "", columns: 1, collapsed: false, items: [] }); }));
  }

  form.addEventListener("submit", function () {
    textarea.value = JSON.stringify(sections);
  });
  raw.hidden = true;
  root.hidden = false;
  root.classList.add("layout-editor");
  render();
})();
