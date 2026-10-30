// Form helpers, no dependencies. Without JS the pages still work: filters
// need their button, and pickers list every row.
//
// [data-autosubmit] submits its form when it changes.
//
// select[data-switch] shows the parts of its form that fit the option
// chosen: elements [data-switch-for=NAME] whose data-kind is the option's
// data-kind (the first part's kind when the option has none). The fields of
// hidden parts are disabled, so they are neither required nor sent.
//
// [data-picker] is a table of rows to tick (stacks, containers) with
// filters above it: an element [data-filter="text"] matches the rows'
// data-text, and any other [data-filter=KEY] matches their data-KEY ("none"
// matches an empty value; a checkbox matches rows whose data-KEY is "1").
// Ticked rows always show. [data-picker-all] ticks every row shown and
// [data-picker-count] says how many are ticked. The filters start hidden
// and are shown here.
(function () {
  "use strict";

  document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () {
      if (el.form) el.form.requestSubmit ? el.form.requestSubmit() : el.form.submit();
    });
  });

  document.querySelectorAll("select[data-switch]").forEach(function (sel) {
    var parts = document.querySelectorAll('[data-switch-for="' + sel.name + '"]');
    if (!parts.length) return;
    var fields = [];
    parts.forEach(function (part) {
      part.querySelectorAll("input, select, textarea, button").forEach(function (f) {
        fields.push({ el: f, part: part, locked: f.disabled });
      });
    });
    function apply() {
      var opt = sel.options[sel.selectedIndex];
      var kind = (opt && opt.dataset.kind) || parts[0].dataset.kind;
      parts.forEach(function (part) { part.hidden = part.dataset.kind !== kind; });
      fields.forEach(function (f) { f.el.disabled = f.locked || f.part.hidden; });
    }
    sel.addEventListener("change", apply);
    apply();
  });

  document.querySelectorAll("[data-picker]").forEach(function (picker) {
    var filters = picker.querySelectorAll("[data-filter]");
    var rows = picker.querySelectorAll("tr[data-text]");
    var count = picker.querySelector("[data-picker-count]");
    var empty = picker.querySelector("[data-picker-empty]");
    picker.querySelectorAll("[data-picker-controls]").forEach(function (el) { el.hidden = false; });

    function ticked(row) {
      var box = row.querySelector("input[type=checkbox], input[type=radio]");
      return box && box.checked;
    }

    function matches(row) {
      for (var i = 0; i < filters.length; i++) {
        var f = filters[i], key = f.dataset.filter;
        if (key === "text") {
          var words = f.value.toLowerCase().trim().split(/\s+/);
          var text = row.dataset.text.toLowerCase();
          for (var j = 0; j < words.length; j++) {
            if (words[j] && text.indexOf(words[j]) < 0) return false;
          }
        } else if (f.type === "checkbox") {
          if (f.checked && row.dataset[key] !== "1") return false;
        } else if (f.value) {
          var v = row.dataset[key] || "";
          if (f.value === "none" ? v !== "" : v !== f.value) return false;
        }
      }
      return true;
    }

    function update() {
      var shown = 0, n = 0;
      rows.forEach(function (row) {
        var on = ticked(row);
        var show = on || matches(row);
        row.hidden = !show;
        if (show) shown++;
        if (on) n++;
      });
      if (count) count.textContent = n === 1 ? "1 selected" : n + " selected";
      if (empty) empty.hidden = shown > 0;
    }

    filters.forEach(function (f) {
      f.addEventListener("input", update);
      f.addEventListener("change", update);
      // Enter in a filter shouldn't submit the change form.
      f.addEventListener("keydown", function (e) { if (e.key === "Enter") e.preventDefault(); });
    });
    picker.addEventListener("change", function (e) {
      if (!e.target.dataset.filter) update();
    });
    var all = picker.querySelector("[data-picker-all]");
    if (all) {
      all.addEventListener("click", function () {
        rows.forEach(function (row) {
          var box = row.querySelector("input[type=checkbox]:not(:disabled)");
          if (box && !row.hidden) box.checked = true;
        });
        update();
      });
    }
    var none = picker.querySelector("[data-picker-none]");
    if (none) {
      none.addEventListener("click", function () {
        rows.forEach(function (row) {
          var box = row.querySelector("input[type=checkbox]");
          if (box) box.checked = false;
        });
        update();
      });
    }
    update();
  });
})();
