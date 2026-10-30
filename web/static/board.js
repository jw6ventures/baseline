// Boards (web/templates/pages/board.html), no dependencies. Dragging a card
// splits each column into one drop zone per transition of the card that
// leads into it; zones whose conditions the user fails show greyed out and
// take no drop, and columns no transition leads into fade. Dropping posts
// the transition, after a small form when its screen asks for something.
// Without this script each card's Move menu does the same.
(function () {
  "use strict";

  var board = document.querySelector("[data-board]");
  if (!board) return;
  var moveForm = document.getElementById("board-move");
  var dialog = document.getElementById("board-screen");
  var dragged = null;

  // field(form, "item") is HTMLFormControlsCollection.item, not the field.
  function field(form, name) {
    return form.elements.namedItem(name);
  }

  function targets(card) {
    try {
      return JSON.parse(card.dataset.targets || "[]");
    } catch (e) {
      return [];
    }
  }

  function commit(card, t) {
    if (t.screen && t.screen.length) {
      openScreen(card, t);
      return;
    }
    field(moveForm, "item").value = card.dataset.item;
    field(moveForm, "transition").value = t.id;
    moveForm.submit();
  }

  // The transition screen: only the fields the transition asks for are
  // shown and sent. Cancelling leaves the card where it was.
  function openScreen(card, t) {
    var form = dialog.querySelector("form");
    field(form, "item").value = card.dataset.item;
    field(form, "transition").value = t.id;
    dialog.querySelector("[data-screen-title]").textContent = card.dataset.ref + ": " + t.name + " → " + t.to;
    dialog.querySelectorAll("[data-screen]").forEach(function (field) {
      var on = t.screen.indexOf(field.dataset.screen) >= 0;
      field.hidden = !on;
      field.querySelectorAll("select, textarea, input").forEach(function (el) {
        el.disabled = !on;
      });
    });
    var assignee = field(form, "assignee");
    assignee.value = card.dataset.assignee || "";
    if (assignee.value !== (card.dataset.assignee || "")) assignee.value = "";
    field(form, "comment").value = "";
    field(form, "resolution").selectedIndex = 0;
    dialog.showModal();
    var first = dialog.querySelector("[data-screen]:not([hidden]) select, [data-screen]:not([hidden]) textarea");
    if (first) first.focus();
  }

  dialog.querySelector("[data-screen-cancel]").addEventListener("click", function () {
    dialog.close();
  });

  function showZones(card) {
    var ts = targets(card);
    board.classList.add("dragging");
    board.querySelectorAll(".board-col").forEach(function (col) {
      var index = parseInt(col.dataset.col, 10);
      var mine = ts.filter(function (t) { return t.col === index; });
      if (!mine.length) {
        col.classList.add("no-drop");
        return;
      }
      var zones = document.createElement("div");
      zones.className = "board-zones";
      mine.forEach(function (t) {
        var zone = document.createElement("div");
        zone.className = "board-zone" + (t.ok ? "" : " denied");
        zone.textContent = t.name + " → " + t.to;
        if (!t.ok) zone.title = "You may not run this transition";
        zone.boardTarget = t;
        zones.appendChild(zone);
      });
      col.appendChild(zones);
    });
  }

  function clearZones() {
    board.classList.remove("dragging");
    board.querySelectorAll(".board-zones").forEach(function (z) { z.remove(); });
    board.querySelectorAll(".no-drop").forEach(function (c) { c.classList.remove("no-drop"); });
    board.querySelectorAll(".board-card.dragged").forEach(function (c) { c.classList.remove("dragged"); });
  }

  board.addEventListener("dragstart", function (e) {
    var card = e.target.closest && e.target.closest(".board-card");
    if (!card) return;
    dragged = card;
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", card.dataset.ref);
    card.classList.add("dragged");
    // Zones appear after the browser has taken its drag image.
    setTimeout(function () { if (dragged === card) showZones(card); }, 0);
  });

  board.addEventListener("dragend", function () {
    dragged = null;
    clearZones();
  });

  function zoneAt(e) {
    var zone = e.target.closest && e.target.closest(".board-zone");
    return zone && !zone.classList.contains("denied") ? zone : null;
  }

  board.addEventListener("dragover", function (e) {
    var zone = zoneAt(e);
    if (!zone || !dragged) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    board.querySelectorAll(".board-zone.over").forEach(function (z) { if (z !== zone) z.classList.remove("over"); });
    zone.classList.add("over");
  });

  board.addEventListener("dragleave", function (e) {
    var zone = zoneAt(e);
    if (zone && !zone.contains(e.relatedTarget)) zone.classList.remove("over");
  });

  board.addEventListener("drop", function (e) {
    var zone = zoneAt(e);
    if (!zone || !dragged) return;
    e.preventDefault();
    var card = dragged, t = zone.boardTarget;
    dragged = null;
    clearZones();
    commit(card, t);
  });

  // The Move menu's transitions with a screen open the same form here
  // instead of the item's page.
  board.addEventListener("click", function (e) {
    var link = e.target.closest("[data-move]");
    if (!link) return;
    var card = link.closest(".board-card");
    var t = targets(card).filter(function (x) { return x.id === link.dataset.move; })[0];
    if (!t) return;
    e.preventDefault();
    link.closest("details").open = false;
    openScreen(card, t);
  });
})();
