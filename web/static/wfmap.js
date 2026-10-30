// The workflow diagram on the workflow page: a version's statuses as boxes
// and its transitions as arrows, on the canvas core in mapcore.js. A
// transition from any status hangs as a dashed tag over the status it leads
// to. On a draft, drag a status to move it (positions are saved), drag from
// the + on its right edge (or shift-drag it) to another status to draw a
// transition, and double-click empty space or use Add status to add one.
// Adding and deleting go through the page's own forms, so the server checks
// them as it checks the tables below.
(function () {
  "use strict";
  var root = document.getElementById("wfmap");
  var dataEl = document.getElementById("wfmap-data");
  if (!root || !dataEl || !window.baselineMap || !window.requestAnimationFrame) return;
  var data;
  try { data = JSON.parse(dataEl.textContent); } catch (e) { return; }
  root.hidden = false;

  var base = root.dataset.base;
  var draft = !!data.draft;
  var stage = root.querySelector(".map-stage");
  var canvas = stage.querySelector("canvas");
  var info = stage.querySelector(".map-info");
  var statusEl = root.querySelector(".map-status");
  var theme = baselineMap.theme();

  var NODE_H = 36, MIN_W = 110, COL = 230, ROW = 100, SNAP = 10, HANDLE = 7;
  var catLabel = {};
  data.categories.forEach(function (c) { catLabel[c.key] = c.label; });

  // ---- Data ------------------------------------------------------------
  var nodes = data.statuses.map(function (s) {
    return { id: s.id, key: s.key, name: s.name, category: s.category, initial: s.initial,
      x: s.x, y: s.y, placed: s.x != null && s.y != null };
  });
  var byId = {};
  nodes.forEach(function (n) { byId[n.id] = n; });
  var edges = data.transitions.filter(function (t) { return byId[t.to] && (!t.from || byId[t.from]); })
    .map(function (t) { return Object.assign({ s: t.from ? byId[t.from] : null, t: byId[t.to] }, t); });

  var measure = document.createElement("canvas").getContext("2d");
  function nodeFont() { return "600 13px " + theme.font; }
  function sizeNodes() {
    measure.font = nodeFont();
    nodes.forEach(function (n) {
      n.hw = Math.max(MIN_W, Math.ceil(measure.measureText(n.name).width) + 30) / 2;
      n.hh = NODE_H / 2;
    });
  }

  // ---- Layout ----------------------------------------------------------
  // layered puts statuses in columns by how many transitions they are from
  // the initial one; those only reachable from any status come last.
  function layered(list) {
    var depth = {};
    var start = nodes.filter(function (n) { return n.initial; })[0] || nodes[0];
    if (start) {
      depth[start.id] = 0;
      var queue = [start];
      while (queue.length) {
        var n = queue.shift();
        edges.forEach(function (e) {
          if (e.s === n && depth[e.t.id] == null) { depth[e.t.id] = depth[n.id] + 1; queue.push(e.t); }
        });
      }
    }
    var maxD = 0;
    Object.keys(depth).forEach(function (k) { maxD = Math.max(maxD, depth[k]); });
    var cols = {};
    nodes.forEach(function (n) {
      var d = depth[n.id] != null ? depth[n.id] : maxD + 1;
      (cols[d] = cols[d] || []).push(n);
    });
    var out = {};
    Object.keys(cols).forEach(function (d) {
      var col = cols[d];
      col.forEach(function (n, i) { out[n.id] = { x: d * COL, y: (i - (col.length - 1) / 2) * ROW }; });
    });
    return list.map(function (n) { return out[n.id]; });
  }
  function placeUnplaced() {
    var todo = nodes.filter(function (n) { return !n.placed; });
    if (!todo.length) return;
    var placed = nodes.filter(function (n) { return n.placed; });
    var pts = layered(todo);
    var dx = 0, dy = 0;
    if (placed.length) {
      // Below what is already placed, keeping their columns.
      var b = bounds(placed), y0 = Infinity;
      pts.forEach(function (p) { y0 = Math.min(y0, p.y); });
      dx = b.x0; dy = b.y1 + ROW - y0;
    }
    todo.forEach(function (n, i) { n.x = pts[i].x + dx; n.y = pts[i].y + dy; });
  }
  function bounds(list) {
    var b = { x0: Infinity, y0: Infinity, x1: -Infinity, y1: -Infinity };
    list.forEach(function (n) {
      b.x0 = Math.min(b.x0, n.x - n.hw); b.x1 = Math.max(b.x1, n.x + n.hw);
      b.y0 = Math.min(b.y0, n.y - n.hh - (anyInto(n).length ? 60 : 0)); b.y1 = Math.max(b.y1, n.y + n.hh);
      if (n.initial) b.x0 = Math.min(b.x0, n.x - n.hw - 50);
    });
    return b;
  }

  var saveTimer = 0, unsaved = {};
  function save(list) {
    if (!draft) return;
    list.forEach(function (n) { unsaved[n.id] = [Math.round(n.x), Math.round(n.y)]; n.placed = true; });
    clearTimeout(saveTimer);
    saveTimer = setTimeout(function () {
      var body = unsaved;
      unsaved = {};
      fetch(base + "/layout", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
      }).then(function (r) {
        if (r.status === 409) throw new Error("this draft was published or discarded; reload the page");
        if (!r.ok) throw new Error(r.status + " " + r.statusText);
        say("");
      }).catch(function (e) { say("Couldn't save the layout: " + e.message); });
    }, 400);
  }
  function say(msg) { statusEl.textContent = msg; statusEl.hidden = !msg; }

  // ---- Geometry --------------------------------------------------------
  // edgeBox clips the line from n's centre towards (tx, ty) at its box.
  function clip(n, tx, ty, pad) {
    var dx = tx - n.x, dy = ty - n.y;
    var t = Math.min((n.hw + pad) / Math.abs(dx || 1e-9), (n.hh + pad) / Math.abs(dy || 1e-9));
    return { x: n.x + dx * t, y: n.y + dy * t };
  }
  // anyInto lists the transitions from any status into n.
  function anyInto(n) { return edges.filter(function (e) { return !e.s && e.t === n; }); }

  // route works out each transition's curve: one between two statuses is
  // straight unless it would cross another status, and transitions between
  // the same two statuses bend apart.
  function curve(e, off) {
    var a = e.s.id < e.t.id ? e.s : e.t, b = a === e.s ? e.t : e.s;
    var dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
    var mx = (a.x + b.x) / 2 - dy / len * off, my = (a.y + b.y) / 2 + dx / len * off;
    // A quadratic curve through (mx, my) at its middle.
    var cx = 2 * mx - (e.s.x + e.t.x) / 2, cy = 2 * my - (e.s.y + e.t.y) / 2;
    var p0 = clip(e.s, cx, cy, 2), p2 = clip(e.t, cx, cy, 4);
    return { p0: p0, c: { x: cx, y: cy }, p2: p2, mid: { x: 0.25 * p0.x + 0.5 * cx + 0.25 * p2.x, y: 0.25 * p0.y + 0.5 * cy + 0.25 * p2.y } };
  }
  function crosses(e, g) {
    for (var i = 1; i < 20; i++) {
      var p = at(g, i / 20);
      for (var j = 0; j < nodes.length; j++) {
        var n = nodes[j];
        if (n !== e.s && n !== e.t && Math.abs(p.x - n.x) <= n.hw + 8 && Math.abs(p.y - n.y) <= n.hh + 8) return true;
      }
    }
    return false;
  }
  function at(g, t) {
    var u = 1 - t;
    if (!g.c) return { x: g.p0.x + (g.p2.x - g.p0.x) * t, y: g.p0.y + (g.p2.y - g.p0.y) * t };
    return { x: u * u * g.p0.x + 2 * u * t * g.c.x + t * t * g.p2.x, y: u * u * g.p0.y + 2 * u * t * g.c.y + t * t * g.p2.y };
  }
  var BENDS = [0, 70, -70, 120, -120, 180, -180];
  function route() {
    var pairs = {};
    edges.forEach(function (e) {
      if (!e.s) return;
      var k = e.s.id < e.t.id ? e.s.id + "|" + e.t.id : e.t.id + "|" + e.s.id;
      (pairs[k] = pairs[k] || []).push(e);
    });
    Object.keys(pairs).forEach(function (k) {
      var list = pairs[k];
      for (var b = 0; b < BENDS.length; b++) {
        var clear = true;
        list.forEach(function (e, i) {
          e.geo = curve(e, BENDS[b] + (i - (list.length - 1) / 2) * 34);
          if (crosses(e, e.geo)) clear = false;
        });
        if (clear) break;
      }
      if (b === BENDS.length) list.forEach(function (e, i) { e.geo = curve(e, (i - (list.length - 1) / 2) * 34); });
    });
    nodes.forEach(function (n) {
      var list = anyInto(n);
      list.forEach(function (e, i) {
        var x = n.x + (i - (list.length - 1) / 2) * 140, y = n.y - n.hh - 48;
        e.geo = { tag: { x: x, y: y }, p0: { x: x, y: y + 11 }, p2: { x: n.x + (x - n.x) * 0.3, y: n.y - n.hh - 4 } };
        e.geo.mid = e.geo.tag;
      });
    });
  }

  // ---- Drawing ---------------------------------------------------------
  var selected = null, hover = null, connect = null, popTarget = null;
  function catColors(c) {
    if (c === "done") return { fill: theme.okBg, line: theme.ok, text: theme.ok };
    if (c === "in_progress") return { fill: theme.warnBg, line: theme.warn, text: theme.warn };
    return { fill: theme.codeBg, line: theme.muted, text: theme.text };
  }
  function roundBox(c, x, y, w, h, r) {
    c.beginPath();
    if (c.roundRect) c.roundRect(x, y, w, h, r); else c.rect(x, y, w, h);
  }
  function hot(e) {
    var f = selected || hover;
    return f && (f === e || (f.kind === "status" && (e.s === f.n || e.t === f.n)));
  }
  function handlePoint(n) { return { x: n.x + n.hw, y: n.y }; }
  function handleNode() {
    if (!draft || connect || popTarget) return null;
    if (hover && hover.kind === "status") return hover.n;
    if (hover && hover.kind === "handle") return hover.n;
    if (selected && selected.kind === "status") return selected.n;
    return null;
  }

  function paint(c, w, h, px, v) {
    c.setTransform(px, 0, 0, px, 0, 0);
    c.fillStyle = theme.surface;
    c.fillRect(0, 0, w, h);
    if (!nodes.length) return;
    c.setTransform(px * v.k, 0, 0, px * v.k, px * v.x, px * v.y);
    route();
    c.lineCap = "round";
    c.lineJoin = "round";

    // Transitions, then their names on top.
    edges.forEach(function (e) {
      var g = e.geo, on = hot(e);
      c.strokeStyle = c.fillStyle = on ? theme.accent : theme.muted;
      c.lineWidth = on ? 2.2 : 1.4;
      c.setLineDash(e.s ? [] : [5, 4]);
      c.beginPath();
      c.moveTo(g.p0.x, g.p0.y);
      if (g.c) c.quadraticCurveTo(g.c.x, g.c.y, g.p2.x, g.p2.y); else c.lineTo(g.p2.x, g.p2.y);
      c.stroke();
      c.setLineDash([]);
      var from = g.c || g.p0;
      baselineMap.arrowHead(c, g.p2.x, g.p2.y, Math.atan2(g.p2.y - from.y, g.p2.x - from.x), on ? 10 : 8);
    });
    c.font = "11.5px " + theme.font;
    c.textAlign = "center";
    c.textBaseline = "middle";
    var taken = nodes.map(function (n) { return { x0: n.x - n.hw, y0: n.y - n.hh, x1: n.x + n.hw, y1: n.y + n.hh }; });
    edges.forEach(function (e) {
      var g = e.geo, on = hot(e), sel = selected === e;
      var text = e.name.length > 26 ? e.name.slice(0, 25) + "…" : e.name;
      var tw = c.measureText(text).width + 12, th = 20;
      // Along the curve, the first place the name doesn't cover another.
      var spots = g.c ? [0.5, 0.38, 0.62, 0.28, 0.72] : [0.5];
      for (var i = 0; i < spots.length; i++) {
        var m = spots[i] === 0.5 ? g.mid : at(g, spots[i]);
        e.box = { x0: m.x - tw / 2, y0: m.y - th / 2, x1: m.x + tw / 2, y1: m.y + th / 2 };
        if (!taken.some(function (b) { return overlap(b, e.box); })) break;
      }
      if (i === spots.length) e.box = { x0: g.mid.x - tw / 2, y0: g.mid.y - th / 2, x1: g.mid.x + tw / 2, y1: g.mid.y + th / 2 };
      taken.push(e.box);
      roundBox(c, e.box.x0, e.box.y0, tw, th, e.s ? 4 : 10);
      c.fillStyle = theme.surface;
      c.fill();
      c.lineWidth = sel ? 2 : 1;
      c.strokeStyle = on ? theme.accent : theme.border;
      c.setLineDash(e.s ? [] : [4, 3]);
      c.stroke();
      c.setLineDash([]);
      c.fillStyle = on ? theme.accent : theme.text;
      c.fillText(text, (e.box.x0 + e.box.x1) / 2, (e.box.y0 + e.box.y1) / 2 + 0.5);
    });

    // Where new items start.
    nodes.forEach(function (n) {
      if (!n.initial) return;
      var x0 = n.x - n.hw - 44, x1 = n.x - n.hw - 4;
      c.fillStyle = c.strokeStyle = theme.text;
      c.beginPath();
      c.arc(x0, n.y, 6, 0, Math.PI * 2);
      c.fill();
      c.lineWidth = 1.4;
      c.beginPath();
      c.moveTo(x0 + 6, n.y);
      c.lineTo(x1, n.y);
      c.stroke();
      baselineMap.arrowHead(c, x1, n.y, 0, 8);
    });

    // Statuses.
    c.font = nodeFont();
    nodes.forEach(function (n) {
      var col = catColors(n.category);
      var sel = selected && selected.kind === "status" && selected.n === n;
      var near = (hover && hover.n === n) || (connect && connect.over === n);
      roundBox(c, n.x - n.hw, n.y - n.hh, n.hw * 2, n.hh * 2, 8);
      c.fillStyle = col.fill;
      c.fill();
      c.lineWidth = sel ? 2.5 : near ? 2 : 1.3;
      c.strokeStyle = sel || near ? theme.accent : col.line;
      if (connect && connect.over === n) c.setLineDash([5, 3]);
      c.stroke();
      c.setLineDash([]);
      c.fillStyle = col.text;
      c.fillText(n.name, n.x, n.y + 0.5);
    });

    // The handle to draw a transition from, and the one being drawn.
    var hn = handleNode();
    if (hn) {
      var hp = handlePoint(hn);
      c.beginPath();
      c.arc(hp.x, hp.y, HANDLE, 0, Math.PI * 2);
      c.fillStyle = theme.accent;
      c.fill();
      c.strokeStyle = theme.surface;
      c.lineWidth = 2;
      c.stroke();
      c.beginPath();
      c.moveTo(hp.x - 3.5, hp.y); c.lineTo(hp.x + 3.5, hp.y);
      c.moveTo(hp.x, hp.y - 3.5); c.lineTo(hp.x, hp.y + 3.5);
      c.lineWidth = 1.6;
      c.stroke();
    }
    if (connect && connect.to) {
      var end = connect.over ? clip(connect.over, connect.from.x, connect.from.y, 4) : connect.to;
      var st = clip(connect.from, end.x, end.y, 2);
      c.strokeStyle = c.fillStyle = theme.accent;
      c.lineWidth = 2;
      c.setLineDash([6, 4]);
      c.beginPath();
      c.moveTo(st.x, st.y);
      c.lineTo(end.x, end.y);
      c.stroke();
      c.setLineDash([]);
      baselineMap.arrowHead(c, end.x, end.y, Math.atan2(end.y - st.y, end.x - st.x), 10);
    }
  }

  // ---- Hit testing -----------------------------------------------------
  function overlap(a, b) { return a.x0 < b.x1 && a.x1 > b.x0 && a.y0 < b.y1 && a.y1 > b.y0; }
  function inBox(b, p) { return b && p.x >= b.x0 && p.x <= b.x1 && p.y >= b.y0 && p.y <= b.y1; }
  function nodeAtWorld(p, except) {
    for (var i = nodes.length - 1; i >= 0; i--) {
      var n = nodes[i];
      if (n !== except && Math.abs(p.x - n.x) <= n.hw && Math.abs(p.y - n.y) <= n.hh) return n;
    }
    return null;
  }
  function nearCurve(e, p, tol) {
    if (!e.geo) return false;
    for (var i = 0; i <= 24; i++) {
      var q = at(e.geo, i / 24);
      if (Math.hypot(p.x - q.x, p.y - q.y) < tol) return true;
    }
    return false;
  }
  function hit(sp) {
    if (!map) return null;
    var p = map.toWorld(sp.x, sp.y), k = map.view.k;
    var hn = handleNode();
    if (hn) {
      var hp = handlePoint(hn);
      if (Math.hypot(p.x - hp.x, p.y - hp.y) <= (HANDLE + 4) / Math.min(k, 1)) return { kind: "handle", n: hn };
    }
    var n = nodeAtWorld(p);
    if (n) return { kind: "status", n: n };
    for (var i = edges.length - 1; i >= 0; i--) if (inBox(edges[i].box, p)) return edges[i];
    for (i = edges.length - 1; i >= 0; i--) if (nearCurve(edges[i], p, 6 / k)) return edges[i];
    return null;
  }
  function same(a, b) {
    if (!a || !b) return a === b;
    return a === b || (a.kind && a.kind === b.kind && a.n === b.n);
  }

  // ---- Interaction -----------------------------------------------------
  function startConnect(n) {
    connect = { from: n, to: null, over: null };
    closePop();
    return {
      move: function (sp) {
        var p = map.toWorld(sp.x, sp.y);
        connect.to = p;
        connect.over = nodeAtWorld(p, n);
        map.draw();
      },
      end: function (sp, moved) {
        var c = connect;
        connect = null;
        if (moved && c.over) newTransition(c.from, c.over, sp);
        map.draw();
      }
    };
  }
  var pointer = {
    paint: paint,
    hit: hit,
    cursor: function (it) { return it.kind === "handle" ? "crosshair" : draft && it.kind === "status" ? "move" : "pointer"; },
    drag: function (it, sp, ev) {
      if (!draft || !it) return null;
      if (it.kind === "handle" || (it.kind === "status" && ev.shiftKey)) return startConnect(it.n);
      if (it.kind !== "status") return null;
      var n = it.n, p0 = map.toWorld(sp.x, sp.y), x0 = n.x, y0 = n.y;
      return {
        move: function (sp2) {
          var p = map.toWorld(sp2.x, sp2.y);
          n.x = Math.round((x0 + p.x - p0.x) / SNAP) * SNAP;
          n.y = Math.round((y0 + p.y - p0.y) / SNAP) * SNAP;
          map.draw();
        },
        end: function (sp2, moved) { if (moved) save([n]); }
      };
    },
    click: function (it) {
      if (popTarget) closePop();
      select(it && it.kind === "handle" ? { kind: "status", n: it.n } : it);
    },
    dblclick: function (it, sp) {
      if (!it) {
        if (!draft) return false;
        newStatus(map.toWorld(sp.x, sp.y), sp);
        return true;
      }
      if (draft && it.id) location.href = base + "/transitions/" + it.id;
      return true;
    },
    hover: function (it) {
      if (!same(it, hover)) { hover = it; map.draw(); }
    },
    leave: function () { if (hover) { hover = null; map.draw(); } },
    keydown: function (ev) {
      if (ev.key === "f" || ev.key === "F") fit();
      else if (ev.key === "Escape") { if (popTarget) closePop(); else select(null); }
      else if ((ev.key === "Delete" || ev.key === "Backspace") && draft && selected) remove(selected);
      else return false;
      return true;
    }
  };

  function fit() {
    if (!nodes.length) return;
    var b = bounds(nodes);
    route();
    edges.forEach(function (e) {
      var m = e.geo.mid;
      b.x0 = Math.min(b.x0, m.x - 40); b.x1 = Math.max(b.x1, m.x + 40);
      b.y0 = Math.min(b.y0, m.y - 12); b.y1 = Math.max(b.y1, m.y + 12);
    });
    map.fit(b, 40, 1.4);
  }

  // ---- Forms -----------------------------------------------------------
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function hidden(form, name, value) {
    var i = el("input");
    i.type = "hidden"; i.name = name; i.value = value;
    form.appendChild(i);
  }
  // post submits a form to the page's own handlers, which come back to the
  // diagram with a notice.
  function post(path, fields) {
    var f = el("form");
    f.method = "post";
    f.action = base + path;
    f.hidden = true;
    Object.keys(fields).forEach(function (k) { hidden(f, k, fields[k]); });
    hidden(f, "back", "diagram");
    document.body.appendChild(f);
    f.submit();
  }
  function remove(it) {
    if (it.kind === "status") {
      if (confirm("Delete " + it.n.name + " and its transitions from the draft?")) post("/statuses/" + it.n.id + "/delete", {});
    } else if (it.id && confirm("Delete the transition " + it.name + " from the draft?")) {
      post("/transitions/" + it.id + "/delete", {});
    }
  }

  // A small form over the canvas, near screen point sp.
  var pop = null;
  function openPop(form, sp) {
    closePop();
    pop = form;
    popTarget = true;
    form.className = "map-pop stack-form";
    stage.appendChild(form);
    var w = form.offsetWidth, h = form.offsetHeight;
    form.style.left = Math.max(8, Math.min(sp.x + 12, map.W - w - 8)) + "px";
    form.style.top = Math.max(8, Math.min(sp.y + 12, map.H - h - 8)) + "px";
    form.addEventListener("keydown", function (ev) { if (ev.key === "Escape") { ev.preventDefault(); closePop(); canvas.focus(); } });
    var first = form.querySelector("input:not([type=hidden])");
    if (first) first.focus();
    map.draw();
  }
  function closePop() {
    if (pop) pop.remove();
    pop = null;
    popTarget = null;
    if (map) map.draw();
  }
  function popForm(title, path) {
    var f = el("form");
    f.method = "post";
    f.action = base + path;
    f.appendChild(el("strong", "", title));
    hidden(f, "back", "diagram");
    return f;
  }
  function field(f, label, input) {
    var l = el("label", "", label);
    l.appendChild(input);
    f.appendChild(l);
    return input;
  }
  function textInput(name, placeholder) {
    var i = el("input");
    i.name = name; i.required = true; i.placeholder = placeholder || ""; i.autocomplete = "off";
    return i;
  }
  function buttons(f, label, extra) {
    var row = el("div", "map-pop-acts");
    row.appendChild(el("button", "small", label));
    if (extra) row.appendChild(extra);
    var cancel = el("button", "small secondary", "Cancel");
    cancel.type = "button";
    cancel.addEventListener("click", function () { closePop(); canvas.focus(); });
    row.appendChild(cancel);
    f.appendChild(row);
  }

  function newTransition(from, to, sp) {
    var f = popForm("New transition", "/transitions");
    f.appendChild(el("p", "muted small", from.name + " → " + to.name));
    hidden(f, "from", from.id);
    hidden(f, "to", to.id);
    hidden(f, "position", edges.length);
    field(f, "Name", textInput("name", "e.g. Start progress"));
    var more = el("a", "small", "More options");
    more.href = base + "/transitions/new?from=" + encodeURIComponent(from.id) + "&to=" + encodeURIComponent(to.id);
    buttons(f, "Add transition", more);
    openPop(f, sp);
  }

  function keyOf(name) {
    var k = name.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
    if (!/^[a-z]/.test(k)) k = "s_" + k;
    return k.slice(0, 32).replace(/_+$/, "");
  }
  function newStatus(p, sp) {
    var f = popForm("New status", "/statuses");
    hidden(f, "x", Math.round(p.x / SNAP) * SNAP);
    hidden(f, "y", Math.round(p.y / SNAP) * SNAP);
    hidden(f, "position", nodes.length);
    var name = field(f, "Name", textInput("name", "In review"));
    var key = field(f, "Key", textInput("key", "in_review"));
    key.pattern = "[a-z][a-z0-9_]{0,31}";
    key.title = "Lower-case letters, digits and underscores, starting with a letter. Fixed once created.";
    var typed = false;
    key.addEventListener("input", function () { typed = key.value !== ""; });
    name.addEventListener("input", function () { if (!typed) key.value = name.value.trim() ? keyOf(name.value) : ""; });
    var cat = el("select");
    cat.name = "category";
    data.categories.forEach(function (c) {
      var o = el("option", "", c.label);
      o.value = c.key;
      cat.appendChild(o);
    });
    field(f, "Category", cat);
    var l = el("label", "check");
    var init = el("input");
    init.type = "checkbox"; init.name = "initial"; init.value = "1";
    l.appendChild(init);
    l.appendChild(document.createTextNode(" Initial: new items start here"));
    f.appendChild(l);
    buttons(f, "Add status");
    openPop(f, sp);
  }

  // ---- Details ---------------------------------------------------------
  function select(it) {
    selected = it;
    renderInfo();
    map.draw();
  }
  function facts(rows) {
    var dl = el("dl", "map-facts");
    rows.forEach(function (r) {
      if (!r) return;
      dl.appendChild(el("dt", "", r[0]));
      var dd = el("dd");
      if (r[1] instanceof Node) dd.appendChild(r[1]); else dd.textContent = r[1];
      dl.appendChild(dd);
    });
    return dl;
  }
  function muted(t) { return el("span", "muted", t); }
  function transList(title, list, side) {
    if (!list.length) return;
    info.appendChild(el("h3", "", title));
    var ul = el("ul", "map-rels");
    list.forEach(function (e) {
      var li = el("li");
      var b = el("button", "link", e.name);
      b.type = "button";
      b.addEventListener("click", function () { select(e); });
      li.appendChild(b);
      li.appendChild(document.createTextNode(" " + (side === "out" ? "to " + e.t.name : e.s ? "from " + e.s.name : "from any status")));
      ul.appendChild(li);
    });
    info.appendChild(ul);
  }
  function acts(list) {
    var row = el("div", "map-info-acts");
    list.forEach(function (a) { row.appendChild(a); });
    info.appendChild(row);
  }
  function linkButton(label, href) {
    var a = el("a", "button small", label);
    a.href = href;
    return a;
  }
  function actButton(label, cls, fn) {
    var b = el("button", "small " + cls, label);
    b.type = "button";
    b.addEventListener("click", fn);
    return b;
  }
  function renderInfo() {
    info.textContent = "";
    if (!selected) { info.hidden = true; return; }
    info.hidden = false;
    var head = el("div", "map-info-head");
    var close = el("button", "link", "✕");
    close.type = "button";
    close.title = "Close (Esc)";
    close.addEventListener("click", function () { select(null); canvas.focus(); });
    if (selected.kind === "status") {
      var n = selected.n;
      head.appendChild(el("strong", "", n.name));
      head.appendChild(close);
      info.appendChild(head);
      info.appendChild(facts([["Key", n.key], ["Category", catLabel[n.category] || n.category], n.initial ? ["Initial", "new items start here"] : null]));
      transList("Out", edges.filter(function (e) { return e.s === n; }), "out");
      transList("In", edges.filter(function (e) { return e.t === n; }), "in");
      if (draft) {
        info.appendChild(el("p", "muted small", "Drag the + on its right edge to another status to add a transition."));
        acts([linkButton("Edit", "#st-" + n.id), actButton("Delete", "danger", function () { remove(selected); })]);
      }
    } else {
      var e = selected;
      head.appendChild(el("strong", "", e.name));
      head.appendChild(close);
      info.appendChild(head);
      info.appendChild(facts([
        ["From", e.s ? e.s.name : muted("any status")], ["To", e.t.name],
        ["Who", e.who || muted("anyone")], e.requires ? ["Requires", e.requires] : null,
        e.then ? ["Then", e.then] : null, e.asks ? ["Asks for", e.asks] : null
      ]));
      if (draft) acts([linkButton("Edit rules", base + "/transitions/" + e.id), actButton("Delete", "danger", function () { remove(selected); })]);
    }
  }

  // ---- Toolbar and start -------------------------------------------------
  function act(name, fn) {
    root.querySelectorAll('[data-act="' + name + '"]').forEach(function (b) { b.addEventListener("click", fn); });
  }
  act("fit", fit);
  act("arrange", function () {
    var pts = layered(nodes);
    nodes.forEach(function (n, i) { n.x = pts[i].x; n.y = pts[i].y; });
    save(nodes);
    fit();
  });
  act("add", function () {
    var c = map.center();
    newStatus(c, { x: map.W / 2 - 120, y: map.H / 2 - 100 });
  });
  act("png", function () {
    closePop();
    var name = root.dataset.name || "workflow";
    map.png("Baseline workflow " + name + " · " + nodes.length + " statuses, " + edges.length + " transitions · " + new Date().toLocaleString(),
      "workflow-" + name.toLowerCase().replace(/[^a-z0-9]+/g, "-") + ".png");
  });

  sizeNodes();
  // A draft keeps the layout it was first shown with, so adding a status
  // or moving one doesn't rearrange the rest.
  var unplaced = nodes.filter(function (n) { return !n.placed; });
  placeUnplaced();
  if (unplaced.length) save(unplaced);
  var map = baselineMap.create(canvas, stage, pointer);
  baselineMap.onTheme(function () { theme = baselineMap.theme(); map.draw(); });
  if (!nodes.length) say(draft ? "No statuses yet. Double-click to add one." : "No statuses.");
  fit();
})();
