// The CI map (/map): every CI the user can see and the relationships between
// them, drawn on a canvas with a force-directed layout. Filters hide CIs by
// type, relationship kind, status, source, host group and tag; a hidden CI
// between two shown ones can be bridged with a dotted edge so chains stay
// readable. Focus narrows the map to a CI's neighbourhood. The filters,
// focus and view live in the query string.
(function () {
  "use strict";
  var root = document.getElementById("cimap");
  if (!root || !window.baselineMap || !window.fetch || !window.requestAnimationFrame || !window.URLSearchParams) return;

  var stage = root.querySelector(".map-stage");
  var canvas = stage.querySelector("canvas");
  var statusEl = stage.querySelector(".map-status");
  var tip = stage.querySelector(".map-tip");
  var legendEl = stage.querySelector(".map-legend");
  var info = stage.querySelector(".map-info");
  var listsEl = root.querySelector("[data-lists]");
  var matchesEl = root.querySelector(".map-matches");
  var focusBox = root.querySelector('[data-group="focus"]');

  // ---- Colours ---------------------------------------------------------
  // Eight validated categorical hues (light and dark steps), assigned to
  // families of CI types in a fixed order; shape tells the types in a
  // family apart. Status colours are reserved for health.
  var HUES = {
    blue: ["#2a78d6", "#3987e5"], orange: ["#eb6834", "#d95926"], aqua: ["#1baf7a", "#199e70"],
    yellow: ["#eda100", "#c98500"], magenta: ["#e87ba4", "#d55181"], green: ["#008300", "#008300"],
    violet: ["#6250d6", "#9085e9"], grey: ["#898781", "#898781"]
  };
  var TYPE_STYLE = {
    host: ["blue", "circle"], server: ["blue", "square"],
    container: ["orange", "circle"],
    compose_stack: ["aqua", "square"],
    service_endpoint: ["yellow", "diamond"], certificate: ["yellow", "triangle"], license: ["yellow", "square"],
    vm: ["magenta", "circle"], lxc: ["magenta", "square"],
    k8s_cluster: ["green", "hexagon"], k8s_node: ["green", "square"], k8s_workload: ["green", "circle"],
    network_device: ["violet", "diamond"], nas: ["violet", "square"], ups: ["violet", "triangle"],
    printer: ["violet", "circle"], appliance: ["violet", "hexagon"],
    site: ["grey", "hexagon"], rack: ["grey", "square"], other: ["grey", "circle"]
  };
  var HEALTH = {
    ok: { color: "#0ca30c", label: "OK", icon: "✓" },
    warn: { color: "#fab219", label: "Needs attention", icon: "!" },
    bad: { color: "#d03b3b", label: "Problem", icon: "✕" },
    off: { color: "#898781", label: "Stopped, planned or retired", icon: "○" }
  };
  var STATUS = {
    active: { hue: "blue", label: "Active" }, planned: { hue: "violet", label: "Planned" },
    missing: { hex: "#d03b3b", label: "Missing" }, retired: { hue: "grey", label: "Retired" }
  };
  var SOURCES = { agent: "Agent", proxmox: "Proxmox", libvirt: "libvirt", k8s: "Kubernetes", manual: "Manual" };

  var theme = {};
  function readTheme() { theme = baselineMap.theme(); }
  function hue(name) { return (HUES[name] || HUES.grey)[theme.dark ? 1 : 0]; }
  function typeStyle(type) { return TYPE_STYLE[type] || ["grey", "circle"]; }
  function nodeColor(n) {
    switch (state.color) {
      case "health": return (HEALTH[n.health] || HEALTH.off).color;
      case "status": var s = STATUS[n.status] || STATUS.retired; return s.hex || hue(s.hue);
    }
    return hue(typeStyle(n.type)[0]);
  }

  // ---- State and the address -------------------------------------------
  var LIST_PARAMS = ["xt", "xk", "xs", "xo", "g", "tag"];
  function defaults() {
    return {
      q: "", color: "type", bridge: true, iso: false, labels: true, only: false,
      xt: new Set(), xk: new Set(), xs: new Set(["retired"]), xo: new Set(), g: new Set(), tag: new Set(),
      focus: "", depth: 2, view: null
    };
  }
  var state = defaults();

  function readURL() {
    var p = new URLSearchParams(location.search);
    var s = defaults();
    s.q = p.get("q") || "";
    if (["type", "health", "status"].indexOf(p.get("color")) >= 0) s.color = p.get("color");
    s.bridge = p.get("bridge") !== "0";
    s.iso = p.get("iso") === "1";
    s.labels = p.get("labels") !== "0";
    s.only = p.get("only") === "1";
    LIST_PARAMS.forEach(function (k) {
      if (p.has(k)) s[k] = new Set(p.get(k).split(",").filter(Boolean));
    });
    s.focus = p.get("focus") || "";
    if (p.has("depth")) s.depth = Math.max(0, Math.min(4, parseInt(p.get("depth"), 10) || 0));
    var v = (p.get("v") || "").split(",").map(Number);
    if (v.length === 3 && v.every(isFinite) && v[2] > 0) s.view = { cx: v[0], cy: v[1], k: v[2] };
    state = s;
  }

  var urlTimer = 0;
  function writeURL() {
    clearTimeout(urlTimer);
    urlTimer = setTimeout(function () {
      var p = new URLSearchParams();
      var d = defaults();
      if (state.q) p.set("q", state.q);
      if (state.color !== d.color) p.set("color", state.color);
      if (!state.bridge) p.set("bridge", "0");
      if (state.iso) p.set("iso", "1");
      if (!state.labels) p.set("labels", "0");
      if (state.only) p.set("only", "1");
      LIST_PARAMS.forEach(function (k) {
        var a = Array.from(state[k]).sort(), b = Array.from(d[k]).sort();
        if (a.join(",") !== b.join(",")) p.set(k, a.join(","));
      });
      if (state.focus) {
        p.set("focus", state.focus);
        if (state.depth !== d.depth) p.set("depth", state.depth);
      }
      if (map && map.W) {
        var c = map.center();
        p.set("v", [Math.round(c.x), Math.round(c.y), +view.k.toFixed(3)].join(","));
      }
      var qs = p.toString();
      history.replaceState(null, "", location.pathname + (qs ? "?" + qs.replace(/%2C/g, ",") : ""));
    }, 250);
  }

  // ---- Data ------------------------------------------------------------
  var data = null;        // as fetched
  var nodes = [], byId = {}, edges = [];
  var typeLabels = {}, groupLabels = {};
  var shown = [], drawn = [];   // the current visible nodes and edges
  var adj = {};                 // node id -> drawn edges touching it
  var matchSet = null;          // ids matching the search, or null

  function load() {
    statusEl.textContent = "Loading…";
    statusEl.hidden = false;
    fetch(root.dataset.src, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) {
        if (!r.ok) throw new Error(r.status + " " + r.statusText);
        return r.json();
      })
      .then(function (d) { ingest(d); })
      .catch(function (e) { statusEl.textContent = "Couldn't load the map: " + e.message; statusEl.hidden = false; });
  }

  function ingest(d) {
    var old = byId;
    data = d;
    typeLabels = {};
    d.types.forEach(function (t) { typeLabels[t.key] = t.label; });
    groupLabels = {};
    d.groups.forEach(function (g) { groupLabels[g.key] = g.label; });
    byId = {};
    nodes = d.nodes.map(function (n, i) {
      var o = old[n.id];
      n.x = o ? o.x : NaN; n.y = o ? o.y : NaN; n.vx = 0; n.vy = 0;
      n.fx = o ? o.fx : null; n.fy = o ? o.fy : null;
      n.idx = i; n.deg = 0;
      n.hay = [n.name, n.host || "", typeLabels[n.type] || n.type, n.status].concat(n.tags, n.notes).join(" ").toLowerCase();
      byId[n.id] = n;
      return n;
    });
    edges = d.edges.map(function (e) {
      var s = byId[e.from], t = byId[e.to];
      s.deg++; t.deg++;
      return { s: s, t: t, kind: e.kind, manual: !!e.manual };
    });
    if (state.focus && !byId[state.focus]) state.focus = "";
    if (selected && !byId[selected.id]) selected = null; else if (selected) selected = byId[selected.id];
    buildFilters();
    syncControls();
    statusEl.hidden = nodes.length > 0;
    if (!nodes.length) statusEl.textContent = "No CIs yet.";
    recompute(true);
    settle(400);
    // The first load opens on the view in the address, or fits; a reload
    // keeps the view as it is.
    if (state.view) setView(state.view);
    else if (firstLoad) fit();
    state.view = null;
    firstLoad = false;
    start();
  }
  var firstLoad = true;

  // ---- Filtering, bridging and focus -----------------------------------
  function matches(n) { return !!matchSet && matchSet.has(n.id); }

  function passes(n) {
    if (state.xt.has(n.type) || state.xs.has(n.status) || state.xo.has(n.source)) return false;
    if (state.tag.size && !n.tags.some(function (t) { return state.tag.has(t); })) return false;
    if (state.only && matchSet && !matchSet.has(n.id)) return false;
    return true;
  }
  function inGroups(n) { return n.groups.some(function (g) { return state.g.has(g); }); }

  function recompute(reheat) {
    var q = state.q.trim().toLowerCase();
    matchSet = null;
    if (q) {
      var words = q.split(/\s+/);
      matchSet = new Set();
      nodes.forEach(function (n) {
        if (words.every(function (w) { return n.hay.indexOf(w) >= 0; })) matchSet.add(n.id);
      });
    }
    var kindOK = function (e) { return !state.xk.has(e.kind); };
    var live = edges.filter(kindOK);

    // CIs that pass the filters. With host groups picked, a CI that lives
    // on no host (a switch, a NAS) stays when it's related to one that's in.
    var vis = new Set();
    nodes.forEach(function (n) {
      if (passes(n) && (!state.g.size || inGroups(n))) vis.add(n.id);
    });
    if (state.g.size) {
      live.forEach(function (e) {
        [[e.s, e.t], [e.t, e.s]].forEach(function (p) {
          if (!p[0].groups.length && !p[0].host && passes(p[0]) && vis.has(p[1].id) && inGroups(p[1])) vis.add(p[0].id);
        });
      });
    }
    if (state.focus) vis.add(state.focus);

    var out = [];
    var direct = new Set();
    live.forEach(function (e) {
      if (vis.has(e.s.id) && vis.has(e.t.id)) {
        out.push(e);
        direct.add(e.s.id + ">" + e.t.id);
        direct.add(e.t.id + ">" + e.s.id);
      }
    });

    // Bridges follow relationships forwards through hidden CIs: a container
    // runs_on a hidden host that runs_on a VM becomes container ⇢ VM. Going
    // forwards only keeps siblings (the containers on one host) from all
    // being joined to each other.
    if (state.bridge) {
      var outgoing = {};
      live.forEach(function (e) { (outgoing[e.s.id] = outgoing[e.s.id] || []).push(e); });
      var seen = new Set();
      vis.forEach(function (id) {
        var stack = [{ n: byId[id], via: [], kinds: [] }];
        var visited = new Set([id]);
        while (stack.length) {
          var cur = stack.pop();
          (outgoing[cur.n.id] || []).forEach(function (e) {
            var t = e.t;
            if (visited.has(t.id)) return;
            visited.add(t.id);
            var kinds = cur.kinds.concat(e.kind);
            if (vis.has(t.id)) {
              if (!cur.via.length) return; // a direct edge, drawn already
              var key = id + ">" + t.id;
              if (direct.has(key) || seen.has(key)) return;
              seen.add(key);
              out.push({ s: byId[id], t: t, kind: kinds.join(" → "), bridge: true, via: cur.via });
            } else {
              stack.push({ n: t, via: cur.via.concat(t), kinds: kinds });
            }
          });
        }
      });
    }

    // Focus: the focused CI and what's within so many hops of it.
    if (state.focus && byId[state.focus]) {
      var nb = {};
      out.forEach(function (e) {
        (nb[e.s.id] = nb[e.s.id] || []).push(e.t.id);
        (nb[e.t.id] = nb[e.t.id] || []).push(e.s.id);
      });
      var keep = new Set([state.focus]);
      var frontier = [state.focus];
      for (var hop = 0; frontier.length && (state.depth === 0 || hop < state.depth); hop++) {
        var next = [];
        frontier.forEach(function (id) {
          (nb[id] || []).forEach(function (o) {
            if (!keep.has(o)) { keep.add(o); next.push(o); }
          });
        });
        frontier = next;
      }
      vis = keep;
      out = out.filter(function (e) { return keep.has(e.s.id) && keep.has(e.t.id); });
    }

    adj = {};
    out.forEach(function (e) {
      (adj[e.s.id] = adj[e.s.id] || []).push(e);
      (adj[e.t.id] = adj[e.t.id] || []).push(e);
    });
    if (state.iso) {
      vis.forEach(function (id) { if (!adj[id] && id !== state.focus) vis.delete(id); });
    }

    shown = nodes.filter(function (n) { return vis.has(n.id); });
    drawn = out;
    shown.forEach(function (n) { n.vdeg = (adj[n.id] || []).length; });
    placeNew();
    if (selected && !vis.has(selected.id)) selected = null;
    if (hover && !vis.has(hover.id)) hover = null;

    var hidden = nodes.length - shown.length;
    var bridges = drawn.filter(function (e) { return e.bridge; }).length;
    matchesEl.textContent = (matchSet ? matchSet.size + " match" + (matchSet.size === 1 ? "" : "es") + ". " : "") +
      "Showing " + shown.length + " of " + nodes.length + " CIs" + (hidden ? " (" + hidden + " hidden)" : "") +
      " and " + (drawn.length - bridges) + " relationships" + (bridges ? " (+" + bridges + " bridged)" : "") + ".";
    if (nodes.length && !shown.length) {
      statusEl.textContent = "Nothing matches these filters.";
      statusEl.hidden = false;
    } else if (nodes.length) {
      statusEl.hidden = true;
    }
    updateFocusBox();
    renderLegend();
    renderInfo();
    writeURL();
    if (reheat) heat(0.6);
    draw();
  }

  // ---- Layout ----------------------------------------------------------
  // A d3-style simulation: springs along edges, Barnes-Hut repulsion
  // between every pair, and a weak pull to the middle so separate clusters
  // stay in view. Seeded, so the same data lays out the same way.
  var alpha = 0, alphaTarget = 0, running = false, frozen = false;
  var LINK = 46, CHARGE = -160, THETA2 = 0.81, GRAVITY = 0.035, DECAY = 0.4;

  function rng(seed) {
    return function () {
      seed |= 0; seed = seed + 0x6D2B79F5 | 0;
      var t = Math.imul(seed ^ seed >>> 15, 1 | seed);
      t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
      return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
  }
  var rand = rng(7);

  function placeNew() {
    // New CIs start beside a placed neighbour, or on a spiral.
    var golden = Math.PI * (3 - Math.sqrt(5));
    var spiral = 0;
    var pending = shown.filter(function (n) { return isNaN(n.x); });
    for (var pass = 0; pass < 3 && pending.length; pass++) {
      pending = pending.filter(function (n) {
        var nb = (adj[n.id] || []).map(function (e) { return e.s === n ? e.t : e.s; })
          .filter(function (o) { return !isNaN(o.x); })[0];
        if (!nb && pass < 2) return true;
        if (nb) {
          var a = rand() * 2 * Math.PI;
          n.x = nb.x + Math.cos(a) * LINK * 0.8;
          n.y = nb.y + Math.sin(a) * LINK * 0.8;
        } else {
          var r = 12 * Math.sqrt(0.5 + spiral), ang = spiral * golden;
          spiral++;
          n.x = r * Math.cos(ang);
          n.y = r * Math.sin(ang);
        }
        return false;
      });
    }
  }

  function buildTree(list) {
    var x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    list.forEach(function (n) {
      if (n.x < x0) x0 = n.x; if (n.x > x1) x1 = n.x;
      if (n.y < y0) y0 = n.y; if (n.y > y1) y1 = n.y;
    });
    var size = Math.max(x1 - x0, y1 - y0, 1) + 1;
    var tree = { x: x0, y: y0, s: size, kids: null, body: null, extra: null, m: 0, cx: 0, cy: 0 };
    list.forEach(function (n) { insert(tree, n, 0); });
    return tree;
  }
  function insert(q, n, depth) {
    q.cx = (q.cx * q.m + n.x) / (q.m + 1);
    q.cy = (q.cy * q.m + n.y) / (q.m + 1);
    q.m++;
    if (!q.kids) {
      if (!q.body) { q.body = n; return; }
      if (depth > 40 || q.s < 1e-3) { (q.extra = q.extra || []).push(n); return; }
      var old = q.body;
      q.body = null;
      q.kids = [null, null, null, null];
      place(q, old, depth);
    }
    place(q, n, depth);
  }
  function place(q, n, depth) {
    var h = q.s / 2;
    var i = (n.x >= q.x + h ? 1 : 0) + (n.y >= q.y + h ? 2 : 0);
    if (!q.kids[i]) q.kids[i] = { x: q.x + (i & 1 ? h : 0), y: q.y + (i & 2 ? h : 0), s: h, kids: null, body: null, extra: null, m: 0, cx: 0, cy: 0 };
    insert(q.kids[i], n, depth + 1);
  }
  function repel(q, n) {
    if (!q || !q.m) return;
    var dx = q.cx - n.x, dy = q.cy - n.y, d2 = dx * dx + dy * dy;
    if (!q.kids) {
      var bodies = q.extra ? [q.body].concat(q.extra) : [q.body];
      bodies.forEach(function (b) {
        if (b === n) return;
        var x = b.x - n.x, y = b.y - n.y, l = x * x + y * y;
        if (l < 1) { x = (rand() - 0.5) * 1e-2; y = (rand() - 0.5) * 1e-2; l = 1; }
        var f = CHARGE * alpha / l;
        n.vx += x * f; n.vy += y * f;
      });
      return;
    }
    if (q.s * q.s / THETA2 < d2) {
      var w = CHARGE * q.m * alpha / Math.max(d2, 1);
      n.vx += dx * w; n.vy += dy * w;
      return;
    }
    for (var i = 0; i < 4; i++) repel(q.kids[i], n);
  }

  function tick() {
    alpha += (alphaTarget - alpha) * 0.0228;
    if (!shown.length) return;
    drawn.forEach(function (e) {
      var s = e.s, t = e.t;
      var x = t.x + t.vx - s.x - s.vx, y = t.y + t.vy - s.y - s.vy;
      var l = Math.sqrt(x * x + y * y) || 1e-3;
      var ds = Math.max(s.vdeg, 1), dt = Math.max(t.vdeg, 1);
      var strength = (e.bridge ? 0.5 : 1) / Math.min(ds, dt);
      var dist = LINK * (e.bridge ? 1.6 : 1) + 3 * Math.sqrt(Math.max(ds, dt));
      l = (l - dist) / l * alpha * strength;
      x *= l; y *= l;
      var bias = ds / (ds + dt);
      t.vx -= x * bias; t.vy -= y * bias;
      s.vx += x * (1 - bias); s.vy += y * (1 - bias);
    });
    var tree = buildTree(shown);
    shown.forEach(function (n) {
      repel(tree, n);
      n.vx -= n.x * GRAVITY * alpha;
      n.vy -= n.y * GRAVITY * alpha;
    });
    shown.forEach(function (n) {
      if (n.fx != null) { n.x = n.fx; n.y = n.fy; n.vx = n.vy = 0; return; }
      n.vx *= 1 - DECAY; n.vy *= 1 - DECAY;
      n.x += n.vx; n.y += n.vy;
    });
  }

  function heat(a) {
    if (frozen) return;
    alpha = Math.max(alpha, a);
    start();
  }
  // settle runs the layout for up to ms before the first paint, so the map
  // doesn't open on a tangle.
  function settle(ms) {
    if (frozen) return;
    alpha = Math.max(alpha, 1);
    var end = performance.now() + ms;
    while (alpha > 0.05 && performance.now() < end) tick();
  }

  var pendingFit = false;
  function frame() {
    running = false;
    if (!frozen && (alpha > 0.004 || alphaTarget > 0)) {
      var end = performance.now() + 12;
      do { tick(); } while (shown.length < 400 && performance.now() < end && alpha > 0.004);
      if (pendingFit && alpha < 0.12) { pendingFit = false; fit(); }
      running = true;
    }
    map.render();
    if (running) requestAnimationFrame(frame);
  }
  function start() {
    if (!running) { running = true; requestAnimationFrame(frame); }
  }

  // ---- View ------------------------------------------------------------
  // The canvas, pan and zoom come from mapcore.js; map is set at the start.
  var map = null, view = { x: 0, y: 0, k: 1 };
  function toWorld(sx, sy) { return map.toWorld(sx, sy); }
  function setView(v) { map.setView(v); }
  function fit() {
    if (!shown.length || !map.W) return;
    var b = { x0: Infinity, y0: Infinity, x1: -Infinity, y1: -Infinity };
    shown.forEach(function (n) {
      b.x0 = Math.min(b.x0, n.x); b.x1 = Math.max(b.x1, n.x);
      b.y0 = Math.min(b.y0, n.y); b.y1 = Math.max(b.y1, n.y);
    });
    map.fit(b, 60, 2.2);
    writeURL();
  }
  function centerOn(n) {
    setView({ cx: n.x, cy: n.y, k: Math.max(view.k, 1) });
    writeURL();
    draw();
  }

  // ---- Drawing ---------------------------------------------------------
  var selected = null, hover = null;

  function radius(n) { return 5 + Math.min(7, Math.sqrt(n.deg) * 1.3); }

  var shapePath = baselineMap.shapePath;

  function related(n) {
    var set = new Set([n.id]);
    (adj[n.id] || []).forEach(function (e) { set.add(e.s.id); set.add(e.t.id); });
    return set;
  }

  // paint draws the map onto c, w×h CSS pixels at scale px, with view v.
  function paint(c, w, h, px, v, opts) {
    opts = opts || {};
    c.setTransform(px, 0, 0, px, 0, 0);
    c.fillStyle = opts.background || theme.surface;
    c.fillRect(0, 0, w, h);
    if (!shown.length) return;
    var k = v.k;
    var sx = function (n) { return n.x * k + v.x; };
    var sy = function (n) { return n.y * k + v.y; };
    var focusN = hover || selected;
    var near = focusN ? related(focusN) : null;
    var searching = !!matchSet && !state.only;
    var onScreen = function (x, y, m) { return x > -m && y > -m && x < w + m && y < h + m; };
    var nr = function (n) { return Math.max(2.5, radius(n) * Math.min(k, 1.6)); };

    // Edges.
    c.lineCap = "round";
    var arrows = k > 0.45;
    drawn.forEach(function (e) {
      var x1 = sx(e.s), y1 = sy(e.s), x2 = sx(e.t), y2 = sy(e.t);
      if (!onScreen(x1, y1, 0) && !onScreen(x2, y2, 0) &&
        (Math.max(x1, x2) < 0 || Math.min(x1, x2) > w || Math.max(y1, y2) < 0 || Math.min(y1, y2) > h)) return;
      var hot = near && near.has(e.s.id) && near.has(e.t.id) && (e.s === focusN || e.t === focusN);
      var faded = (near && !hot) || (searching && !(matches(e.s) || matches(e.t)));
      c.globalAlpha = faded ? 0.12 : hot ? 1 : 0.55;
      c.strokeStyle = hot ? theme.accent : theme.muted;
      c.lineWidth = hot ? 2 : 1;
      c.setLineDash(e.bridge ? [2, 4] : e.manual ? [6, 4] : []);
      var dx = x2 - x1, dy = y2 - y1, len = Math.sqrt(dx * dx + dy * dy) || 1;
      var r2 = nr(e.t) + 2, r1 = nr(e.s);
      var ex = x2 - dx / len * r2, ey = y2 - dy / len * r2;
      c.beginPath();
      c.moveTo(x1 + dx / len * r1, y1 + dy / len * r1);
      c.lineTo(ex, ey);
      c.stroke();
      if (arrows && len > r1 + r2 + 6) {
        c.setLineDash([]);
        c.fillStyle = c.strokeStyle;
        var a = Math.atan2(dy, dx), al = hot ? 8 : 6;
        c.beginPath();
        c.moveTo(ex, ey);
        c.lineTo(ex - al * Math.cos(a - 0.4), ey - al * Math.sin(a - 0.4));
        c.lineTo(ex - al * Math.cos(a + 0.4), ey - al * Math.sin(a + 0.4));
        c.closePath();
        c.fill();
      }
      if ((hot || k > 1.5) && len > 70) {
        var label = e.bridge ? "via " + e.via.length + " hidden" : e.kind.replace(/_/g, " ");
        c.globalAlpha = faded ? 0.2 : 1;
        c.font = "10px " + theme.font;
        c.textAlign = "center";
        c.textBaseline = "middle";
        c.lineWidth = 3;
        c.strokeStyle = theme.surface;
        c.setLineDash([]);
        c.strokeText(label, (x1 + x2) / 2, (y1 + y2) / 2);
        c.fillStyle = theme.muted;
        c.fillText(label, (x1 + x2) / 2, (y1 + y2) / 2);
      }
    });
    c.setLineDash([]);

    // Nodes, with a ring of the surface colour so overlapping ones separate.
    var labelled = [];
    shown.forEach(function (n) {
      var x = sx(n), y = sy(n), r = nr(n);
      if (!onScreen(x, y, r + 4)) return;
      var faded = (near && !near.has(n.id)) || (searching && !matches(n));
      c.globalAlpha = faded ? 0.18 : 1;
      var shape = typeStyle(n.type)[1];
      shapePath(c, shape, x, y, r);
      c.fillStyle = nodeColor(n);
      c.fill();
      c.lineWidth = 2;
      c.strokeStyle = theme.surface;
      c.stroke();
      if (n.status === "missing" || n.status === "planned") {
        shapePath(c, shape, x, y, r + 3);
        c.setLineDash([3, 3]);
        c.lineWidth = 1.2;
        c.strokeStyle = nodeColor(n);
        c.stroke();
        c.setLineDash([]);
      }
      if (n === selected || n.id === state.focus || (searching && matches(n)) || n.fx != null) {
        shapePath(c, shape, x, y, r + (n === selected ? 4 : 3));
        c.lineWidth = n === selected ? 2.5 : 1.5;
        c.strokeStyle = n.fx != null && n !== selected && !matches(n) ? theme.muted : theme.accent;
        c.stroke();
      }
      if (opts.labels !== false && state.labels) labelled.push({ n: n, x: x, y: y + r + 3, faded: faded });
    });

    // Names, most important first, skipping any that would overlap one
    // already drawn.
    if (opts.labels !== false && state.labels) {
      var rank = function (l) {
        var n = l.n;
        return (n === selected ? 1e6 : 0) + (n === hover ? 5e5 : 0) + (matches(n) ? 1e5 : 0) +
          (near && near.has(n.id) ? 5e4 : 0) + (l.faded ? -1e5 : 0) + n.deg;
      };
      labelled.sort(function (a, b) { return rank(b) - rank(a); });
      c.font = "11px " + theme.font;
      c.textAlign = "center";
      c.textBaseline = "top";
      var boxes = [];
      var minDeg = k >= 0.9 ? 0 : k >= 0.5 ? 3 : k >= 0.25 ? 8 : 20;
      labelled.forEach(function (l) {
        var n = l.n;
        var important = n === selected || n === hover || matches(n) || (near && near.has(n.id));
        if (!important && n.deg < minDeg) return;
        var text = n.name.length > 28 ? n.name.slice(0, 27) + "…" : n.name;
        var tw = c.measureText(text).width;
        var b = { x0: l.x - tw / 2 - 2, x1: l.x + tw / 2 + 2, y0: l.y, y1: l.y + 13 };
        for (var i = 0; i < boxes.length; i++) {
          var o = boxes[i];
          if (b.x0 < o.x1 && b.x1 > o.x0 && b.y0 < o.y1 && b.y1 > o.y0) {
            if (!important) return;
          }
        }
        boxes.push(b);
        c.globalAlpha = l.faded ? 0.3 : 1;
        c.lineWidth = 3;
        c.strokeStyle = theme.surface;
        c.strokeText(text, l.x, l.y);
        c.fillStyle = theme.text;
        c.fillText(text, l.x, l.y);
      });
    }
    c.globalAlpha = 1;
  }

  function draw() { if (map) map.draw(); }

  // ---- Interaction -----------------------------------------------------
  function nodeAt(sx, sy) {
    var p = toWorld(sx, sy);
    var best = null, bestD = Infinity;
    for (var i = shown.length - 1; i >= 0; i--) {
      var n = shown[i];
      var r = Math.max(2.5, radius(n) * Math.min(view.k, 1.6)) / view.k + 4 / view.k;
      var dx = n.x - p.x, dy = n.y - p.y, d = dx * dx + dy * dy;
      if (d < r * r && d < bestD) { best = n; bestD = d; }
    }
    return best;
  }
  // pointer is what mapcore.js asks about the pointer.
  var pointer = {
    paint: function (c, w, h, px, v) { paint(c, w, h, px, v); },
    hit: function (p) { return nodeAt(p.x, p.y); },
    drag: function (n) {
      if (!n) return null;
      return {
        move: function (p) {
          hideTip();
          var w = toWorld(p.x, p.y);
          n.fx = w.x; n.fy = w.y;
          n.x = w.x; n.y = w.y;
          alphaTarget = 0.25;
          heat(0.25);
          draw();
        },
        end: function (p, moved) {
          alphaTarget = 0;
          if (moved) writeURL();
        }
      };
    },
    click: function (n) { select(n); },
    hover: function (n, p) {
      if (n !== hover) { hover = n; draw(); }
      showTip(n, p);
    },
    leave: function () { if (hover) { hover = null; hideTip(); draw(); } },
    dblclick: function (n) {
      if (!n) return false;
      location.href = n.link;
      return true;
    },
    viewChanged: function () { hideTip(); writeURL(); },
    keydown: function (ev) {
      if (ev.key === "f" || ev.key === "F") fit();
      else if (ev.key === "Escape") { if (selected) select(null); else if (state.focus) setFocus(""); }
      else if (ev.key === "Enter" && selected) location.href = selected.link;
      else return false;
      return true;
    }
  };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function typeName(n) { return typeLabels[n.type] || n.type; }
  function healthLine(n) {
    var h = HEALTH[n.health] || HEALTH.off;
    return h.icon + " " + h.label;
  }

  function showTip(n, p) {
    if (!n) { hideTip(); return; }
    tip.textContent = "";
    tip.appendChild(el("strong", null, n.name));
    tip.appendChild(el("div", "muted", typeName(n) + " · " + n.status + (n.host && n.type !== "host" ? " · on " + n.host : "")));
    var h = el("div", "map-health " + n.health, healthLine(n));
    tip.appendChild(h);
    n.notes.slice(0, 4).forEach(function (t) { tip.appendChild(el("div", "small", t)); });
    tip.hidden = false;
    var tw = tip.offsetWidth, th = tip.offsetHeight;
    var x = p.x + 14, y = p.y + 14;
    if (x + tw > map.W - 4) x = p.x - tw - 14;
    if (y + th > map.H - 4) y = p.y - th - 14;
    tip.style.left = Math.max(4, x) + "px";
    tip.style.top = Math.max(4, y) + "px";
  }
  function hideTip() { tip.hidden = true; }

  function select(n) {
    selected = n;
    renderInfo();
    draw();
  }

  function setFocus(id) {
    state.focus = id;
    pendingFit = true;
    recompute(true);
    syncControls();
  }

  function button(label, cls, fn) {
    var b = el("button", "small " + (cls || "secondary"), label);
    b.type = "button";
    b.addEventListener("click", fn);
    return b;
  }

  function renderInfo() {
    if (!selected) { info.hidden = true; return; }
    var n = selected;
    info.textContent = "";
    var head = el("div", "map-info-head");
    head.appendChild(el("strong", null, n.name));
    var close = button("✕", "link", function () { select(null); });
    close.setAttribute("aria-label", "Close");
    head.appendChild(close);
    info.appendChild(head);
    var dl = el("dl", "map-facts");
    var fact = function (k, v) { if (!v) return; dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, v)); };
    fact("Type", typeName(n));
    fact("Status", n.status);
    fact("Source", SOURCES[n.source] || n.source);
    if (n.type !== "host") fact("Host", n.host);
    fact("Groups", n.groups.map(function (g) { return groupLabels[g] || g; }).join(", "));
    fact("Tags", n.tags.join(", "));
    info.appendChild(dl);
    var h = el("p", "map-health " + n.health, healthLine(n));
    info.appendChild(h);
    if (n.notes.length) {
      var ul = el("ul", "map-notes small");
      n.notes.forEach(function (t) { ul.appendChild(el("li", null, t)); });
      info.appendChild(ul);
    }
    var acts = el("div", "map-info-acts");
    var open = el("a", "button small", "Open page");
    open.href = n.link;
    acts.appendChild(open);
    if (state.focus !== n.id) acts.appendChild(button("Focus here", "secondary", function () { setFocus(n.id); }));
    if (n.fx != null) acts.appendChild(button("Unpin", "secondary", function () { n.fx = n.fy = null; heat(0.3); renderInfo(); }));
    info.appendChild(acts);

    var rels = adj[n.id] || [];
    if (rels.length) {
      info.appendChild(el("h3", null, rels.length + " shown relationship" + (rels.length === 1 ? "" : "s")));
      var list = el("ul", "map-rels small");
      rels.slice().sort(function (a, b) {
        return (a.s === n ? 0 : 1) - (b.s === n ? 0 : 1) || a.kind.localeCompare(b.kind) ||
          (a.s === n ? a.t : a.s).name.localeCompare((b.s === n ? b.t : b.s).name);
      }).slice(0, 40).forEach(function (e) {
        var out = e.s === n, other = out ? e.t : e.s;
        var li = el("li");
        var verb = e.bridge ? (out ? "⇢ " : "⇠ ") + e.kind.replace(/ → /g, ", then ").replace(/_/g, " ")
          : (out ? "→ " : "← ") + e.kind.replace(/_/g, " ");
        li.appendChild(el("span", "muted", verb + " "));
        var b = button(other.name, "link", function () { select(other); centerOn(other); });
        li.appendChild(b);
        if (e.bridge) {
          li.appendChild(el("span", "muted", " via " + e.via.map(function (v) { return v.name; }).join(", ")));
        } else if (e.manual) {
          li.appendChild(el("span", "muted", " (manual)"));
        }
        list.appendChild(li);
      });
      if (rels.length > 40) list.appendChild(el("li", "muted", "and " + (rels.length - 40) + " more"));
      info.appendChild(list);
    }
    var hiddenRels = n.deg - rels.filter(function (e) { return !e.bridge; }).length;
    if (hiddenRels > 0) info.appendChild(el("p", "muted small", hiddenRels + " more relationship" + (hiddenRels === 1 ? " is" : "s are") + " hidden by the filters."));
    info.hidden = false;
  }

  // ---- Legend ----------------------------------------------------------
  function swatch(color, shape) {
    var c = el("canvas", "map-swatch");
    c.width = c.height = 32;
    var g = c.getContext("2d");
    g.scale(2, 2);
    shapePath(g, shape, 8, 8, 5.5);
    g.fillStyle = color;
    g.fill();
    return c;
  }
  function renderLegend() {
    legendEl.textContent = "";
    var det = el("details");
    det.open = !(window.innerWidth < 700);
    det.appendChild(el("summary", null, "Legend"));
    var ul = el("ul");
    var add = function (color, shape, label, count) {
      var li = el("li");
      li.appendChild(swatch(color, shape));
      li.appendChild(el("span", null, label + (count != null ? " (" + count + ")" : "")));
      ul.appendChild(li);
    };
    var counts = {};
    var key = state.color === "type" ? "type" : state.color === "health" ? "health" : "status";
    shown.forEach(function (n) { counts[n[key]] = (counts[n[key]] || 0) + 1; });
    if (state.color === "type") {
      data.types.forEach(function (t) {
        if (counts[t.key]) { var s = typeStyle(t.key); add(hue(s[0]), s[1], t.label, counts[t.key]); }
      });
    } else if (state.color === "health") {
      ["bad", "warn", "ok", "off"].forEach(function (h) {
        if (counts[h]) add(HEALTH[h].color, "circle", HEALTH[h].icon + " " + HEALTH[h].label, counts[h]);
      });
      ul.appendChild(el("li", "muted small", "Shape shows the type."));
    } else {
      ["active", "planned", "missing", "retired"].forEach(function (s) {
        if (counts[s]) add(STATUS[s].hex || hue(STATUS[s].hue), "circle", STATUS[s].label, counts[s]);
      });
      ul.appendChild(el("li", "muted small", "Shape shows the type."));
    }
    var lines = el("li", "map-line-key");
    [["solid", "discovered"], ["dashed", "manual"], ["dotted", "bridged"]].forEach(function (l) {
      if (l[1] === "bridged" && !state.bridge) return;
      var pair = el("span", "map-line-pair");
      pair.appendChild(el("span", "map-line " + l[0]));
      pair.appendChild(el("span", null, l[1]));
      lines.appendChild(pair);
    });
    ul.appendChild(lines);
    det.appendChild(ul);
    legendEl.appendChild(det);
  }

  // ---- Filters ---------------------------------------------------------
  // Excluding lists (types, kinds, statuses, sources) start with
  // everything ticked; including lists (host groups, tags) start empty,
  // meaning no restriction.
  function buildFilters() {
    listsEl.textContent = "";
    var count = function (f) {
      var c = {};
      nodes.forEach(function (n) { [].concat(f(n)).forEach(function (v) { c[v] = (c[v] || 0) + 1; }); });
      return c;
    };
    var tc = count(function (n) { return n.type; });
    var types = data.types.filter(function (t) { return tc[t.key]; }).map(function (t) {
      var s = typeStyle(t.key);
      return { key: t.key, label: t.label, n: tc[t.key], color: hue(s[0]), shape: s[1] };
    });
    group("Types", "xt", true, types);
    var kc = {};
    edges.forEach(function (e) { kc[e.kind] = (kc[e.kind] || 0) + 1; });
    group("Relationships", "xk", true, data.kinds.map(function (k) {
      return { key: k, label: k.replace(/_/g, " "), n: kc[k] || 0 };
    }));
    var sc = count(function (n) { return n.status; });
    group("Status", "xs", true, ["active", "planned", "missing", "retired"].map(function (s) {
      return { key: s, label: STATUS[s].label, n: sc[s] || 0 };
    }));
    var oc = count(function (n) { return n.source; });
    group("Source", "xo", true, Object.keys(oc).sort().map(function (s) {
      return { key: s, label: SOURCES[s] || s, n: oc[s] };
    }));
    if (data.groups.length) {
      var gc = count(function (n) { return n.groups; });
      group("Host groups", "g", false, data.groups.map(function (g) {
        return { key: g.key, label: g.label, n: gc[g.key] || 0 };
      }), "None ticked: every group. Agentless CIs related to a ticked group's CIs stay.");
    }
    var tagc = count(function (n) { return n.tags; });
    var tags = Object.keys(tagc).sort();
    if (tags.length) {
      group("Tags", "tag", false, tags.map(function (t) { return { key: t, label: t, n: tagc[t] }; }),
        "None ticked: tagged or not.");
    }
  }

  function group(title, param, excluding, items, hint) {
    var fs = el("fieldset", "map-group");
    fs.dataset.param = param;
    var lg = el("legend", null, title);
    fs.appendChild(lg);
    var bar = el("div", "map-allnone small");
    bar.appendChild(button(excluding ? "All" : "Clear", "link", function () {
      state[param] = new Set();
      syncControls();
      recompute(true);
    }));
    if (excluding) {
      bar.appendChild(button("None", "link", function () {
        state[param] = new Set(items.map(function (i) { return i.key; }));
        syncControls();
        recompute(true);
      }));
    }
    fs.appendChild(bar);
    if (hint) fs.appendChild(el("p", "muted small", hint));
    var box = el("div", "map-checks" + (items.length > 12 ? " long" : ""));
    items.forEach(function (it) {
      var lab = el("label", "check");
      var cb = el("input");
      cb.type = "checkbox";
      cb.value = it.key;
      cb.addEventListener("change", function () {
        var on = cb.checked;
        if (excluding === on) state[param].delete(it.key); else state[param].add(it.key);
        recompute(true);
      });
      lab.appendChild(cb);
      if (it.color) lab.appendChild(swatch(it.color, it.shape));
      lab.appendChild(el("span", null, it.label));
      lab.appendChild(el("span", "muted", " " + it.n));
      box.appendChild(lab);
    });
    fs.appendChild(box);
    listsEl.appendChild(fs);
  }

  function syncControls() {
    root.querySelectorAll("[data-param]").forEach(function (fs) {
      var p = fs.dataset.param, excluding = ["xt", "xk", "xs", "xo"].indexOf(p) >= 0;
      fs.querySelectorAll("input[type=checkbox]").forEach(function (cb) {
        cb.checked = excluding ? !state[p].has(cb.value) : state[p].has(cb.value);
      });
    });
    root.querySelector('[data-f="q"]').value = state.q;
    root.querySelector('[data-f="color"]').value = state.color;
    root.querySelector('[data-f="bridge"]').checked = state.bridge;
    root.querySelector('[data-f="iso"]').checked = state.iso;
    root.querySelector('[data-f="labels"]').checked = state.labels;
    root.querySelector('[data-f="only"]').checked = state.only;
    root.querySelector('[data-f="depth"]').value = String(state.depth);
  }

  function updateFocusBox() {
    var n = state.focus && byId[state.focus];
    focusBox.hidden = !n;
    if (n) focusBox.querySelector("[data-focus-name]").textContent = n.name;
  }

  var qTimer = 0;
  root.querySelector('[data-f="q"]').addEventListener("input", function (ev) {
    clearTimeout(qTimer);
    qTimer = setTimeout(function () {
      state.q = ev.target.value;
      recompute(state.only);
    }, 150);
  });
  root.querySelector('[data-f="q"]').addEventListener("keydown", function (ev) {
    if (ev.key !== "Enter") return;
    ev.preventDefault();
    if (state.q !== ev.target.value) {
      clearTimeout(qTimer);
      state.q = ev.target.value;
      recompute(state.only);
    }
    var first = shown.filter(matches).sort(function (a, b) { return b.deg - a.deg; })[0];
    if (first) { select(first); centerOn(first); }
  });
  [["color", "change"], ["depth", "change"]].forEach(function (f) {
    root.querySelector('[data-f="' + f[0] + '"]').addEventListener(f[1], function (ev) {
      if (f[0] === "depth") { state.depth = parseInt(ev.target.value, 10) || 0; pendingFit = true; recompute(true); return; }
      state.color = ev.target.value;
      recompute(false);
    });
  });
  ["bridge", "iso", "labels", "only"].forEach(function (f) {
    root.querySelector('[data-f="' + f + '"]').addEventListener("change", function (ev) {
      state[f] = ev.target.checked;
      recompute(f !== "labels");
    });
  });

  // ---- Toolbar ---------------------------------------------------------
  function act(name, fn) {
    root.parentNode.querySelectorAll('[data-act="' + name + '"]').forEach(function (b) { b.addEventListener("click", fn); });
  }
  act("fit", fit);
  act("relayout", function () {
    nodes.forEach(function (n) { n.x = n.y = NaN; n.fx = n.fy = null; n.vx = n.vy = 0; });
    rand = rng(Math.floor(Math.random() * 1e9));
    placeNew();
    settle(300);
    pendingFit = true;
    heat(1);
    fit();
  });
  act("freeze", function (ev) {
    frozen = !frozen;
    ev.currentTarget.setAttribute("aria-pressed", String(frozen));
    ev.currentTarget.textContent = frozen ? "Resume" : "Freeze";
    if (!frozen) heat(0.3);
  });
  act("reload", load);
  act("unfocus", function () { setFocus(""); });
  act("reset", function () {
    var keepView = state.view;
    state = defaults();
    state.view = keepView;
    syncControls();
    pendingFit = true;
    recompute(true);
  });
  act("png", function () {
    var stamp = new Date();
    var day = stamp.getFullYear() + "-" + String(stamp.getMonth() + 1).padStart(2, "0") + "-" + String(stamp.getDate()).padStart(2, "0");
    map.png("Baseline CI map · " + shown.length + " CIs, " + drawn.length + " relationships · " + stamp.toLocaleString(), "ci-map-" + day + ".png");
  });

  // ---- Start -----------------------------------------------------------
  readTheme();
  baselineMap.onTheme(function () {
    readTheme();
    if (data) { buildFilters(); syncControls(); renderLegend(); }
    draw();
  });
  readURL();
  syncControls();
  map = baselineMap.create(canvas, stage, pointer);
  view = map.view;
  load();
})();
