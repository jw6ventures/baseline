// The canvas core shared by the CI map (cimap.js) and the workflow diagram
// (wfmap.js): a canvas that fills its stage at the device's pixel ratio, a
// view that pans and zooms (drag, wheel, pinch, keys), pointer handling
// that tells clicks, drags and hovers apart, the page's theme colours,
// node shapes and PNG export. What is drawn and what a drag does belong to
// the page script.
(function () {
  "use strict";

  var dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)");

  // theme reads the colours of the page's stylesheet.
  function theme() {
    var css = getComputedStyle(document.documentElement);
    var t = function (n) { return css.getPropertyValue(n).trim(); };
    return {
      dark: !!(dark && dark.matches), text: t("--text"), muted: t("--muted"), border: t("--border"),
      surface: t("--surface"), bg: t("--bg"), accent: t("--accent"), font: t("--font") || "system-ui, sans-serif",
      ok: t("--ok"), okBg: t("--ok-bg"), warn: t("--warn"), warnBg: t("--warn-bg"), codeBg: t("--code-bg")
    };
  }
  function onTheme(fn) { if (dark && dark.addEventListener) dark.addEventListener("change", fn); }

  function shapePath(c, shape, x, y, r) {
    c.beginPath();
    switch (shape) {
      case "square":
        var s = r * 0.9;
        if (c.roundRect) c.roundRect(x - s, y - s, s * 2, s * 2, Math.min(3, s / 2)); else c.rect(x - s, y - s, s * 2, s * 2);
        break;
      case "diamond":
        var d = r * 1.25;
        c.moveTo(x, y - d); c.lineTo(x + d, y); c.lineTo(x, y + d); c.lineTo(x - d, y); c.closePath();
        break;
      case "triangle":
        var t = r * 1.3;
        c.moveTo(x, y - t); c.lineTo(x + t * 0.95, y + t * 0.6); c.lineTo(x - t * 0.95, y + t * 0.6); c.closePath();
        break;
      case "hexagon":
        var hx = r * 1.15;
        for (var i = 0; i < 6; i++) {
          var a = Math.PI / 3 * i + Math.PI / 6;
          if (i) c.lineTo(x + hx * Math.cos(a), y + hx * Math.sin(a)); else c.moveTo(x + hx * Math.cos(a), y + hx * Math.sin(a));
        }
        c.closePath();
        break;
      default:
        c.arc(x, y, r, 0, Math.PI * 2);
    }
  }

  // arrowHead fills an arrow head with its tip at (x, y), pointing along
  // angle a.
  function arrowHead(c, x, y, a, len) {
    c.beginPath();
    c.moveTo(x, y);
    c.lineTo(x - len * Math.cos(a - 0.4), y - len * Math.sin(a - 0.4));
    c.lineTo(x - len * Math.cos(a + 0.4), y - len * Math.sin(a + 0.4));
    c.closePath();
    c.fill();
  }

  function dist(a, b) { return Math.hypot(a.x - b.x, a.y - b.y) || 1; }
  function mid(a, b) { return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }; }

  // create sets up a map on canvas inside stage. o has:
  //   paint(c, w, h, px, view)   draws everything (required)
  //   hit(p)                     the item at screen point p, or null
  //   drag(item, p, ev)          starts dragging item (null: the background);
  //                              returns {move(p), end(p)} to handle it, or
  //                              null to pan the view
  //   click(item, ev)            a press and release without moving
  //   dblclick(item, p, ev)      default: zoom in on the background
  //   hover(item, p)             the pointer moved without a button down
  //   leave()                    the pointer left the canvas
  //   cursor(item)               the cursor over an item (default "pointer")
  //   viewChanged()              after a pan or zoom ends
  //   keydown(ev)                return true when handled
  function create(canvas, stage, o) {
    var ctx = canvas.getContext("2d");
    var m = {
      W: 0, H: 0, DPR: 1, view: { x: 0, y: 0, k: 1 }, minK: 0.03, maxK: 8, dragging: false,
      canvas: canvas, ctx: ctx
    };
    canvas.tabIndex = 0;

    m.toWorld = function (sx, sy) { return { x: (sx - m.view.x) / m.view.k, y: (sy - m.view.y) / m.view.k }; };
    m.toScreen = function (x, y) { return { x: x * m.view.k + m.view.x, y: y * m.view.k + m.view.y }; };
    m.clampK = function (k) { return Math.max(m.minK, Math.min(m.maxK, k)); };
    // setView centres the view on world point (cx, cy) at zoom k.
    m.setView = function (v) {
      m.view.k = m.clampK(v.k);
      m.view.x = m.W / 2 - v.cx * m.view.k;
      m.view.y = m.H / 2 - v.cy * m.view.k;
    };
    m.center = function () { return m.toWorld(m.W / 2, m.H / 2); };
    // fit shows the world box {x0, y0, x1, y1} with pad pixels around it,
    // zoomed in no further than maxK.
    m.fit = function (b, pad, maxK) {
      if (!m.W || !isFinite(b.x0)) return;
      pad = pad == null ? 60 : pad;
      var k = Math.min((m.W - pad * 2) / Math.max(b.x1 - b.x0, 1), (m.H - pad * 2) / Math.max(b.y1 - b.y0, 1), maxK || 2.2);
      m.setView({ cx: (b.x0 + b.x1) / 2, cy: (b.y0 + b.y1) / 2, k: k });
      m.draw();
    };
    m.zoomAt = function (p, f) {
      var v = m.view, k = m.clampK(v.k * f);
      f = k / v.k;
      v.x = p.x - (p.x - v.x) * f;
      v.y = p.y - (p.y - v.y) * f;
      v.k = k;
      m.draw();
    };

    // render paints now; draw paints on the next frame, at most once.
    m.render = function () { if (m.W) o.paint(ctx, m.W, m.H, m.DPR, m.view); };
    var queued = false;
    m.draw = function () {
      if (queued) return;
      queued = true;
      requestAnimationFrame(function () { queued = false; m.render(); });
    };

    m.resize = function () {
      var r = stage.getBoundingClientRect();
      var c = m.W ? m.center() : null;
      m.W = Math.max(1, Math.round(r.width));
      m.H = Math.max(1, Math.round(r.height));
      m.DPR = window.devicePixelRatio || 1;
      canvas.width = Math.round(m.W * m.DPR);
      canvas.height = Math.round(m.H * m.DPR);
      canvas.style.width = m.W + "px";
      canvas.style.height = m.H + "px";
      if (c) m.setView({ cx: c.x, cy: c.y, k: m.view.k });
      m.draw();
    };
    if (window.ResizeObserver) new ResizeObserver(m.resize).observe(stage);
    else window.addEventListener("resize", m.resize);

    // png downloads the current view with a footer line of text.
    m.png = function (footer, filename) {
      var scale = Math.max(2, m.DPR);
      var off = document.createElement("canvas");
      off.width = Math.round(m.W * scale);
      off.height = Math.round((m.H + 28) * scale);
      var c = off.getContext("2d");
      var th = theme();
      o.paint(c, m.W, m.H, scale, m.view);
      c.setTransform(scale, 0, 0, scale, 0, 0);
      c.fillStyle = th.surface;
      c.fillRect(0, m.H, m.W, 28);
      c.fillStyle = th.border;
      c.fillRect(0, m.H, m.W, 1);
      c.fillStyle = th.muted;
      c.font = "11px " + th.font;
      c.textAlign = "left";
      c.textBaseline = "bottom";
      c.fillText(footer, 10, m.H + 22);
      off.toBlob(function (blob) {
        if (!blob) return;
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 5000);
      }, "image/png");
    };

    // ---- Pointers ------------------------------------------------------
    function local(ev) {
      var r = canvas.getBoundingClientRect();
      return { x: ev.clientX - r.left, y: ev.clientY - r.top };
    }
    m.local = local;
    var hit = function (p) { return o.hit ? o.hit(p) : null; };
    var cursor = function (it) { return it ? (o.cursor ? o.cursor(it) : "pointer") : "grab"; };
    var changed = function () { if (o.viewChanged) o.viewChanged(); };

    var pointers = new Map();
    var drag = null;   // {mode: "pan"|"item"|"pinch", ...}
    canvas.addEventListener("pointerdown", function (ev) {
      if (ev.button > 0) return;
      canvas.focus({ preventScroll: true });
      var p = local(ev);
      pointers.set(ev.pointerId, p);
      canvas.setPointerCapture(ev.pointerId);
      if (pointers.size === 2) {
        if (drag && drag.h && drag.moved && drag.h.end) drag.h.end(p, true);
        var pts = Array.from(pointers.values());
        drag = { mode: "pinch", d: dist(pts[0], pts[1]), k: m.view.k, mid: mid(pts[0], pts[1]), moved: true };
        return;
      }
      var it = hit(p);
      var h = o.drag ? o.drag(it, p, ev) : null;
      drag = h ? { mode: "item", it: it, h: h, start: p, moved: false }
        : { mode: "pan", it: it, start: p, vx: m.view.x, vy: m.view.y, moved: false };
    });
    canvas.addEventListener("pointermove", function (ev) {
      var p = local(ev);
      if (pointers.has(ev.pointerId)) pointers.set(ev.pointerId, p);
      if (!drag) {
        var it = hit(p);
        canvas.style.cursor = cursor(it);
        if (o.hover) o.hover(it, p, ev);
        return;
      }
      if (drag.mode === "pinch") {
        if (pointers.size !== 2) return;
        var pts = Array.from(pointers.values());
        var c = mid(pts[0], pts[1]);
        m.zoomAt(drag.mid, m.clampK(drag.k * dist(pts[0], pts[1]) / drag.d) / m.view.k);
        m.view.x += c.x - drag.mid.x; m.view.y += c.y - drag.mid.y;
        drag.mid = c;
        m.draw();
        return;
      }
      if (!drag.moved && Math.abs(p.x - drag.start.x) + Math.abs(p.y - drag.start.y) < 4) return;
      drag.moved = true;
      m.dragging = true;
      if (drag.mode === "pan") {
        m.view.x = drag.vx + p.x - drag.start.x;
        m.view.y = drag.vy + p.y - drag.start.y;
        canvas.style.cursor = "grabbing";
        m.draw();
      } else {
        drag.h.move(p, ev);
      }
    });
    function endPointer(ev) {
      pointers.delete(ev.pointerId);
      if (!drag) return;
      if (drag.mode === "pinch") {
        if (!pointers.size) { drag = null; m.dragging = false; changed(); }
        return;
      }
      var d = drag;
      drag = null;
      m.dragging = false;
      var p = local(ev);
      if (d.mode === "item" && d.h.end) d.h.end(p, d.moved, ev);
      if (!d.moved && ev.type === "pointerup") {
        if (o.click) o.click(d.it, ev);
      } else if (d.mode === "pan") {
        changed();
      }
      canvas.style.cursor = cursor(hit(p));
    }
    canvas.addEventListener("pointerup", endPointer);
    canvas.addEventListener("pointercancel", endPointer);
    canvas.addEventListener("pointerleave", function () { if (!drag && o.leave) o.leave(); });
    canvas.addEventListener("dblclick", function (ev) {
      var p = local(ev);
      var it = hit(p);
      if (o.dblclick && o.dblclick(it, p, ev)) return;
      if (!it) { m.zoomAt(p, 1.6); changed(); }
    });
    canvas.addEventListener("wheel", function (ev) {
      ev.preventDefault();
      var f = Math.exp(-ev.deltaY * (ev.deltaMode === 1 ? 0.05 : 0.0018));
      m.zoomAt(local(ev), f);
      changed();
    }, { passive: false });
    canvas.addEventListener("keydown", function (ev) {
      if (ev.target !== canvas) return;
      if (o.keydown && o.keydown(ev)) { ev.preventDefault(); return; }
      if (ev.key === "+" || ev.key === "=") m.zoomAt({ x: m.W / 2, y: m.H / 2 }, 1.25);
      else if (ev.key === "-") m.zoomAt({ x: m.W / 2, y: m.H / 2 }, 0.8);
      else return;
      changed();
      ev.preventDefault();
    });

    m.resize();
    return m;
  }

  window.baselineMap = { create: create, theme: theme, onTheme: onTheme, shapePath: shapePath, arrowHead: arrowHead };
})();
