// Replaces the server-rendered SVG charts on a host's Metrics tab with
// interactive uPlot charts: hover for values, drag to zoom, double-click to
// zoom out. Without JavaScript (or if anything here fails) the SVG stays.
(function () {
  "use strict";
  if (!window.uPlot || !window.fetch || !document.querySelectorAll) return;

  var css = getComputedStyle(document.documentElement);
  function token(name) { return css.getPropertyValue(name).trim(); }

  var units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  function bytes(v) {
    var i = 0;
    while (Math.abs(v) >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + units[i];
  }
  function compact(v) {
    var a = Math.abs(v);
    if (a >= 1e9) return +(v / 1e9).toFixed(1) + "G";
    if (a >= 1e6) return +(v / 1e6).toFixed(1) + "M";
    if (a >= 1e3) return +(v / 1e3).toFixed(1) + "k";
    if (a === Math.trunc(a)) return v.toFixed(0);
    return +v.toFixed(a >= 10 ? 1 : 2) + "";
  }
  function formatter(unit) {
    switch (unit) {
      case "%": return function (v) { return v.toFixed(v < 10 && v !== 0 ? 1 : 0) + "%"; };
      case "bytes": return bytes;
      case "bytes/s": return function (v) { return bytes(v) + "/s"; };
      case "°C": return function (v) { return v.toFixed(0) + "°C"; };
      case "/s": return function (v) { return compact(v) + "/s"; };
    }
    return compact;
  }

  // Byte axes step by powers of two of whole units: 2 GiB, not 2.3 GiB.
  var binaryIncrs = [];
  for (var k = 0; k < 6; k++) {
    [1, 2, 4, 8, 16, 32, 64, 128, 256, 512].forEach(function (m) { binaryIncrs.push(m * Math.pow(1024, k)); });
  }

  function chart(fig, d) {
    var plot = fig.querySelector(".chart-plot");
    var fmt = formatter(d.unit);
    var muted = token("--muted"), grid = token("--border");
    var stamp = uPlot.fmtDate("{MMM} {D} {HH}:{mm}");
    var series = [{ value: function (u, v) { return v == null ? "—" : stamp(uPlot.tzDate(new Date(v * 1e3), d.tz)); } }];
    d.labels.forEach(function (label, i) {
      series.push({
        label: label,
        stroke: token("--s" + (i % 8)),
        width: 1.5,
        spanGaps: false,
        value: function (u, v) { return v == null ? "—" : fmt(v); },
      });
    });
    var axis = { stroke: muted, grid: { stroke: grid, width: 1 }, ticks: { stroke: grid, width: 1 } };
    // Times as the SVG charts show them: 24-hour clock, dates for long spans.
    var timeFmt = uPlot.fmtDate(d.to - d.from > 2 * 86400 ? "{MMM} {D}" : "{HH}:{mm}");
    // Room for the widest y label ("1023.9 MiB/s").
    var ySize = d.unit === "bytes" || d.unit === "bytes/s" ? 92 : 64;
    var opts = {
      width: plot.clientWidth,
      height: 220,
      series: series,
      tzDate: function (ts) { return uPlot.tzDate(new Date(ts * 1e3), d.tz); },
      scales: {
        x: { time: true, min: d.from, max: d.to },
        y: { range: function (u, min, max) { return [0, d.max || (max > 0 ? max * 1.05 : 1)]; } },
      },
      axes: [
        Object.assign({}, axis, {
          values: function (u, vals) { return vals.map(function (v) { return timeFmt(uPlot.tzDate(new Date(v * 1e3), d.tz)); }); },
        }),
        Object.assign({}, axis, { size: ySize, incrs: ySize > 64 ? binaryIncrs : undefined, values: function (u, vals) { return vals.map(fmt); } }),
      ],
      cursor: { drag: { x: true, y: false } },
      legend: { live: true },
    };
    var data = [d.times].concat(d.values);
    plot.textContent = "";
    fig.classList.add("live");
    var u = new uPlot(opts, data, plot);
    if (window.ResizeObserver) {
      new ResizeObserver(function () {
        if (plot.clientWidth !== u.width) u.setSize({ width: plot.clientWidth, height: 220 });
      }).observe(plot);
    }
  }

  document.querySelectorAll("figure.chart[data-src]").forEach(function (fig) {
    fetch(fig.getAttribute("data-src"), { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) { if (d.times.length) chart(fig, d); })
      .catch(function () { /* keep the SVG */ });
  });
})();
