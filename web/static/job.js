// Live job output (docs/architecture.md §6): appends what the server streams
// over Server-Sent Events, and reloads the page when the job ends so the
// result shows. Without JS the page shows the output so far.
(function () {
  "use strict";
  var pre = document.getElementById("output");
  if (!pre || !window.EventSource) return;
  var follow = true;
  window.addEventListener("scroll", function () {
    follow = window.innerHeight + window.scrollY >= document.body.scrollHeight - 40;
  });
  var es = new EventSource(pre.dataset.src);
  es.addEventListener("output", function (e) {
    var d = JSON.parse(e.data);
    var span = document.createElement("span");
    span.className = d.s;
    span.textContent = d.t;
    pre.appendChild(span);
    var wait = document.getElementById("output-wait");
    if (wait) wait.remove();
    if (follow) window.scrollTo(0, document.body.scrollHeight);
  });
  es.addEventListener("state", function (e) {
    var d = JSON.parse(e.data);
    var tag = document.querySelector("#job-state .tag");
    if (tag) tag.textContent = d.reboot && d.state === "running" ? "rebooting" : d.state.replace("_", " ");
  });
  es.addEventListener("done", function () {
    es.close();
    window.location.reload();
  });
})();
