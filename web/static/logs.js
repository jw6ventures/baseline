// Follows a container's log (container_logs.html): appends the lines the
// server streams over Server-Sent Events until the log ends, the server
// stops following it, or Stop is pressed. Old lines are trimmed so a long
// session doesn't grow the page without bound. logview.js filters the new
// lines and keeps the end of the log in view.
(function () {
  "use strict";
  var pre = document.getElementById("logs");
  if (!pre || !window.EventSource) return;
  var maxLines = 20000;
  var state = document.getElementById("logs-state");
  var stopBtn = document.getElementById("logs-stop");
  var dropped = 0;
  function setState(text, cls) {
    if (!state) return;
    state.textContent = text;
    state.className = "tag " + cls;
  }
  function clearWait() {
    var wait = document.getElementById("logs-wait");
    if (wait) wait.remove();
  }
  var es = new EventSource(pre.dataset.src);
  function finish(text, cls) {
    es.close();
    clearWait();
    setState(text, cls);
    if (stopBtn) stopBtn.hidden = true;
  }
  es.addEventListener("open", function () { setState("following", "ok"); });
  es.addEventListener("lines", function (e) {
    var d = JSON.parse(e.data);
    clearWait();
    setState("following", "ok");
    var frag = document.createDocumentFragment();
    var added = (d.l || []).map(function (l) {
      var span = document.createElement("span");
      span.className = l.s;
      span.textContent = l.t + "\n";
      frag.appendChild(span);
      return span;
    });
    pre.appendChild(frag);
    while (pre.childNodes.length > maxLines) pre.removeChild(pre.firstChild);
    if (d.d) {
      dropped += d.d;
      var p = document.getElementById("logs-dropped");
      p.textContent = dropped + " lines were left out: the container wrote faster than they could be sent.";
      p.hidden = false;
    }
    pre.dispatchEvent(new CustomEvent("logview:lines", { detail: { nodes: added } }));
  });
  es.addEventListener("done", function (e) {
    var d = JSON.parse(e.data);
    if (d.error) {
      var p = document.getElementById("logs-error");
      p.textContent = d.error;
      p.hidden = false;
      finish("stopped", "warn");
    } else {
      finish("ended", "");
    }
  });
  es.addEventListener("error", function () {
    // Don't let the browser reconnect: it would read the tail again.
    if (es.readyState !== EventSource.CLOSED) finish("disconnected", "warn");
  });
  if (stopBtn) stopBtn.addEventListener("click", function () { finish("stopped", ""); });
})();
