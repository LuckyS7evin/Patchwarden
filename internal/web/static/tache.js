// Journal d'une tâche en direct (Server-Sent Events) et avancement des
// étapes. Sans ce script, la page affiche l'état au moment du chargement.
(function () {
  "use strict";
  var pre = document.getElementById("journal");
  if (!pre || !pre.dataset.flux || !window.EventSource) return;
  var follow = document.getElementById("suivre");
  var steps = Array.prototype.slice.call(document.querySelectorAll("#etapes .s"));
  var es = new EventSource(pre.dataset.flux);

  function has(text, markers) {
    text = text.replace("▶ vm-", "▶ lxc-"); // une VM a les mêmes verbes en vm-
    return (markers || "").split("|").some(function (m) { return m && text.indexOf(m) >= 0; });
  }
  // Mêmes règles que stepsFor (steps.go).
  function advance(text) {
    for (var i = 0; i < steps.length; i++) {
      var s = steps[i], st = s.dataset.etat;
      if (st === "encours" && has(text, s.dataset.fin)) { s.dataset.etat = "fait"; return; }
      if (st === "" && has(text, s.dataset.debut)) {
        for (var k = 0; k < i; k++) if (steps[k].dataset.etat === "encours") steps[k].dataset.etat = "fait";
        s.dataset.etat = has(text, s.dataset.fin) ? "fait" : "encours";
        return;
      }
    }
  }
  function cls(l) {
    var t = l.x.trim();
    if (l.e || /^(PW-ERREUR|PW-ALERTE|⚠)/.test(t)) return "err";
    if (/^(▶|PW:)/.test(t)) return "pw";
    if (t.indexOf("[OK]") >= 0 || t.indexOf("✔") === 0) return "okl";
    return "";
  }

  es.addEventListener("debut", function () {
    // Le serveur renvoie tout le journal à chaque (re)connexion.
    pre.textContent = "";
    steps.forEach(function (s) { s.dataset.etat = ""; });
  });
  es.addEventListener("ligne", function (e) {
    var l = JSON.parse(e.data);
    var span = document.createElement("span");
    span.className = cls(l);
    var h = document.createElement("span");
    h.className = "h";
    h.textContent = l.h;
    span.appendChild(h);
    span.appendChild(document.createTextNode("  " + l.x + "\n"));
    pre.appendChild(span);
    advance(l.x);
    if (!follow || follow.checked) pre.scrollTop = pre.scrollHeight;
  });
  es.addEventListener("fin", function () {
    es.close();
    window.location.reload();
  });
})();
