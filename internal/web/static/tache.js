// Journal d'une tâche en direct (Server-Sent Events) et avancement des
// étapes. Sans ce script, la page affiche l'état au moment du chargement.
(function () {
  "use strict";
  var pre = document.getElementById("journal");
  if (!pre || !pre.dataset.flux || !window.EventSource) return;
  var follow = document.getElementById("suivre");
  var steps = Array.prototype.slice.call(document.querySelectorAll("#etapes .s"));
  var es = new EventSource(pre.dataset.flux);
  var etat = pre.dataset.flux.replace(/\/flux$/, "/etat");
  var heard = false, errors = 0, poll = null;

  function checkEnd() {
    fetch(etat, { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { if (j && j.fini) window.location.reload(); })
      .catch(function () {});
  }
  // Sans flux en direct (proxy, réseau, navigateur) : la page suit l'état de
  // la tâche et se recharge régulièrement, puis à la fin.
  function fallback() {
    if (poll) return;
    es.close();
    poll = setInterval(checkEnd, 4000);
    setTimeout(function () { window.location.reload(); }, 15000);
  }
  es.onerror = function () {
    errors++;
    if (errors >= 3 || es.readyState === 2) fallback();
  };
  setTimeout(function () { if (!heard) fallback(); }, 8000);
  // Filet de sécurité : même si le flux semble ouvert mais ne transmet plus
  // rien (veille, réseau), l'état est vérifié toutes les 10 s.
  setInterval(checkEnd, 10000);
  // Retour sur l'onglet (téléphone en veille…) : la tâche a pu finir entre-temps.
  document.addEventListener("visibilitychange", function () { if (!document.hidden) checkEnd(); });

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
    heard = true;
    errors = 0;
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
