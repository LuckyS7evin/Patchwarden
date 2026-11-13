// Journal d'une tâche en direct (Server-Sent Events). Sans ce script, la page
// affiche l'état au moment du chargement.
(function () {
  "use strict";
  var pre = document.getElementById("journal");
  if (!pre || !pre.dataset.flux || !window.EventSource) return;
  var follow = document.getElementById("suivre");
  var es = new EventSource(pre.dataset.flux);

  es.addEventListener("debut", function () {
    // Le serveur renvoie tout le journal à chaque (re)connexion.
    pre.textContent = "";
  });
  es.addEventListener("ligne", function (e) {
    var l = JSON.parse(e.data);
    var span = document.createElement("span");
    if (l.e) span.className = "err";
    span.textContent = l.h + "  " + l.x + "\n";
    pre.appendChild(span);
    if (!follow || follow.checked) pre.scrollTop = pre.scrollHeight;
  });
  es.addEventListener("fin", function () {
    es.close();
    window.location.reload();
  });
})();
