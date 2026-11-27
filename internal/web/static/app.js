// Petites améliorations de l'interface. Tout reste utilisable sans ce script :
// chaque ligne mène à la fiche de l'invité, chaque formulaire est classique.
(function () {
  "use strict";

  // Raccourci « / » : recherche.
  document.addEventListener("keydown", function (e) {
    var t = e.target;
    if (e.key !== "/" || e.ctrlKey || e.metaKey || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return;
    var q = document.getElementById("recherche");
    if (q) { e.preventDefault(); q.focus(); }
  });

  // Inventaire : aperçu de l'invité dans un tiroir.
  var drawer = document.getElementById("tiroir");
  var current = null;
  function closeDrawer() {
    if (!drawer) return;
    drawer.hidden = true;
    drawer.innerHTML = "";
    if (current) current.classList.remove("sel");
    current = null;
  }
  function openDrawer(tr) {
    fetch(tr.dataset.apercu, { credentials: "same-origin", headers: { "X-Requested-With": "apercu" } })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.text(); })
      .then(function (html) {
        if (current) current.classList.remove("sel");
        current = tr; tr.classList.add("sel");
        drawer.innerHTML = html;
        drawer.hidden = false;
        var x = drawer.querySelector("[data-fermer]");
        if (x) { x.addEventListener("click", closeDrawer); x.focus(); }
      })
      .catch(function () { window.location.href = tr.dataset.fiche; });
  }
  if (drawer) {
    document.querySelectorAll("tr[data-apercu]").forEach(function (tr) {
      tr.addEventListener("click", function (e) {
        if (e.target.closest("a, button, form, input, select")) return;
        if (current === tr && !drawer.hidden) { closeDrawer(); return; }
        openDrawer(tr);
      });
    });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeDrawer(); });
  }

  // Filtres appliqués dès le choix dans une liste (le bouton reste sans script).
  document.querySelectorAll("form[data-auto]").forEach(function (f) {
    f.querySelectorAll("select").forEach(function (s) {
      s.addEventListener("change", function () { f.submit(); });
    });
    var b = f.querySelector("[data-auto-btn]");
    if (b) b.hidden = true;
  });

  // « Retour » / « Annuler » : page précédente si elle vient de PatchWarden,
  // sinon le lien indiqué.
  document.querySelectorAll("a[data-retour]").forEach(function (a) {
    a.addEventListener("click", function (e) {
      var ref = document.referrer;
      if (ref && ref.indexOf(window.location.origin + "/") === 0 && ref !== window.location.href && window.history.length > 1) {
        e.preventDefault();
        window.history.back();
      }
    });
  });

  // À traiter : barre de sélection.
  var bar = document.getElementById("lot");
  if (bar) {
    var form = bar.closest("form");
    var count = document.getElementById("lot-nombre");
    var boxes = form.querySelectorAll("input[name=sel]");
    var update = function () {
      var keys = {};
      boxes.forEach(function (b) { if (b.checked) keys[b.value.split(":")[0]] = true; });
      var n = Object.keys(keys).length;
      bar.hidden = n === 0;
      count.textContent = n + (n > 1 ? " invités sélectionnés" : " invité sélectionné");
    };
    boxes.forEach(function (b) { b.addEventListener("change", update); });
    form.querySelectorAll(".grp-all").forEach(function (all) {
      all.hidden = false;
      var sec = all.closest("section");
      all.addEventListener("change", function () {
        sec.querySelectorAll("input[name=sel]").forEach(function (b) { b.checked = all.checked; });
        update();
      });
    });
    var none = document.getElementById("lot-aucun");
    if (none) none.addEventListener("click", function () { boxes.forEach(function (b) { b.checked = false; }); update(); });
    update();
  }
})();
