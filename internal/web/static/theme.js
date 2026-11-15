// Thème de l'interface : « auto » (suit le système), « clair » ou « sombre ».
// Chargé dans <head> pour appliquer le choix avant l'affichage.
(function () {
  "use strict";
  var KEY = "pw-theme", root = document.documentElement;
  function read() { try { return localStorage.getItem(KEY) || "auto"; } catch (e) { return "auto"; } }
  function apply(t) { if (t === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", t); }
  apply(read());
  var next = { auto: "light", light: "dark", dark: "auto" };
  var label = { auto: "Thème : automatique", light: "Thème : clair", dark: "Thème : sombre" };
  var icon = { auto: "Thème : auto", light: "Thème : clair", dark: "Thème : sombre" };
  document.addEventListener("DOMContentLoaded", function () {
    var b = document.getElementById("theme-toggle");
    if (!b) return;
    function show(t) { b.textContent = icon[t]; b.title = label[t] + " (cliquer pour changer)"; b.setAttribute("aria-label", label[t]); }
    show(read());
    b.addEventListener("click", function () {
      var t = next[read()] || "auto";
      try { localStorage.setItem(KEY, t); } catch (e) {}
      apply(t); show(t);
    });
  });
})();
