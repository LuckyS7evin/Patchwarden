// Thème de l'interface : « auto » (suit le système), « light » ou « dark ».
// Chargé dans <head> pour appliquer le choix avant l'affichage.
(function () {
  "use strict";
  var KEY = "pw-theme", root = document.documentElement;
  function read() { try { return localStorage.getItem(KEY) || "auto"; } catch (e) { return "auto"; } }
  function apply(t) { if (t === "light" || t === "dark") root.setAttribute("data-theme", t); else root.removeAttribute("data-theme"); }
  apply(read());
  document.addEventListener("DOMContentLoaded", function () {
    var btns = document.querySelectorAll("[data-theme-set]");
    function show(t) { btns.forEach(function (b) { b.setAttribute("aria-pressed", b.dataset.themeSet === t ? "true" : "false"); }); }
    show(read());
    btns.forEach(function (b) {
      b.hidden = false;
      b.addEventListener("click", function () {
        var t = b.dataset.themeSet;
        try { localStorage.setItem(KEY, t); } catch (e) {}
        apply(t); show(t);
      });
    });
  });
})();
