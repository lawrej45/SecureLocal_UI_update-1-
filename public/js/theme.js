/* Runs before first paint: sets theme + enables the .js class used by animations. */
(function () {
  var d = document.documentElement;
  d.classList.add('js');
  try {
    var t = localStorage.getItem('sl-theme');
    if (!t && window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches) t = 'dark';
    if (t) d.setAttribute('data-theme', t);
  } catch (e) {}
})();
