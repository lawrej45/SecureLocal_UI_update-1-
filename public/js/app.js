/* SecureLocal UI enhancements — progressive: everything works without JS. CSP-safe (no inline code). */
(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---- Theme toggle ---- */
  var root = document.documentElement;
  var tbtn = $('.theme-toggle');
  function paintTheme() { if (tbtn) tbtn.textContent = root.getAttribute('data-theme') === 'dark' ? '☀️' : '🌙'; }
  paintTheme();
  if (tbtn) tbtn.addEventListener('click', function () {
    var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('sl-theme', next); } catch (e) {}
    paintTheme();
  });

  /* ---- Nav: mobile menu, active link, shadow on scroll ---- */
  var toggle = $('.nav-toggle'), links = $('.navlinks');
  if (toggle && links) toggle.addEventListener('click', function () {
    var open = links.classList.toggle('open');
    toggle.setAttribute('aria-expanded', open);
  });
  $$('.navlinks a').forEach(function (a) {
    var p = a.getAttribute('href');
    if (p === location.pathname || (p !== '/' && location.pathname.indexOf(p) === 0 && p !== '/incidents' && p !== '/admin') ||
        (p === '/incidents' && location.pathname === '/incidents') || (p === '/admin' && location.pathname === '/admin')) a.classList.add('active');
  });
  var wrap = $('.nav-wrap');
  function onScroll() { if (wrap) wrap.classList.toggle('scrolled', window.scrollY > 8); }
  onScroll(); window.addEventListener('scroll', onScroll, { passive: true });

  /* ---- Scroll reveal with stagger ---- */
  var revealEls = $$('.card, .stat, .panel, .table-wrap, .hero, .page-head');
  revealEls.forEach(function (el, i) { el.classList.add('reveal'); el.style.setProperty('--i', (i % 6)); });
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (es) {
      es.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
    }, { threshold: 0 });
    revealEls.forEach(function (el) { io.observe(el); });
  } else revealEls.forEach(function (el) { el.classList.add('in'); });

  /* ---- Count-up numbers ---- */
  $$('.stat strong').forEach(function (el) {
    var end = parseInt(el.textContent, 10); if (isNaN(end) || reduce) return;
    var t0 = null; el.textContent = '0';
    function tick(t) { if (!t0) t0 = t; var p = Math.min((t - t0) / 1100, 1); el.textContent = Math.round(end * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(tick); }
    requestAnimationFrame(tick);
  });

  /* ---- Button ripple + loading state ---- */
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('.button'); if (!b || reduce) return;
    var r = b.getBoundingClientRect(), s = Math.max(r.width, r.height), d = document.createElement('span');
    d.className = 'ripple'; d.style.cssText = 'width:' + s + 'px;height:' + s + 'px;left:' + (e.clientX - r.left - s / 2) + 'px;top:' + (e.clientY - r.top - s / 2) + 'px';
    b.appendChild(d); setTimeout(function () { d.remove(); }, 600);
  });
  $$('form').forEach(function (f) {
    f.addEventListener('submit', function (e) {
      var msg = f.getAttribute('data-confirm');
      if (msg && !window.confirm(msg)) { e.preventDefault(); return; }
      var btn = $('button.button:not(.secondary):not(.danger), button.button.full', f) || $('button[type=submit], button:not([type])', f);
      if (btn && !e.defaultPrevented) setTimeout(function () { btn.classList.add('loading'); btn.disabled = true; }, 0);
    });
  });
  window.addEventListener('pageshow', function () { $$('.button.loading').forEach(function (b) { b.classList.remove('loading'); b.disabled = false; }); });

  /* ---- Gentle 3D tilt on feature cards (desktop only) ---- */
  if (!reduce && window.matchMedia && matchMedia('(hover:hover)').matches) {
    $$('.card-link, .stat').forEach(function (c) {
      c.classList.add('tilt');
      c.addEventListener('mousemove', function (e) {
        var r = c.getBoundingClientRect(), x = (e.clientX - r.left) / r.width - .5, y = (e.clientY - r.top) / r.height - .5;
        c.style.transform = 'perspective(700px) rotateX(' + (-y * 6) + 'deg) rotateY(' + (x * 7) + 'deg) translateY(-6px)';
      });
      c.addEventListener('mouseleave', function () { c.style.transform = ''; });
    });
    var art = $('.hero-art'), pz = $('.pizza');
    if (art && pz) art.addEventListener('mousemove', function (e) {
      var r = art.getBoundingClientRect(); pz.style.transform = 'translate(' + ((e.clientX - r.left) / r.width - .5) * 16 + 'px,' + ((e.clientY - r.top) / r.height - .5) * 16 + 'px)';
    });
    if (art && pz) art.addEventListener('mouseleave', function () { pz.style.transform = ''; });
  }

  /* ---- Password: show/hide + strength meter ---- */
  $$('input[type=password]').forEach(function (inp) {
    var w = document.createElement('div'); w.className = 'pw-wrap';
    inp.parentNode.insertBefore(w, inp); w.appendChild(inp);
    var eye = document.createElement('button'); eye.type = 'button'; eye.className = 'pw-eye'; eye.textContent = '👁️'; eye.setAttribute('aria-label', 'Show or hide password');
    eye.addEventListener('click', function () { var show = inp.type === 'password'; inp.type = show ? 'text' : 'password'; eye.textContent = show ? '🙈' : '👁️'; });
    w.appendChild(eye);
    if (inp.getAttribute('autocomplete') === 'new-password') {
      var meter = document.createElement('div'); meter.className = 'meter'; meter.innerHTML = '<i></i>';
      var label = document.createElement('div'); label.className = 'meter-label';
      var rules = document.createElement('div'); rules.className = 'rules';
      rules.innerHTML = '<span data-r="len">12+ characters</span><span data-r="mix">Upper &amp; lower</span><span data-r="num">Number</span><span data-r="sym">Symbol</span>';
      w.parentNode.insertBefore(meter, w.nextSibling); meter.after(label); label.after(rules);
      var uname = $('input[name=username]');
      inp.addEventListener('input', function () {
        var v = inp.value, c = { len: v.length >= 12, mix: /[a-z]/.test(v) && /[A-Z]/.test(v), num: /\d/.test(v), sym: /[^A-Za-z0-9]/.test(v) };
        var n = 0; Object.keys(c).forEach(function (k) { if (c[k]) n++; var s = $('[data-r=' + k + ']', rules); s.classList.toggle('ok', c[k]); });
        if (uname && uname.value.length > 2 && v.toLowerCase().indexOf(uname.value.toLowerCase()) > -1) n = Math.min(n, 1);
        var pct = v ? Math.max(12, n * 25) : 0, bar = $('i', meter);
        bar.style.width = pct + '%'; bar.style.background = n <= 1 ? '#dc2626' : n === 2 ? '#f59e0b' : n === 3 ? '#84cc16' : '#16a34a';
        label.textContent = !v ? '' : n <= 1 ? 'Too weak 😬' : n === 2 ? 'Getting there 🙂' : n === 3 ? 'Strong 💪' : 'Excellent 🔥';
      });
    }
  });

  /* ---- Quantity stepper + live order total ---- */
  $$('form[data-price]').forEach(function (f) {
    var q = $('input[name=quantity]', f); if (!q) return;
    var wrapQ = document.createElement('div'); wrapQ.className = 'qty';
    var minus = document.createElement('button'), plus = document.createElement('button');
    minus.type = plus.type = 'button'; minus.textContent = '−'; plus.textContent = '+'; minus.setAttribute('aria-label', 'Decrease'); plus.setAttribute('aria-label', 'Increase');
    q.parentNode.insertBefore(wrapQ, q); wrapQ.append(minus, q, plus);
    var tot = $('.live-total b', f), price = parseFloat(f.getAttribute('data-price')) || 0;
    function upd() { var n = Math.min(20, Math.max(1, parseInt(q.value, 10) || 1)); if (tot) { tot.textContent = '₱' + (n * price).toFixed(2); tot.classList.remove('bump'); void tot.offsetWidth; tot.classList.add('bump'); } }
    minus.addEventListener('click', function () { q.value = Math.max(1, (parseInt(q.value, 10) || 1) - 1); upd(); });
    plus.addEventListener('click', function () { q.value = Math.min(20, (parseInt(q.value, 10) || 1) + 1); upd(); });
    q.addEventListener('input', upd); upd();
  });
  /* only one order form open at a time */
  var dets = $$('details.order');
  dets.forEach(function (d) { d.addEventListener('toggle', function () { if (d.open) dets.forEach(function (o) { if (o !== d) o.open = false; }); }); });

  /* ---- Copy buttons (backup codes / setup key) ---- */
  var codes = $('.codes');
  if (codes) {
    var cb = document.createElement('button'); cb.type = 'button'; cb.className = 'button secondary small-button copy-btn'; cb.textContent = '📋 Copy all codes';
    codes.parentNode.insertBefore(cb, codes);
    cb.addEventListener('click', function () {
      var txt = $$('code', codes).map(function (c) { return c.textContent; }).join('\n');
      (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject()).then(function () { cb.textContent = '✅ Copied!'; }).catch(function () { cb.textContent = 'Select & copy manually'; });
      setTimeout(function () { cb.textContent = '📋 Copy all codes'; }, 2000);
    });
  }
  var sec = $('.secret code');
  if (sec) { sec.style.cursor = 'copy'; sec.title = 'Click to copy'; sec.addEventListener('click', function () { if (navigator.clipboard) navigator.clipboard.writeText(sec.textContent).then(function () { var o = sec.textContent; sec.textContent = 'Copied ✓'; setTimeout(function () { sec.textContent = o; }, 1300); }); }); }

  /* ---- Live table search ---- */
  $$('.table-wrap').forEach(function (tw) {
    var rows = $$('tbody tr', tw); if (rows.length < 6) return;
    var bar = document.createElement('div'); bar.className = 'table-search';
    bar.innerHTML = '<input type="search" placeholder="Search this table…" aria-label="Search table"><span></span>';
    tw.parentNode.insertBefore(bar, tw);
    var inp = $('input', bar), cnt = $('span', bar);
    inp.addEventListener('input', function () {
      var q = inp.value.toLowerCase(), n = 0;
      rows.forEach(function (r) { var m = r.textContent.toLowerCase().indexOf(q) > -1; r.style.display = m ? '' : 'none'; if (m) n++; });
      cnt.textContent = q ? n + ' of ' + rows.length + ' shown' : '';
    });
  });
})();

/* ================= CREATIVE LAYER ================= */
(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  var hover = window.matchMedia && matchMedia('(hover:hover)').matches;
  var rnd = function (a, b) { return a + Math.random() * (b - a); };

  /* scroll progress bar */
  var bar = document.createElement('div'); bar.className = 'progress'; document.body.appendChild(bar);
  function prog() { var h = document.documentElement.scrollHeight - innerHeight; bar.style.width = (h > 0 ? scrollY / h * 100 : 0) + '%'; }
  addEventListener('scroll', prog, { passive: true }); prog();

  /* floating food doodles in the background */
  if (!reduce) {
    var d = document.createElement('div'); d.className = 'doodles'; d.setAttribute('aria-hidden', 'true');
    var set = ['🍕', '🧀', '🍅', '🌿', '🍄', '🌶️', '🔥', '🫒', '🔐', '🛡️'];
    for (var i = 0; i < 16; i++) {
      var s = document.createElement('span'); s.textContent = set[i % set.length];
      s.style.cssText = 'left:' + rnd(1, 96) + '%;top:' + rnd(2, 92) + '%;font-size:' + rnd(22, 54) + 'px;--d:' + rnd(6, 13) + 's;--r:' + rnd(-25, 25) + 'deg;animation-delay:-' + rnd(0, 8) + 's';
      d.appendChild(s);
    }
    document.body.appendChild(d);
  }

  /* confetti */
  function confetti(x, y, n) {
    if (reduce) return;
    var bits = ['🍕', '🧀', '🍅', '🌿', '✨', '🔥', '🎉', '🍄'];
    for (var i = 0; i < (n || 26); i++) {
      var b = document.createElement('span'); b.className = 'confetti-bit'; b.textContent = bits[i % bits.length];
      var a = rnd(0, Math.PI * 2), dist = rnd(80, 260);
      b.style.cssText = 'left:' + x + 'px;top:' + y + 'px;--dx:' + Math.cos(a) * dist + 'px;--dy:' + (Math.sin(a) * dist + 120) + 'px;--rot:' + rnd(-540, 540) + 'deg;font-size:' + rnd(16, 30) + 'px';
      document.body.appendChild(b); setTimeout(function (el) { el.remove(); }.bind(null, b), 1400);
    }
  }
  window.slConfetti = confetti;
  var hp = $('.hero-art .pizza');
  if (hp) hp.addEventListener('click', function (e) { confetti(e.clientX, e.clientY); });
  if ($('.success')) setTimeout(function () { confetti(innerWidth / 2, 160, 34); }, 500);
  $$('.stamp.s-completed').forEach(function (st) { st.addEventListener('mouseenter', function () { var r = st.getBoundingClientRect(); confetti(r.left + r.width / 2, r.top, 12); }); });

  /* sparkle cursor trail */
  if (hover && !reduce) {
    var last = 0;
    addEventListener('mousemove', function (e) {
      var t = Date.now(); if (t - last < 70) return; last = t;
      var s = document.createElement('span'); s.className = 'spark'; s.textContent = ['✨', '🔥', '·'][Math.floor(Math.random() * 3)];
      s.style.left = e.clientX + 6 + 'px'; s.style.top = e.clientY + 6 + 'px'; s.style.setProperty('--sx', rnd(-18, 18) + 'px');
      document.body.appendChild(s); setTimeout(function () { s.remove(); }, 900);
    }, { passive: true });
    /* magnetic buttons */
    $$('.hero .button, .cta .button, .actions .button').forEach(function (b) {
      b.addEventListener('mousemove', function (e) { var r = b.getBoundingClientRect(); b.style.transform = 'translate(' + (e.clientX - r.left - r.width / 2) * .18 + 'px,' + (e.clientY - r.top - r.height / 2) * .28 + 'px)'; });
      b.addEventListener('mouseleave', function () { b.style.transform = ''; });
    });
  }

  /* marquee: duplicate content for a seamless loop */
  $$('.marquee .track').forEach(function (t) { t.innerHTML += t.innerHTML; });

  /* interactive pizza builder */
  var tops = $('#bTops'); if (!tops) return;
  var NS = 'http://www.w3.org/2000/svg', chosen = {}, pos = {};
  function ring(n) { var out = []; for (var i = 0; i < n; i++) { var a = rnd(0, 6.28), r = Math.sqrt(Math.random()) * 62; out.push([100 + Math.cos(a) * r, 104 + Math.sin(a) * r]); } return out; }
  function names(c) {
    if (!c.length) return 'Plain Dough Dream';
    if (c.length === 1) return c[0] + ' Delight';
    if (c.length === 2) return c[0] + ' & ' + c[1] + ' Duo';
    if (c.length === 3) return 'The ' + c[0] + ' Trio';
    return 'The Ultimate ' + c[c.length - 1] + ' Feast';
  }
  function refresh() {
    var list = Object.keys(chosen).filter(function (k) { return chosen[k]; });
    var nm = list.map(function (k) { return $('.chip[data-top="' + k + '"]').getAttribute('data-name'); });
    $('#bName').textContent = names(nm);
    var pr = $('#bPrice'); pr.textContent = '₱' + (249 + list.length * 30); pr.classList.remove('bump'); void pr.offsetWidth; pr.classList.add('bump');
  }
  function toggle(chip, force) {
    var k = chip.getAttribute('data-top'), on = force === undefined ? !chosen[k] : force;
    chosen[k] = on; chip.classList.toggle('on', on);
    var g = tops.querySelector('[data-k="' + k + '"]');
    if (g) g.remove();
    if (on) {
      g = document.createElementNS(NS, 'g'); g.setAttribute('data-k', k);
      ring(k === '🌿' || k === '🧀' ? 9 : 7).forEach(function (p, i) {
        var t = document.createElementNS(NS, 'text'); t.setAttribute('x', p[0]); t.setAttribute('y', p[1]); t.setAttribute('font-size', 17); t.setAttribute('text-anchor', 'middle'); t.setAttribute('class', 'topping');
        t.style.animationDelay = i * 45 + 'ms'; t.textContent = k; g.appendChild(t);
      });
      tops.appendChild(g);
    }
    refresh();
  }
  $$('.chip').forEach(function (c) { c.addEventListener('click', function (e) { toggle(c); if (chosen[c.getAttribute('data-top')]) confetti(e.clientX, e.clientY, 6); }); });
  $('#bClear').addEventListener('click', function () { $$('.chip').forEach(function (c) { if (chosen[c.getAttribute('data-top')]) toggle(c, false); }); });
  $('#bShuffle').addEventListener('click', function (e) {
    var chips = $$('.chip'); chips.forEach(function (c) { toggle(c, Math.random() > .5); }); confetti(e.clientX, e.clientY, 16);
  });
})();
