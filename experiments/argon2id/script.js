/* Argon2id experiment. Argon2id: hash-wasm (js/vendor). MD5: CryptoJS. SHA-1, SHA-256, PBKDF2: Web Crypto. */
(function () {
  'use strict';
  console.info('argon2id script.js loaded');
  var $ = function (id) { return document.getElementById(id); };
  var enc = new TextEncoder();
  var hw = window.hashwasm || window.hashWasm;
  var obs = [], lastEncoded = '', prevDigest = '';

  /* ---------- helpers ---------- */
  function toHex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  function b64ToHex(b64) {
    while (b64.length % 4) b64 += '=';
    var bin = atob(b64), out = '';
    for (var i = 0; i < bin.length; i++) out += ('0' + bin.charCodeAt(i).toString(16)).slice(-2);
    return out;
  }
  function el(tag, text, cls) {
    var e = document.createElement(tag);
    if (text !== undefined) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }
  function showError(m) { $('a2-error').textContent = m || ''; }
  var BUSY = '#a2-hash,#a2-compare,#a2-verify,#a2-cfg,#a2-rand,#a2-pw,#a2-salt,#a2-mem,#a2-iter,#a2-par,#sl-m,#sl-t,#sl-p,#simulation .pm,[data-cf],#cfa-m,#cfa-t,#cfa-p,#cfb-m,#cfb-t,#cfb-p';
  function setBusy(b) { document.querySelectorAll(BUSY).forEach(function (e) { e.disabled = b; }); }
  function fmt(ms) { return ms < 1 ? ms.toFixed(3) + ' ms' : ms.toFixed(1) + ' ms'; }
  function table(headers, rows) {
    var t = el('table', undefined, 'a2-table'), hr = el('tr');
    headers.forEach(function (h) { hr.appendChild(el('th', h)); });
    t.appendChild(hr);
    rows.forEach(function (r) {
      var tr = el('tr');
      r.forEach(function (c) { tr.appendChild(el('td', c.text !== undefined ? c.text : c, c.mono ? 'a2-mono' : '')); });
      t.appendChild(tr);
    });
    return t;
  }

  /* ---------- inputs ---------- */
  function readInputs() {
    var pw = $('a2-pw').value, salt = $('a2-salt').value;
    var m = Number($('a2-mem').value), t = Number($('a2-iter').value), p = Number($('a2-par').value);
    if (!pw.length) return { error: 'Enter a password. An empty password is not allowed.' };
    if (enc.encode(salt).length < 8) return { error: 'Salt must be at least 8 bytes. Use Random salt or type 8 or more characters.' };
    if (!Number.isInteger(p) || p < 1 || p > 4) return { error: 'Parallelism must be a whole number from 1 to 4.' };
    if (!Number.isInteger(t) || t < 1 || t > 10) return { error: 'Time cost must be a whole number from 1 to 10.' };
    if (!Number.isInteger(m) || m < 8 * p || m > 65536) return { error: 'Memory cost must be a whole number from ' + (8 * p) + ' to 65536 KiB.' };
    return { pw: pw, salt: salt, m: m, t: t, p: p };
  }
  function libsReady() {
    if (!hw || typeof hw.argon2id !== 'function' || typeof hw.argon2Verify !== 'function') {
      showError('The Argon2id library (js/vendor/hash-wasm.min.js) did not load. Open the page through http://localhost and check the console (F12).');
      return false;
    }
    return true;
  }
  /* The real Argon2id runs in a Web Worker when possible (keeps the animation smooth) and falls back to the main thread. */
  var wk = null, wseq = 0, pend = {};
  function getWorker() {
    if (wk !== null) return wk;
    try {
      var u = new URL('../../js/vendor/hash-wasm.min.js', location.href).href;
      var src = 'importScripts(' + JSON.stringify(u) + ');onmessage=async function(e){var d=e.data;try{var h=self.hashwasm;var r=d.op==="hash"?await h.argon2id(d.o):await h.argon2Verify(d.o);postMessage({id:d.id,r:r});}catch(x){postMessage({id:d.id,err:String(x&&x.message||x)});}};';
      wk = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
      wk.onmessage = function (e) { var q = pend[e.data.id]; if (!q) return; delete pend[e.data.id]; if (e.data.err) q.rej(new Error(e.data.err)); else q.res(e.data.r); };
      wk.onerror = function () { wk = false; Object.keys(pend).forEach(function (k) { var q = pend[k]; delete pend[k]; q.rej({ workerFail: 1 }); }); };
    } catch (e) { wk = false; }
    return wk;
  }
  function direct(op, o) { return op === 'hash' ? hw.argon2id(o) : hw.argon2Verify(o); }
  function run(op, o) {
    var w = getWorker();
    if (!w) return direct(op, o);
    return new Promise(function (res, rej) { var id = ++wseq; pend[id] = { res: res, rej: rej }; w.postMessage({ id: id, op: op, o: o }); })
      .catch(function (e) { if (e && e.workerFail) return direct(op, o); throw e; });
  }
  async function argon(v) {
    var t0 = performance.now();
    var encoded = await run('hash', { password: v.pw, salt: enc.encode(v.salt), parallelism: v.p, iterations: v.t, memorySize: v.m, hashLength: 32, outputType: 'encoded' });
    return { encoded: encoded, ms: performance.now() - t0 };
  }
  function parse(s) {
    var parts = s.split('$');
    if (parts.length !== 6 || parts[1] !== 'argon2id') return null;
    var o = {};
    parts[3].split(',').forEach(function (kv) { var a = kv.split('='); o[a[0]] = a[1]; });
    return { version: parts[2], m: o.m, t: o.t, p: o.p, saltB64: parts[4], hashB64: parts[5] };
  }

  /* ---------- generate ---------- */
  function avalanche(hex) {
    var box = el('div');
    if (prevDigest) {
      var bits = 0, line = el('p', undefined, 'a2-mono');
      for (var i = 0; i < hex.length; i++) {
        var x = parseInt(hex[i], 16) ^ parseInt(prevDigest[i], 16);
        bits += [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4][x];
        var sp = el('span', hex[i]);
        if (x) sp.style.cssText = 'background:#e8a24a;color:#2b1f1c';
        line.appendChild(sp);
      }
      box.appendChild(el('p', bits === 0
        ? 'Identical to the previous run: same password, salt and parameters always give the same hash.'
        : 'Compared with the previous run: ' + bits + ' of 256 bits differ (' + Math.round(bits / 2.56) + '%). About 50% is expected (avalanche effect). Changed hex characters are highlighted.', 'a2-hint'));
      box.appendChild(line);
    }
    prevDigest = hex;
    return box;
  }
  function copyBtn() {
    var b = el('button', 'Copy hash', 'a2-btn'); b.type = 'button';
    b.addEventListener('click', function () {
      var p = navigator.clipboard ? navigator.clipboard.writeText(lastEncoded) : Promise.reject();
      p.then(function () { b.textContent = 'Copied!'; }, function () { b.textContent = 'Copy failed'; });
      setTimeout(function () { b.textContent = 'Copy hash'; }, 1500);
    });
    return b;
  }
  function renderObs() {
    $('a2-obs').replaceChildren(obs.length ? table(['Run', 'Memory m', 'Time t', 'Parallelism p', 'Measured time', 'Digest (first 8 bytes)'], obs) : el('p', 'No runs yet.'));
  }
  async function onHash() {
    showError('');
    var v = readInputs();
    if (v.error) { showError(v.error); return; }
    if (!libsReady()) return;
    setBusy(true); V.start('hash', v);
    $('a2-out').replaceChildren(el('p', 'Computing Argon2id (' + v.m + ' KiB, t=' + v.t + ', p=' + v.p + ')...'));
    try {
      var r = await argon(v), f = parse(r.encoded), hex = b64ToHex(f.hashB64);
      lastEncoded = r.encoded;
      $('a2-vhash').value = r.encoded;
      $('a2-out').replaceChildren(
        el('p', 'Argon2id encoded hash:'), el('p', r.encoded, 'a2-mono'), copyBtn(),
        table(['Field', 'Value'], [
          ['Algorithm', 'argon2id'], ['Version', f.version + ' (v=19 means 0x13)'],
          ['Memory cost m', f.m + ' KiB'], ['Time cost t', f.t + ' iterations'], ['Parallelism p', f.p + ' lane(s)'],
          ['Salt (UTF-8 bytes, base64)', { text: f.saltB64, mono: true }], ['Digest (32 bytes, hex)', { text: hex, mono: true }],
          ['Measured time (this browser)', fmt(r.ms)]
        ]),
        avalanche(hex));
      obs.push([String(obs.length + 1), v.m + ' KiB', String(v.t), String(v.p), fmt(r.ms), { text: hex.slice(0, 16) + '...', mono: true }]);
      if (obs.length > 12) obs.shift();
      renderObs(); V.finish('hash', true, r.ms, r.encoded);
    } catch (e) { showError('Hashing failed: ' + (e && e.message ? e.message : e)); V.finish('hash', false); }
    setBusy(false);
  }

  /* ---------- verify ---------- */
  function renderVerify(ok, ms) {
    var d = el('div', undefined, 'vres ' + (ok ? 'ok' : 'bad')), ic = el('div'), tx = el('div');
    ic.innerHTML = ok ? '<svg class="vi" viewBox="0 0 52 52"><circle cx="26" cy="26" r="23"/><path d="M15 27l8 8 15-17"/></svg>'
                      : '<svg class="vi" viewBox="0 0 52 52"><circle cx="26" cy="26" r="23"/><path d="M26 14v16M26 38v1"/></svg>';
    tx.appendChild(el('b', ok ? 'Password verified' : 'Password does not match'));
    tx.appendChild(el('p', ok ? 'Argon2id recomputed the hash from the typed password using the salt and parameters in the stored string, and the result is identical.'
                              : 'The recomputed hash differs from the stored one. Nothing about the real password is revealed.'));
    tx.appendChild(el('p', 'Verification time (this browser): ' + fmt(ms), 'a2-hint'));
    d.appendChild(ic); d.appendChild(tx);
    $('a2-verify-out').replaceChildren(d);
  }
  async function onVerify() {
    showError('');
    var stored = $('a2-vhash').value.trim(), pw = $('a2-vpw').value;
    if (!stored) { showError('Paste or generate an Argon2id hash first.'); return; }
    var f = parse(stored);
    if (!f) { showError('That is not a valid Argon2id encoded hash. It must look like $argon2id$v=19$m=...,t=...,p=...$salt$hash'); return; }
    if (!pw.length) { showError('Enter the password to check.'); return; }
    if (Number(f.m) > 65536) { showError('The memory cost in that hash is above the 64 MiB lab limit.'); return; }
    if (!libsReady()) return;
    var P = { m: clampI(f.m, 8, 65536), t: clampI(f.t, 1, 10), p: clampI(f.p, 1, 4) }, ok = false, ms = 0, fail = false;
    setBusy(true); V.start('verify', P);
    try { var t0 = performance.now(); ok = await run('verify', { password: pw, hash: stored }); ms = performance.now() - t0; }
    catch (e) { fail = true; showError('Verification failed: the hash string is malformed or unsupported.'); }
    if (!fail) renderVerify(ok, ms);
    V.finish('verify', !fail, ms, fail ? 'error' : (ok ? 'ok' : 'bad'));
    setBusy(false);
  }

  /* ---------- comparison ---------- */
  async function avg(fn, n) {
    var t0 = performance.now(), last;
    for (var i = 0; i < n; i++) last = await fn();
    return { value: last, ms: (performance.now() - t0) / n };
  }
  async function digest(name, data) { return toHex(await crypto.subtle.digest(name, data)); }
  function gps(ms) { var g = 1000 / ms; return (g >= 1000 ? Math.round(g).toLocaleString() : g.toFixed(1)) + ' /s'; }

  async function onCompare() {
    showError('');
    var v = readInputs();
    if (v.error) { showError(v.error); return; }
    if (!libsReady()) return;
    if (!window.crypto || !crypto.subtle) { showError('Web Crypto is unavailable. Open the page via http://localhost, not as a file.'); return; }
    setBusy(true);
    $('a2-cmp').replaceChildren(el('p', 'Running comparison...'));
    try {
      var data = enc.encode(v.pw), salt = enc.encode(v.salt), N = 200, rows = [];
      if (window.CryptoJS) {
        var md5 = await avg(async function () { return CryptoJS.MD5(v.pw).toString(); }, N);
        rows.push(['MD5', '128-bit', 'None (unsalted)', fmt(md5.ms) + ' (avg of ' + N + ')', gps(md5.ms), 'No: broken and very fast', { text: md5.value, mono: true }]);
      } else rows.push(['MD5', 'unavailable', 'CryptoJS did not load', '-', '-', 'No', '-']);
      var s1 = await avg(function () { return digest('SHA-1', data); }, N);
      rows.push(['SHA-1', '160-bit', 'None (unsalted)', fmt(s1.ms) + ' (avg of ' + N + ')', gps(s1.ms), 'No: broken and very fast', { text: s1.value, mono: true }]);
      var s256 = await avg(function () { return digest('SHA-256', data); }, N);
      rows.push(['SHA-256', '256-bit', 'None (unsalted)', fmt(s256.ms) + ' (avg of ' + N + ')', gps(s256.ms), 'Not on its own: too fast', { text: s256.value, mono: true }]);
      var ITER = 600000, t0 = performance.now();
      var key = await crypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits']);
      var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: ITER }, key, 256);
      var pb = performance.now() - t0;
      rows.push(['PBKDF2-SHA256', '256-bit', 'Salt + ' + ITER + ' iterations (CPU only)', fmt(pb) + ' (1 run)', gps(pb), 'Acceptable, not memory-hard', { text: toHex(bits), mono: true }]);
      var a = await argon(v);
      rows.push(['Argon2id', '32-byte digest (encoded)', 'Salt + m=' + v.m + ', t=' + v.t + ', p=' + v.p, fmt(a.ms) + ' (1 run)', gps(a.ms), 'Yes: recommended', { text: a.encoded, mono: true }]);
      $('a2-cmp').replaceChildren(
        el('div', undefined, 'a2-table-wrap'),
        el('p', 'On this run SHA-256 tests about ' + Math.max(1, Math.round(a.ms / s256.ms)).toLocaleString() + 'x more guesses per second than Argon2id with your settings (one thread, this browser). That gap is what makes Argon2id expensive for an attacker.', 'a2-ok'),
        el('p', 'Times vary between devices and runs. Fast hashes are averaged over ' + N + ' runs. Argon2id memory use is the configured m, not a measured figure.', 'a2-hint'));
      $('a2-cmp').firstChild.appendChild(table(['Algorithm', 'Output', 'Cost parameters', 'Measured time', 'Guesses per second', 'Suitable for passwords?', 'Output value'], rows));
    } catch (e) { showError('Comparison failed: ' + (e && e.message ? e.message : e)); }
    setBusy(false);
  }

  /* ---------- UI helpers ---------- */
  var reduce = !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
  function clampI(v, a, b) { v = Math.round(Number(v)); return isNaN(v) ? a : Math.max(a, Math.min(b, v)); }
  function on(id, fn) { var e = $(id); if (e) e.addEventListener('click', fn); }
  function put(id, t) { var e = $(id); if (e && e.textContent !== t) e.textContent = t; }
  function bump(id) { var e = $(id); e.classList.remove('bump'); void e.offsetWidth; e.classList.add('bump'); }
  function setTxt(id, t) { var e = $(id), had = e.textContent !== ''; if (e.textContent !== t) { e.textContent = t; if (had) bump(id); } }
  function fmtMem(m) { return m >= 1024 ? (m / 1024).toFixed(m % 1024 ? 1 : 0) + ' MiB' : m + ' KiB'; }
  function mToSl(m) { return Math.round(100 * Math.log(m / 8) / Math.log(8192)); }
  function slToM(v) { return Math.round(8 * Math.pow(8192, v / 100)); }
  function vp() {
    var m = Number($('a2-mem').value), t = Number($('a2-iter').value), p = Number($('a2-par').value);
    p = p >= 1 ? Math.min(Math.floor(p), 4) : 1; t = t >= 1 ? Math.min(Math.floor(t), 10) : 2; m = m > 0 ? Math.min(Math.floor(m), 65536) : 19456;
    return { m: Math.max(m, 8 * p), t: t, p: p };
  }
  function reveal(n) {
    if (reduce || !n) return;
    var full = n.textContent, i = 0; n.textContent = '';
    (function f() { i = Math.min(full.length, i + 8); n.textContent = full.slice(0, i); if (i < full.length) requestAnimationFrame(f); })();
  }

  /* ---------- tooltips ---------- */
  var TIPS = {
    pw: ['PASSWORD', 'The secret you type. It is never stored; only its hash is.'],
    salt: ['SALT', 'A random, non-secret value mixed into the password. It makes identical passwords give different hashes and defeats precomputed tables.'],
    m: ['MEMORY COST (m)', 'Amount of memory used during hashing, in KiB. Raising it generally raises the memory needed for every password guess.'],
    t: ['TIME COST (t)', 'How many passes are made over the memory. More passes means more computation per password.'],
    p: ['PARALLELISM (p)', 'How many lanes the memory is split into. Lanes can be processed at the same time. It also changes the resulting hash.'],
    params: ['PARAMETERS', 'm, t and p are stored inside the encoded hash so the verifier can repeat exactly the same work.'],
    argon2id: ['ARGON2ID', 'A memory-hard password hashing function (RFC 9106). It fills a large memory area and mixes it repeatedly.'],
    enc: ['ENCODED HASH', 'One string holding the algorithm, version, m, t, p, salt and hash, all that verification needs.'],
    verify: ['VERIFY', 'Recompute the hash from the typed password using the stored salt and parameters, then compare. Nothing is decrypted.'],
    blocks: ['MEMORY BLOCKS', 'Argon2 memory is split into 1 KiB blocks. Each square here stands for a group of them (a schematic).'],
    lanes: ['LANES', 'Independent rows of memory. With p lanes, p rows can be worked on in parallel.'],
    pass: ['PASS', 'One full sweep over the memory. Time cost t is the number of passes.'],
    indep: ['DATA-INDEPENDENT', 'Which earlier block is read does not depend on secret data. This resists side-channel leaks. Argon2id uses it for the first two slices of pass 1.'],
    dep: ['DATA-DEPENDENT', 'Which earlier block is read depends on the data computed so far. This makes memory-saving shortcuts costly. Argon2id uses it for the rest.']
  };
  function tipInit() {
    var box = el('div'), cur = null; box.id = 'tipbox'; document.body.appendChild(box);
    function hide() { box.style.display = 'none'; cur = null; }
    function show(t) {
      var d = TIPS[t.getAttribute('data-tip')];
      if (!d) return;
      if (cur === t) { hide(); return; }
      cur = t; box.replaceChildren(el('b', d[0]), el('br'), document.createTextNode(d[1])); box.style.display = 'block';
      var r = t.getBoundingClientRect();
      box.style.top = (window.scrollY + r.bottom + 6) + 'px';
      box.style.left = Math.max(8, Math.min(window.scrollX + r.left, window.scrollX + document.documentElement.clientWidth - 300)) + 'px';
    }
    document.addEventListener('click', function (e) { var t = e.target.closest ? e.target.closest('[data-tip]') : null; if (t) show(t); else hide(); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') hide();
      if (e.key === 'Enter' && e.target.classList && e.target.classList.contains('tip')) show(e.target);
    });
  }

  /* ---------- memory visualizer (a schematic; separate from the real hashing) ---------- */
  var viz = { s: 0, T: 1, A: 1, per: 64, P: { m: 19456, t: 2, p: 1 }, play: false, hold: false, fast: false, speed: 1, last: 0, raf: 0, busy: false, t0: 0, clock: 0, dp: Promise.resolve(), geo: null };
  var LATER = ['#f2bd7c', '#f8d8ac', '#ffe9cf'];
  function vsetup(P) {
    viz.P = P; viz.per = Math.max(16, Math.min(128, Math.round(Math.sqrt(P.m / P.p) / 8) * 4));
    viz.A = Math.round(viz.per * 0.4); viz.T = viz.A + P.t * viz.per;
  }
  function draw(now) {
    var c = $('a2-cv'), P = viz.P, per = viz.per, q = per / 4, ch = 9, lh = 4 * (ch + 2), gap = 10, pad = 8, lab = 30;
    var W = c.clientWidth || 640, H = P.p * lh + (P.p - 1) * gap + pad * 2, dpr = window.devicePixelRatio || 1;
    if (c.width !== Math.round(W * dpr) || c.height !== Math.round(H * dpr)) { c.width = Math.round(W * dpr); c.height = Math.round(H * dpr); c.style.height = H + 'px'; }
    var x = c.getContext('2d'); x.setTransform(dpr, 0, 0, dpr, 0, 0); x.clearRect(0, 0, W, H);
    var s = viz.s, done = s >= viz.T, u = s - viz.A, alloc = u < 0 && !done;
    var pass = done ? P.t - 1 : (u < 0 ? -1 : Math.floor(u / per)), pos = done ? per : (u < 0 ? 0 : u % per);
    var cw = (W - pad * 2 - lab) / q - 1, pulse = 0.5 + 0.5 * Math.sin((now || 0) / 180);
    viz.geo = { pad: pad, lab: lab, lh: lh, gap: gap, q: q, cw: cw, ch: ch, per: per, pass: pass, pos: pos, done: done, alloc: alloc };
    x.font = '11px Arial'; x.textBaseline = 'middle';
    for (var l = 0; l < P.p; l++) {
      var y = pad + l * (lh + gap);
      x.fillStyle = '#c9b8a6'; x.fillText('L' + (l + 1), pad, y + lh / 2);
      for (var i = 0; i < per; i++) {
        var col = '#3a2e2a';
        if (alloc) { if (i < (s / viz.A) * per) col = '#6b5646'; }
        else {
          var k = (done || i < pos) ? pass : pass - 1;
          if (k < 0) col = '#6b5646'; else if (k === 0) col = i < per / 2 ? '#5b8def' : '#e8a24a'; else col = LATER[Math.min(k - 1, 2)];
        }
        var head = !alloc && !done && i === Math.floor(pos);
        x.fillStyle = head ? '#ffe9cf' : col;
        if (head) { x.shadowColor = '#ffe9cf'; x.shadowBlur = 6 + 8 * pulse; }
        x.fillRect(pad + lab + (i % q) * (cw + 1), y + Math.floor(i / q) * (ch + 2), cw, ch);
        x.shadowBlur = 0;
      }
    }
    var ph = done ? 'COMPLETE' : alloc ? 'ALLOCATING' : (pass === 0 ? (pos < per / 2 ? 'DATA-INDEPENDENT' : 'DATA-DEPENDENT') : 'LATER PASSES');
    var frac = done ? 1 : Math.max(0, u) / (P.t * per), prog = Math.min(100, Math.round(100 * s / viz.T));
    put('st-pass', (done ? P.t : Math.max(0, pass + 1)) + ' / ' + P.t);
    put('st-lane', P.p + (P.p > 1 ? ' lanes, in parallel' : ' lane'));
    put('st-phase', ph); put('st-prog', prog + '%'); $('st-bar').style.width = prog + '%';
    put('st-mem', fmtMem(P.m) + ', each square is about ' + (P.m / (P.p * per)).toFixed(1) + ' blocks');
    put('st-blk', '\u2248 ' + Math.round(P.m * P.t * frac).toLocaleString() + ' / ' + (P.m * P.t).toLocaleString());
    $('lg-i').classList.toggle('on', ph === 'DATA-INDEPENDENT'); $('lg-d').classList.toggle('on', ph === 'DATA-DEPENDENT'); $('lg-l').classList.toggle('on', ph === 'LATER PASSES');
    var wait = viz.hold && s >= viz.T * 0.97 ? ' Waiting for the real computation to finish\u2026' : '';
    put('a2-what', ph === 'COMPLETE' ? 'Hash computation completed.' : ph === 'ALLOCATING' ? 'Argon2id is allocating its memory region (' + fmtMem(P.m) + ').'
      : ph === 'DATA-INDEPENDENT' ? 'Processing blocks in each lane. This phase uses data-independent addressing: which earlier block is read does not depend on secret data.'
      : ph === 'DATA-DEPENDENT' ? 'This phase uses data-dependent addressing: the block read next depends on the data computed so far.'
      : 'Additional passes are being performed over the memory (pass ' + (pass + 1) + ' of ' + P.t + ').' + wait);
    if (ph !== 'LATER PASSES' && wait) put('a2-what', $('a2-what').textContent + wait);
  }
  function tick(now) {
    if (!viz.play) { viz.raf = 0; draw(now); return; }
    var dt = Math.min(0.05, (now - viz.last) / 1000); viz.last = now;
    var rate = viz.T / ((1 + 0.5 * viz.P.t) / viz.speed) * (viz.fast ? 3 : 1), cap = viz.hold ? viz.T * 0.97 : viz.T;
    viz.s = reduce && !viz.hold ? viz.T : Math.min(cap, viz.s + rate * dt);
    draw(now);
    if (viz.s >= viz.T) { viz.play = false; viz.raf = 0; return; }
    viz.raf = requestAnimationFrame(tick);
  }
  function vplay() {
    if (viz.s >= viz.T) viz.s = 0;
    viz.play = true; viz.last = performance.now(); $('a2-vplay').textContent = '\u25B6 Play';
    if (!viz.raf) viz.raf = requestAnimationFrame(tick);
  }
  function vpause() { viz.play = false; $('a2-vplay').textContent = '\u25B6 Resume'; }

  /* ---------- process diagram ---------- */
  var NODES = ['pd-pw', 'pd-salt', 'pd-par', 'pd-arg', 'pd-enc', 'pd-ver'], dseq = 0;
  function pdClear() { NODES.forEach(function (id) { $(id).className = 'pd-n'; }); document.querySelectorAll('.pd-a').forEach(function (a) { a.className = 'pd-a'; }); }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, reduce ? 0 : ms / viz.speed); }); }
  async function diagram(kind, P) {
    var my = ++dseq, ar = document.querySelectorAll('.pd-a');
    pdClear();
    put('pd-pars', fmtMem(P.m) + ' \u00B7 t=' + P.t + ' \u00B7 p=' + P.p); put('pd-args', kind === 'hash' ? 'hashing\u2026' : 'recomputing\u2026');
    put('pd-vers', 'waiting'); put('pd-encs', kind === 'hash' ? 'computing\u2026' : 'stored hash');
    for (var i = 0; i < 3; i++) {
      if (my !== dseq) return;
      $(NODES[i]).classList.add('on'); ar[i].classList.add('flow'); await sleep(320);
    }
    if (my !== dseq) return;
    $('pd-arg').classList.add('act');
  }
  async function dfinish(kind, ok, extra) {
    var my = dseq; await viz.dp; if (my !== dseq) return;
    var ar = document.querySelectorAll('.pd-a');
    $('pd-arg').classList.remove('act'); $('pd-arg').classList.add('on'); put('pd-args', ok ? 'done' : 'failed');
    ar[3].classList.add('flow'); await sleep(260); if (my !== dseq) return;
    $('pd-enc').classList.add('on'); ar[4].classList.add('flow');
    if (kind === 'hash') put('pd-encs', ok && extra ? extra.slice(0, 34) + '\u2026' : 'failed');
    await sleep(260); if (my !== dseq) return;
    if (kind === 'hash') { put('pd-vers', ok ? 'ready' : '\u2014'); if (ok) $('pd-ver').classList.add('ready'); }
    else { $('pd-ver').classList.add(extra === 'ok' ? 'ok' : 'bad'); put('pd-vers', extra === 'ok' ? 'MATCH' : extra === 'bad' ? 'NO MATCH' : 'error'); }
    ar.forEach(function (a) { a.classList.remove('flow'); });
  }
  var V = {
    start: function (kind, P) {
      viz.busy = true; vsetup(P); viz.s = 0; viz.hold = true; viz.fast = false; vplay();
      viz.dp = diagram(kind, P);
      viz.t0 = performance.now(); clearInterval(viz.clock);
      viz.clock = setInterval(function () { put('a2-el', ((performance.now() - viz.t0) / 1000).toFixed(1) + ' s'); }, 100);
      var b = $(kind === 'hash' ? 'a2-hash' : 'a2-verify'); b.className = 'busy'; b.textContent = kind === 'hash' ? '\u25C9 Hashing\u2026' : '\u25C9 Verifying\u2026';
    },
    finish: function (kind, ok, ms, extra) {
      clearInterval(viz.clock); put('a2-el', ms ? ms.toFixed(0) + ' ms (measured)' : '\u2014');
      viz.hold = false; viz.fast = true; viz.busy = false;
      if (ok) { if (!viz.play) vplay(); } else { viz.play = false; draw(performance.now()); }
      var b = $(kind === 'hash' ? 'a2-hash' : 'a2-verify'), idle = kind === 'hash' ? 'Generate Argon2id hash' : 'Verify password';
      if (ok) { b.className = 'done'; b.textContent = kind === 'hash' ? '\u2713 Hash generated' : '\u2713 Done'; setTimeout(function () { b.className = ''; b.textContent = idle; }, 1800); }
      else { b.className = ''; b.textContent = idle; }
      if (kind === 'hash' && ok) reveal($('a2-out').querySelector('p.a2-mono'));
      dfinish(kind, ok, extra);
    }
  };

  /* ---------- parameter controls ---------- */
  var OW = { m: 19456, t: 2, p: 1 };
  function sync() {
    var P = vp();
    setTxt('pv-m', fmtMem(P.m)); setTxt('pv-t', P.t + (P.t === 1 ? ' pass' : ' passes')); setTxt('pv-p', P.p + (P.p === 1 ? ' lane' : ' lanes'));
    $('sl-m').value = mToSl(P.m); $('sl-t').value = P.t; $('sl-p').value = P.p;
    setTxt('sum-m', fmtMem(P.m)); setTxt('sum-t', P.t + (P.t === 1 ? ' pass' : ' passes')); setTxt('sum-p', P.p + (P.p === 1 ? ' lane' : ' lanes'));
    setTxt('sum-s', enc.encode($('a2-salt').value).length + ' bytes');
    $('pn-m').textContent = P.m > OW.m ? 'Higher memory \u2192 harder for attackers to run many guesses at once (and more RAM per login for you).' : P.m < OW.m ? 'Lower memory \u2192 cheaper for the server, but easier for attackers to run many guesses at once.' : 'Controls how much memory Argon2id uses.';
    $('pn-t').textContent = P.t > OW.t ? 'Higher time \u2192 more computation per password.' : P.t < OW.t ? 'Lower time \u2192 less computation per password.' : 'Controls the number of passes over the memory.';
    $('pn-p').textContent = P.p > OW.p ? 'Higher parallelism \u2192 more lanes processed concurrently (this browser runs the library on one thread, so time may not drop).' : 'Controls the number of parallel processing lanes.';
    if (!viz.busy) { put('pd-pars', fmtMem(P.m) + ' \u00B7 t=' + P.t + ' \u00B7 p=' + P.p); vsetup(P); viz.play = false; viz.s = viz.T; draw(performance.now()); }
  }
  function fixInputs() {
    var p = clampI($('a2-par').value, 1, 4); $('a2-par').value = p;
    $('a2-iter').value = clampI($('a2-iter').value, 1, 10);
    $('a2-mem').value = clampI($('a2-mem').value, 8 * p, 65536);
  }
  function paramInit() {
    ['a2-mem', 'a2-iter', 'a2-par', 'a2-salt'].forEach(function (id) { $(id).addEventListener('input', sync); });
    ['a2-mem', 'a2-iter', 'a2-par'].forEach(function (id) { $(id).addEventListener('change', function () { fixInputs(); sync(); }); });
    document.querySelectorAll('.pm').forEach(function (b) {
      b.addEventListener('click', function () {
        var k = b.getAttribute('data-p'), d = Number(b.getAttribute('data-d')), id = { m: 'a2-mem', t: 'a2-iter', p: 'a2-par' }[k], v = Number($(id).value) || 0;
        $(id).value = v + (k === 'm' ? d * 1024 : d); fixInputs(); sync(); bump('pv-' + k);
      });
    });
    $('sl-m').addEventListener('input', function () { $('a2-mem').value = slToM(Number(this.value)); fixInputs(); sync(); });
    $('sl-t').addEventListener('input', function () { $('a2-iter').value = this.value; sync(); });
    $('sl-p').addEventListener('input', function () { $('a2-par').value = this.value; fixInputs(); sync(); });
  }
  function vizInit() {
    $('a2-speed').addEventListener('input', function () { viz.speed = Number(this.value) || 1; });
    on('a2-vplay', vplay); on('a2-vpause', vpause);
    on('a2-vreplay', function () { if (viz.busy) return; vsetup(vp()); viz.s = 0; viz.hold = false; viz.fast = false; vplay(); });
    window.addEventListener('resize', function () { draw(performance.now()); });
    if (window.ResizeObserver) new ResizeObserver(function () { draw(performance.now()); }).observe($('a2-cv'));
    tipInit(); sync();
  }

  /* ---------- configuration comparison (A vs B, editable m, t, p) ---------- */
  function cfgOf(k) { return [Number($('cf' + k + '-m').value), Number($('cf' + k + '-t').value), Number($('cf' + k + '-p').value)]; }
  function cfBars(title, vals, f) {
    var box = el('div'), mx = Math.max(vals[0], vals[1]);
    box.appendChild(el('p', title, 'a2-hint'));
    ['A', 'B'].forEach(function (n, i) {
      var row = el('div', undefined, 'cfb'), bar = el('div', undefined, 'bar'), fill = el('i');
      bar.appendChild(fill); row.appendChild(el('b', n)); row.appendChild(bar); row.appendChild(el('span', String(f(vals[i])))); box.appendChild(row);
      requestAnimationFrame(function () { requestAnimationFrame(function () { fill.style.width = Math.max(4, vals[i] / mx * 100) + '%'; }); });
    });
    return box;
  }
  async function onCfg() {
    showError('');
    var base = readInputs();
    if (base.error) { showError(base.error); return; }
    if (!libsReady()) return;
    var cfgs = [cfgOf('a'), cfgOf('b')], out = $('cf-out'), res = [];
    for (var q = 0; q < 2; q++) {
      var c0 = cfgs[q];
      if (!Number.isInteger(c0[2]) || c0[2] < 1 || c0[2] > 4 || !Number.isInteger(c0[1]) || c0[1] < 1 || c0[1] > 10 || !Number.isInteger(c0[0]) || c0[0] < 8 * c0[2] || c0[0] > 65536) {
        showError('Configuration ' + 'AB'.charAt(q) + ': use whole numbers, m from 8 x p to 65536 KiB, t from 1 to 10, p from 1 to 4.'); return;
      }
    }
    setBusy(true); out.replaceChildren(el('p', 'Running configurations A and B\u2026'));
    try {
      await argon({ pw: 'warmup', salt: 'warmup00', m: 8, t: 1, p: 1 });
      for (var i = 0; i < 2; i++) {
        var c = cfgs[i], r = await argon({ pw: base.pw, salt: base.salt, m: c[0], t: c[1], p: c[2] });
        res.push({ c: c, ms: r.ms });
      }
      out.replaceChildren(
        cfBars('Memory', [res[0].c[0], res[1].c[0]], fmtMem), cfBars('Time cost t (passes)', [res[0].c[1], res[1].c[1]], String),
        cfBars('Parallelism p (lanes)', [res[0].c[2], res[1].c[2]], String), cfBars('Measured time', [res[0].ms, res[1].ms], fmt),
        el('p', 'Measured times are observations from this device and browser (single runs after a warm-up), not universal benchmarks.', 'a2-hint'));
    } catch (e) { showError('Comparison failed: ' + (e && e.message ? e.message : e)); out.replaceChildren(); }
    setBusy(false);
  }

  /* ---------- quiz (10 compulsory questions) ---------- */
  var QUIZ = [
    { q: 'Why is SHA-256 alone a poor choice for storing passwords?', o: ['It produces a hash that is too short to store', 'It is very fast, so attackers can test guesses quickly', 'It can be decrypted with a key', 'It cannot take a salt'], a: 1, why: 'Speed is the problem: fast hashes let an attacker try enormous numbers of guesses per second.' },
    { q: 'What is the purpose of a salt?', o: ['To encrypt the password', 'To make the hash shorter', 'To make identical passwords produce different hashes', 'To keep the hash secret'], a: 2, why: 'A unique random salt defeats precomputed tables and hides repeated passwords. It is stored openly with the hash.' },
    { q: 'In Argon2id, what does the memory cost parameter control?', o: ['How many bytes the salt has', 'How much memory is filled and used per hash', 'How many characters the password may have', 'The number of users supported'], a: 1, why: 'Memory cost m (in KiB) sets the size of the memory block, which makes large-scale parallel cracking expensive.' },
    { q: 'What does the time cost (iterations) parameter change?', o: ['The number of passes over the memory', 'The version of Argon2', 'The length of the password', 'The character set of the salt'], a: 0, why: 'Time cost t is the number of passes; more passes means more work for every guess.' },
    { q: 'Argon2id is best described as:', o: ['A reversible cipher', 'A hybrid of Argon2i and Argon2d', 'A public-key signature scheme', 'A checksum for files'], a: 1, why: 'Argon2id starts with data-independent access (like Argon2i) and continues with data-dependent access (like Argon2d).' },
    { q: 'How does Argon2id verify a password at login?', o: ['It decrypts the stored hash', 'It sends the password to the server unhashed', 'It re-hashes the entered password with the stored salt and parameters and compares', 'It compares the password length'], a: 2, why: 'Parameters and salt are read from the encoded string, the entered password is hashed, and the digests are compared.' },
    { q: 'An attacker stores only half of the memory blocks to save RAM. What happens?', o: ['Nothing, the hash is unchanged', 'Missing blocks must be recomputed, so the work grows a lot', 'The hash becomes reversible', 'The salt stops working'], a: 1, why: 'Each block depends on earlier blocks, so every missing block has to be rebuilt. This is the time-memory trade-off.' },
    { q: 'Why does Argon2id need a lot of memory per guess?', o: ['To store the password for later', 'GPUs and ASICs have little memory per core, so it limits parallel guessing', 'To make the hash reversible', 'Because the salt is large'], a: 1, why: 'Memory, not just time, is what cheap parallel hardware lacks. That is what memory-hard means.' },
    { q: 'What can a verifier do with the stored string $argon2id$v=19$m=19456,t=2,p=1$salt$hash ?', o: ['Decrypt the original password', 'Repeat the same hashing using the stored salt and parameters', 'Skip hashing and compare plain passwords', 'Learn the password length from the salt'], a: 1, why: 'The version, m, t, p and salt are stored with the digest, so the verifier can recompute the hash and compare.' },
    { q: 'Even with Argon2id, why does a long, unpredictable password still matter?', o: ['Argon2id only slows guessing, so weak passwords are still found quickly', 'Argon2id cannot hash long passwords', 'Short passwords make the salt invalid', 'It does not matter at all'], a: 0, why: 'A slow hash raises the cost per guess; a weak, common password still falls after few guesses.' }
  ];
  function renderQuiz() {
    var box = $('a2-quiz');
    box.replaceChildren();
    QUIZ.forEach(function (item, i) {
      var fs = el('fieldset');
      fs.appendChild(el('legend', (i + 1) + '. ' + item.q));
      item.o.forEach(function (opt, j) {
        var id = 'a2-q' + i + '-' + j, lab = el('label'), r = document.createElement('input');
        lab.setAttribute('for', id);
        r.type = 'radio'; r.name = 'a2-q' + i; r.id = id; r.value = String(j); r.addEventListener('change', qProgress);
        lab.appendChild(r); lab.appendChild(document.createTextNode(opt)); fs.appendChild(lab);
      });
      var fb = el('p', '', 'a2-hint'); fb.id = 'a2-fb' + i; fs.appendChild(fb);
      box.appendChild(fs);
    });
    $('a2-qresult').textContent = ''; $('a2-qresult').className = ''; qProgress();
  }
  function qProgress() {
    var n = 0;
    QUIZ.forEach(function (it, i) {
      var s = document.querySelector('input[name="a2-q' + i + '"]:checked'), fs = $('a2-fb' + i).parentNode;
      if (s) { n++; if (fs.classList.contains('miss')) { fs.classList.remove('miss'); $('a2-fb' + i).textContent = ''; } }
    });
    $('a2-qcount').textContent = n + ' of ' + QUIZ.length + ' answered (all are compulsory)';
    $('a2-qbar').style.width = (100 * n / QUIZ.length) + '%';
  }
  function submitQuiz() {
    var score = 0, first = -1, res = $('a2-qresult');
    QUIZ.forEach(function (item, i) {
      if (!document.querySelector('input[name="a2-q' + i + '"]:checked')) {
        var fb = $('a2-fb' + i); fb.parentNode.classList.add('miss'); fb.textContent = 'Compulsory: please answer this question.'; fb.className = 'a2-hint a2-bad';
        if (first < 0) first = i;
      }
    });
    if (first >= 0) {
      res.className = 'a2-bad'; res.textContent = 'Please answer all ' + QUIZ.length + ' questions before submitting. Question ' + (first + 1) + ' is still unanswered.';
      $('a2-fb' + first).parentNode.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }
    QUIZ.forEach(function (item, i) {
      var sel = document.querySelector('input[name="a2-q' + i + '"]:checked'), fb = $('a2-fb' + i);
      if (Number(sel.value) === item.a) { score++; fb.textContent = 'Correct. ' + item.why; fb.className = 'a2-hint a2-ok'; }
      else { fb.textContent = 'Incorrect. Correct answer: ' + item.o[item.a] + '. ' + item.why; fb.className = 'a2-hint a2-bad'; }
    });
    res.className = score === QUIZ.length ? 'a2-ok' : '';
    res.textContent = 'Score: ' + score + ' / ' + QUIZ.length + '.' + (score === QUIZ.length ? ' Excellent work.' : ' Review the Theory tab and try again.');
  }

  /* ---------- extras: algorithm explorer, strength meter, block inspector, comparison inputs ---------- */
  /* ALGO-START */
  var AL = { step: 0, t: 0, play: true, speed: 1, p: 2, T: 2, raf: 0, last: 0 };
  var CL = { cell: '#3a2e2a', fill: '#4e3d36', line: '#6b5646', text: '#f0e2cc', mute: '#c9b8a6', amber: '#e8a24a', blue: '#5b8def', green: '#8ee29c', cream: '#ffe9cf', card: '#33261f' };
  var ALS = [
    { n: 'H0 seed', title: '1. Hash every input into the 64-byte seed H0', dur: 8,
      text: 'Argon2id first mixes all inputs (password, salt, m, t, p, tag length, version 0x13 and the type y = 2 for Argon2id) into one 64-byte seed H0 with BLAKE2b-512. Every memory block is derived from H0, so changing any single input changes everything that follows.',
      math: 'H0 = BLAKE2b-512( p \u2016 T \u2016 m \u2016 t \u2016 v \u2016 y \u2016 len(P) \u2016 P \u2016 len(S) \u2016 S \u2016 len(K) \u2016 K \u2016 len(X) \u2016 X )',
      why: 'Why it matters: this is the only place the password and salt enter. The rest of the algorithm works on H0 and the memory.' },
    { n: 'Memory layout', title: '2. Allocate the memory matrix (lanes, slices, blocks)', dur: 8,
      text: 'The memory is a matrix of 1024-byte blocks: p lanes (rows), each with q columns, and every lane is cut into 4 slices. Change p and t with the selectors under the animation: the matrix reshapes and the numbers below use the memory m from your Simulation controls.',
      math: "m' = 4\u00B7p\u00B7\u230A m / 4p \u230B ;  q = m' / p ;  slice length = q / 4",
      why: 'Why it matters: m is the amount of memory every single guess needs. That is what makes cheap parallel hardware struggle.' },
    { n: 'Seed blocks', title: '3. Seed the first two blocks of every lane', dur: 8,
      text: "Each lane starts from H0. Block 0 and block 1 of lane i are produced by H', a variable-length BLAKE2b that outputs 1024 bytes. Lane number i is part of the input, so lanes never start identically.",
      math: "B[i][0] = H'( H0 \u2016 0 \u2016 i )     B[i][1] = H'( H0 \u2016 1 \u2016 i )",
      why: "Why it matters: H' stretches the 64-byte seed to full 1024-byte blocks. Everything else in the lane is built from these two." },
    { n: 'Compress G', title: '4. Compute every new block with the compression function G', dur: 9,
      text: 'A new block needs two earlier blocks: the previous one X and a reference block Y. G computes R = X \u2295 Y, treats R as an 8 \u00D7 8 matrix of 16-byte registers, applies the BLAKE2b round permutation P to every row and then every column, and XORs the result with R.',
      math: 'B[i][j] = G( B[i][j\u22121], B[l][z] )   (passes 2+: result \u2295 old B[i][j])',
      why: 'Why it matters: each block depends on two earlier blocks, so skipping storage forces recomputing chains of blocks. This is the time-memory trade-off.' },
    { n: 'Pick reference', title: '5. Choose the reference block (l, z)', dur: 9,
      text: 'Two 32-bit values J1 and J2 pick the reference block: J2 chooses the lane l, J1 the column z (recent blocks are favoured). Argon2id uses a data-independent source for slices 1 and 2 of pass 1 and a data-dependent source after that. In the very first slice of pass 1 the reference must stay in the same lane.',
      math: 'pass 1, slices 1\u20132:  (J1,J2) = G(counter block)      otherwise:  (J1,J2) = first 64 bits of B[i][j\u22121]',
      why: 'Why it matters: the independent start gives timing side-channel resistance; the dependent rest makes memory-saving shortcuts expensive.' },
    { n: 'Slices & passes', title: '6. Run lanes in parallel, slice by slice, for t passes', dur: 10,
      text: 'Inside a slice the p lanes can run at the same time. At the end of every slice they must wait for each other (a barrier), because the next slice may reference blocks from other lanes. The whole matrix is then swept t times; passes after the first overwrite blocks and XOR with the old value.',
      math: 'for pass = 1..t:  for slice = 1..4:  all lanes in parallel, then synchronise',
      why: 'Why it matters: more lanes can use more CPU cores, more passes cost more time for you and for an attacker.' },
    { n: 'Finalise', title: '7. XOR the last blocks and hash down to the tag', dur: 10,
      text: "After the last pass, the final block of every lane is XORed together into C. H' then compresses C into the T-byte tag (32 bytes here). The tag, salt and parameters are written out as the encoded string you generate in the Simulation tab.",
      math: "C = B[0][q\u22121] \u2295 B[1][q\u22121] \u2295 \u2026 ;   tag = H'( C, T )",
      why: 'Why it matters: this is the string stored in a database and the one you verify against.' }
  ];
  function durOf(i) { return i === 5 ? 2.5 + AL.T * 4 * 1.3 : ALS[i].dur; }
  function clamp01(v) { return v < 0 ? 0 : v > 1 ? 1 : v; }
  function ease(v) { v = clamp01(v); return v < 0.5 ? 2 * v * v : 1 - Math.pow(-2 * v + 2, 2) / 2; }
  function sg(t, a, b) { return ease((t - a) / (b - a)); }
  function lerp(a, b, k) { return a + (b - a) * k; }
  function hv(a, b, c) { var v = Math.sin(a * 12.9898 + b * 78.233 + c * 37.719) * 43758.5453; return v - Math.floor(v); }
  function rr(x, X, Y, w, h, r) { x.beginPath(); x.moveTo(X + r, Y); x.arcTo(X + w, Y, X + w, Y + h, r); x.arcTo(X + w, Y + h, X, Y + h, r); x.arcTo(X, Y + h, X, Y, r); x.arcTo(X, Y, X + w, Y, r); x.closePath(); }
  function txt(x, s, X, Y, col, size, al, bold) { x.fillStyle = col || CL.text; x.font = (bold ? 'bold ' : '') + (size || 13) + 'px Arial'; x.textAlign = al || 'left'; x.textBaseline = 'middle'; x.fillText(s, X, Y); }
  function box(x, X, Y, w, h, label, col, a, glow) {
    x.save(); x.globalAlpha = a == null ? 1 : a;
    if (glow) { x.shadowColor = col || CL.amber; x.shadowBlur = glow; }
    rr(x, X, Y, w, h, 8); x.fillStyle = CL.card; x.fill(); x.shadowBlur = 0; x.strokeStyle = col || CL.line; x.lineWidth = 1.5; x.stroke();
    if (label) txt(x, label, X + w / 2, Y + h / 2, CL.text, 13, 'center', true);
    x.restore();
  }
  function arrow(x, x1, y1, x2, y2, col, k) {
    k = k == null ? 1 : k; if (k <= 0) return;
    var ex = lerp(x1, x2, k), ey = lerp(y1, y2, k), a = Math.atan2(y2 - y1, x2 - x1);
    x.strokeStyle = col; x.fillStyle = col; x.lineWidth = 2; x.beginPath(); x.moveTo(x1, y1); x.lineTo(ex, ey); x.stroke();
    x.beginPath(); x.moveTo(ex, ey); x.lineTo(ex - 9 * Math.cos(a - 0.4), ey - 9 * Math.sin(a - 0.4)); x.lineTo(ex - 9 * Math.cos(a + 0.4), ey - 9 * Math.sin(a + 0.4)); x.closePath(); x.fill();
  }
  function curve(x, x1, y1, x2, y2, col, k, lift) {
    if (k <= 0) return;
    var mx = (x1 + x2) / 2, my = Math.min(y1, y2) - lift, n = 30;
    x.strokeStyle = col; x.lineWidth = 2; x.beginPath();
    for (var i = 0; i <= n * k; i++) { var u = i / n, px = (1 - u) * (1 - u) * x1 + 2 * (1 - u) * u * mx + u * u * x2, py = (1 - u) * (1 - u) * y1 + 2 * (1 - u) * u * my + u * u * y2; if (i === 0) x.moveTo(px, py); else x.lineTo(px, py); }
    x.stroke();
    if (k >= 1) { x.fillStyle = col; x.beginPath(); x.arc(x2, y2, 4, 0, 6.3); x.fill(); }
  }
  function geo(W, H, p) { var x0 = 64, y0 = 92, ch = Math.max(14, Math.min(34, (H - y0 - 90) / p - 8)); return { x0: x0, y0: y0, cols: 24, cw: (W - x0 - 14) / 24, ch: ch, rowH: ch + 8, p: p }; }
  function cellXY(g, l, c) { return [g.x0 + c * g.cw, g.y0 + l * g.rowH]; }
  function dCell(x, g, l, c, col, a, glow) { var P = cellXY(g, l, c); x.save(); x.globalAlpha = a == null ? 1 : a; x.fillStyle = col; if (glow) { x.shadowColor = col; x.shadowBlur = glow; } x.fillRect(P[0] + 1, P[1], g.cw - 2, g.ch); x.restore(); }
  function laneLabels(x, g, a) { x.save(); x.globalAlpha = a; for (var l = 0; l < g.p; l++) txt(x, 'Lane ' + l, 8, g.y0 + l * g.rowH + g.ch / 2, CL.mute, 12); x.restore(); }
  function hex8(v) { var s = Math.floor(v * 4294967295).toString(16); while (s.length < 8) s = '0' + s; return s; }

  function s1(x, W, H, t) {
    var items = [['P', 'password'], ['S', 'salt'], ['m', 'memory'], ['t', 'passes'], ['p', 'lanes'], ['T', 'tag length'], ['v', '0x13'], ['y', '2 = Argon2id']];
    var bw = Math.min(180, W * 0.24), bh = 96, cx = W * 0.46, cy = H / 2 - 6, cwid = Math.min(128, W * 0.22), st = (H - 70) / 8;
    items.forEach(function (it, i) {
      var k = sg(t, i * 0.32, i * 0.32 + 1.2), sx = 12, sy = 26 + i * st, tx = cx - bw / 2 - cwid + 24, ty = cy - 12;
      x.save(); x.globalAlpha = 0.25; rr(x, sx, sy, cwid, 24, 6); x.strokeStyle = CL.line; x.lineWidth = 1; x.stroke(); x.restore();
      x.save(); x.globalAlpha = k < 0.8 ? 1 : 1 - (k - 0.8) / 0.2;
      var px = lerp(sx, tx, k), py = lerp(sy, ty, k); rr(x, px, py, cwid, 24, 6); x.fillStyle = CL.card; x.fill(); x.strokeStyle = CL.amber; x.lineWidth = 1.5; x.stroke();
      txt(x, it[0] + ' \u00B7 ' + it[1], px + 8, py + 12, CL.text, 12, 'left', true); x.restore();
    });
    var g = sg(t, 2.6, 4.4), glow = t > 2.6 && t < 4.6 ? 10 + 8 * Math.sin(t * 8) : 0;
    box(x, cx - bw / 2, cy - bh / 2, bw, bh, null, CL.amber, 1, glow);
    txt(x, 'BLAKE2b-512', cx, cy - 14, CL.text, 15, 'center', true);
    x.fillStyle = CL.cell; x.fillRect(cx - bw / 2 + 16, cy + 14, bw - 32, 8); x.fillStyle = CL.amber; x.fillRect(cx - bw / 2 + 16, cy + 14, (bw - 32) * g, 8);
    var ox = cx + bw / 2 + 44, cs = Math.max(6, Math.min(14, (W - ox - 14) / 16 - 2)), oy = cy - 2 * (cs + 2);
    arrow(x, cx + bw / 2 + 4, cy, ox - 6, cy, CL.amber, sg(t, 4, 4.5));
    if (t > 4) txt(x, 'H0 \u00B7 64 bytes', ox, oy - 16, CL.mute, 12);
    var n = Math.floor(sg(t, 4.2, 6.4) * 64);
    for (var i = 0; i < n; i++) { var r = Math.floor(i / 16), c = i % 16; x.fillStyle = 'rgba(232,162,74,' + (0.3 + 0.7 * hv(r, c, 9)) + ')'; x.fillRect(ox + c * (cs + 2), oy + r * (cs + 2), cs, cs); }
    x.save(); x.globalAlpha = sg(t, 6.6, 7.4); txt(x, 'Every memory block will be derived from H0', W / 2, H - 22, CL.cream, 14, 'center', true); x.restore();
  }
  function s2(x, W, H, t) {
    var p = AL.p, g = geo(W, H, p), show = sg(t, 0, 3.2) * 24, m = vp().m, mp = 4 * p * Math.floor(m / (4 * p)), q = mp / p;
    for (var l = 0; l < p; l++) for (var c = 0; c < 24; c++) { var a = clamp01(show - c); if (a > 0) dCell(x, g, l, c, CL.fill, a); }
    laneLabels(x, g, sg(t, 0.2, 1));
    for (var k = 0; k < 4; k++) {
      var a2 = sg(t, 3.2 + k * 0.35, 3.8 + k * 0.35), X0 = g.x0 + k * 6 * g.cw + 2, X1 = X0 + 6 * g.cw - 4;
      x.save(); x.globalAlpha = a2; x.strokeStyle = CL.amber; x.lineWidth = 2; x.beginPath(); x.moveTo(X0, g.y0 - 10); x.lineTo(X1, g.y0 - 10); x.stroke(); txt(x, 'Slice ' + k, (X0 + X1) / 2, g.y0 - 24, CL.cream, 12, 'center', true); x.restore();
    }
    var yb = g.y0 + p * g.rowH + 22, fa = sg(t, 4.4, 5.4);
    x.save(); x.globalAlpha = fa;
    txt(x, 'm = ' + m + ' KiB,  p = ' + p + '   \u2192   m\u2032 = 4\u00B7p\u00B7\u230Am/4p\u230B = ' + mp + ' blocks of 1024 bytes', 14, yb, CL.text, 13, 'left', true);
    txt(x, 'each lane: q = m\u2032/p = ' + q + ' blocks      each slice: q/4 = ' + (q / 4) + ' blocks', 14, yb + 22, CL.cream, 13, 'left', true);
    txt(x, 'The picture shows 24 columns per lane as a schematic.', 14, yb + 44, CL.mute, 12);
    x.restore();
  }
  function s3(x, W, H, t) {
    var p = AL.p, g = geo(W, H, p);
    for (var l = 0; l < p; l++) for (var c = 0; c < 24; c++) dCell(x, g, l, c, CL.cell, 0.7);
    laneLabels(x, g, 1);
    box(x, g.x0, 16, 96, 30, 'H0', CL.amber, 1, 8);
    for (var i = 0; i < p; i++) {
      var s0 = 0.6 + i * 0.7, k0 = sg(t, s0, s0 + 1.1), k1 = sg(t, s0 + 1.6, s0 + 2.7), a = cellXY(g, i, 0), b = cellXY(g, i, 1);
      arrow(x, g.x0 + 30, 48, a[0] + g.cw / 2, a[1] - 2, CL.blue, k0);
      arrow(x, g.x0 + 66, 48, b[0] + g.cw / 2, b[1] - 2, CL.amber, k1);
      if (k0 >= 1) dCell(x, g, i, 0, CL.blue, 1, 10); if (k1 >= 1) dCell(x, g, i, 1, CL.amber, 1, 10);
      if (k1 >= 1 && g.rowH > 20) { x.save(); x.globalAlpha = sg(t, s0 + 2.7, s0 + 3.2); txt(x, "B[" + i + "][0] = H'(H0\u2016 0 \u2016" + i + ")    B[" + i + "][1] = H'(H0\u2016 1 \u2016" + i + ")", g.x0 + g.cw * 2.6, g.y0 + i * g.rowH + g.ch / 2, CL.cream, 12, 'left', true); x.restore(); }
    }
    x.save(); x.globalAlpha = sg(t, 5.5, 6.5); txt(x, "Only two blocks per lane exist so far. H' stretches 64 bytes to 1024 bytes.", 14, g.y0 + p * g.rowH + 24, CL.mute, 13); x.restore();
  }
  function mg(x, X, Y, cs, seed, rgb, a, rows, cols, hr, hc) {
    x.save(); x.globalAlpha = a;
    for (var r = 0; r < 8; r++) for (var c = 0; c < 8; c++) {
      var sd = c < cols ? seed + 2 : (r < rows ? seed + 1 : seed), v = hv(r, c, sd);
      x.fillStyle = 'rgba(' + rgb + ',' + (0.2 + 0.8 * v) + ')'; x.fillRect(X + c * cs, Y + r * cs, cs - 1, cs - 1);
    }
    x.strokeStyle = CL.amber; x.lineWidth = 2;
    if (hr >= 0) x.strokeRect(X - 1, Y + hr * cs - 1, 8 * cs + 1, cs + 1);
    if (hc >= 0) x.strokeRect(X + hc * cs - 1, Y - 1, cs + 1, 8 * cs + 1);
    x.restore();
  }
  function s4(x, W, H, t) {
    var cs = Math.max(6, Math.min(14, (W - 40) / 52)), gw = 8 * cs, gap = (W - 20 - 5 * gw) / 4, Y = 74, X = [], i;
    for (i = 0; i < 5; i++) X.push(10 + i * (gw + gap));
    var names = ['X = B[i][j\u22121]', 'Y = B[l][z]', 'R = X \u2295 Y', 'Z = P(rows, cols)', 'B[i][j] = Z \u2295 R'];
    var al = [sg(t, 0, 1), sg(t, 0.4, 1.4), sg(t, 1.8, 2.8), sg(t, 2.8, 3.4), sg(t, 6.9, 7.8)];
    var rows = Math.floor(sg(t, 3, 4.9) * 8 + 0.001), cols = Math.floor(sg(t, 5, 6.9) * 8 + 0.001);
    var hr = t > 3 && t < 4.9 ? Math.min(7, rows) : -1, hc = t > 5 && t < 6.9 ? Math.min(7, cols) : -1;
    for (i = 0; i < 5; i++) { x.save(); x.globalAlpha = al[i]; txt(x, names[i], X[i] + gw / 2, Y - 18, CL.mute, Math.max(10, Math.min(12, gw / 8)), 'center', true); x.restore(); }
    mg(x, X[0], Y, cs, 1, '91,141,239', al[0], 0, 0, -1, -1);
    mg(x, X[1], Y, cs, 2, '232,162,74', al[1], 0, 0, -1, -1);
    mg(x, X[2], Y, cs, 3, '201,184,166', al[2], 0, 0, -1, -1);
    mg(x, X[3], Y, cs, 3, '201,184,166', al[3], rows, cols, hr, hc);
    mg(x, X[4], Y, cs, 7, '255,233,207', al[4], 0, 0, -1, -1);
    var ops = ['\u2295', '=', 'P', '\u2295 R'];
    for (i = 0; i < 4; i++) { x.save(); x.globalAlpha = i === 0 ? al[1] : i === 1 ? al[2] : i === 2 ? al[3] : al[4]; txt(x, ops[i], X[i] + gw + gap / 2, Y + gw / 2, CL.amber, 18, 'center', true); x.restore(); }
    var cap = t < 1.8 ? 'Take two 1024-byte blocks: X is the previous block, Y is the reference block.' : t < 3 ? 'R = X \u2295 Y  (bitwise XOR of the two blocks).' :
      t < 5 ? 'Apply the BLAKE2b round permutation P to each of the 8 rows (16-byte registers).' : t < 6.9 ? 'Then apply P to each of the 8 columns.' : 'New block = Z \u2295 R. (In passes 2+ it is also XORed with the old block.)';
    txt(x, cap, W / 2, Y + gw + 34, CL.cream, 13, 'center', true);
    var sy = H - 54, n = 22, sw = Math.min(26, (W - 40) / n), sx = (W - n * sw) / 2, kk = sg(t, 7.2, 8.4);
    for (i = 0; i < n; i++) { x.fillStyle = i < 12 ? CL.fill : CL.cell; x.fillRect(sx + i * sw + 1, sy, sw - 2, 16); }
    x.save(); x.globalAlpha = kk; x.fillStyle = CL.cream; x.shadowColor = CL.cream; x.shadowBlur = 10; x.fillRect(sx + 12 * sw + 1, sy, sw - 2, 16); x.restore();
    arrow(x, X[4] + gw / 2, Y + gw + 4 + 14, sx + 12.5 * sw, sy - 4, CL.cream, kk);
    txt(x, 'lane i', sx - 4, sy + 8, CL.mute, 11, 'right'); txt(x, 'B[i][j]', sx + 12.5 * sw, sy + 28, CL.cream, 11, 'center', true);
  }
  function s5(x, W, H, t) {
    var p = AL.p, g = geo(W, H, p), j = 2 + Math.floor(sg(t, 0.3, 8.2) * 21.99), indep = j < 12, sl = Math.floor(j / 6);
    var r = hv(j, 3, 1), z = Math.max(0, j - 1 - Math.floor(r * r * (j - 1))), l2 = p > 1 ? Math.floor(hv(j, 5, 2) * p) : 0;
    if (l2 !== 0) { var lim = 6 * sl - 1; if (lim < 0) l2 = 0; else z = Math.min(z, lim); }
    for (var l = 0; l < p; l++) for (var c = 0; c < 24; c++) {
      if (l === 0 && c === j) continue;
      if (l === 0 ? c < j : c < 6 * sl) dCell(x, g, l, c, c < 12 ? CL.blue : CL.amber, 0.8); else dCell(x, g, l, c, CL.cell, 0.7);
    }
    laneLabels(x, g, 1);
    var cur = cellXY(g, 0, j), ref = cellXY(g, l2, z);
    dCell(x, g, 0, j, CL.cream, 1, 14);
    curve(x, cur[0] + g.cw / 2, cur[1], ref[0] + g.cw / 2, ref[1], CL.cream, 1, 22 + Math.abs(j - z) * 3);
    dCell(x, g, l2, z, CL.green, 1, 14);
    var bw = Math.min(250, (W - 40) / 2);
    box(x, 12, 10, bw, 44, null, CL.blue, indep ? 1 : 0.35, indep ? 8 : 0); box(x, W - bw - 12, 10, bw, 44, null, CL.amber, indep ? 0.35 : 1, indep ? 0 : 8);
    x.save(); x.globalAlpha = indep ? 1 : 0.4; txt(x, 'DATA-INDEPENDENT', 12 + bw / 2, 24, CL.blue, 12, 'center', true); txt(x, 'J1,J2 = G(counter block): no memory read', 12 + bw / 2, 42, CL.text, 11, 'center'); x.restore();
    x.save(); x.globalAlpha = indep ? 0.4 : 1; txt(x, 'DATA-DEPENDENT', W - bw / 2 - 12, 24, CL.amber, 12, 'center', true); txt(x, 'J1,J2 = first 64 bits of B[i][j\u22121]', W - bw / 2 - 12, 42, CL.text, 11, 'center'); x.restore();
    if (!indep) { var pv = cellXY(g, 0, j - 1); arrow(x, pv[0] + g.cw / 2, pv[1] - 2, W - bw / 2 - 12, 58, CL.amber, 1); }
    var yb = g.y0 + p * g.rowH + 22;
    txt(x, 'Pass 1 \u00B7 slice ' + (sl + 1) + ' \u00B7 computing block ' + j + ' of lane 0', 14, yb, CL.cream, 13, 'left', true);
    txt(x, 'J1 = 0x' + hex8(hv(j, 7, 3)) + '   J2 = 0x' + hex8(hv(j, 8, 4)) + '   \u2192 reference B[' + l2 + '][' + z + ']  (recent blocks are favoured)', 14, yb + 22, CL.mute, 12);
    txt(x, 'cream = block being computed, green = reference block, blue / orange = filled blocks', 14, yb + 44, CL.mute, 11);
  }
  function s6(x, W, H, t) {
    var p = AL.p, T = AL.T, sl = Math.max(0, (t - 0.8)) / 1.3, tot = T * 4, idx, f;
    if (sl >= tot) { idx = tot - 1; f = 1; } else { idx = Math.floor(sl); f = sl - idx; }
    var pass = Math.floor(idx / 4), slice = idx % 4, bx = 74, bwid = W - bx - 16, sw = bwid / 4, fl = [0.55, 0.7, 0.85, 0.95];
    txt(x, 'Pass ' + (pass + 1) + ' / ' + T, 12, 24, CL.cream, 18, 'left', true); txt(x, 'Slice ' + (slice + 1) + ' / 4', 12, 50, CL.mute, 13, 'left', true);
    txt(x, pass === 0 ? 'Pass 1: blocks are written for the first time' : 'Pass ' + (pass + 1) + ': every new block is also XORed with the block it overwrites', 140, 24, CL.mute, 12);
    var done = sl >= tot;
    for (var l = 0; l < p; l++) {
      var y = 80 + l * 46; txt(x, 'Lane ' + l, 10, y + 15, CL.mute, 12);
      for (var s = 0; s < 4; s++) {
        var cur = s === slice && !done, ps = done || s < slice, prog = ps ? 1 : cur ? Math.min(1, f / fl[l]) : 0, X0 = bx + s * sw + 2, w = sw - 4;
        x.fillStyle = CL.cell; x.fillRect(X0, y, w, 30);
        if (pass > 0 && !ps) { x.save(); x.globalAlpha = 0.45; x.fillStyle = CL.cream; x.fillRect(X0, y, w, 30); x.restore(); }
        x.fillStyle = pass === 0 ? (s < 2 ? CL.blue : CL.amber) : CL.cream; x.fillRect(X0, y, w * prog, 30);
        if (cur && f > fl[l] && f < 1) { x.save(); x.globalAlpha = 0.5 + 0.5 * Math.sin(t * 10); txt(x, 'waiting at barrier', X0 + w / 2, y + 15, CL.text, 11, 'center', true); x.restore(); }
      }
    }
    var yb = 80 + p * 46;
    for (s = 1; s < 4; s++) { x.save(); x.strokeStyle = CL.line; x.setLineDash([4, 4]); x.beginPath(); x.moveTo(bx + s * sw, 70); x.lineTo(bx + s * sw, yb - 8); x.stroke(); x.restore(); }
    if (!done && f > 0.93) { x.save(); x.globalAlpha = (f - 0.93) / 0.07; x.strokeStyle = CL.green; x.lineWidth = 3; x.beginPath(); var bxx = bx + (slice + 1) * sw; x.moveTo(bxx, 70); x.lineTo(bxx, yb - 8); x.stroke(); x.restore(); }
    txt(x, done ? 'All ' + T + ' pass(es) finished.' : 'Lanes run in parallel; all must reach the barrier before the next slice starts.', 14, yb + 14, CL.cream, 13, 'left', true);
    txt(x, 'blue = data-independent, orange = data-dependent, light = later passes', 14, yb + 38, CL.mute, 12);
  }
  function s7(x, W, H, t) {
    var p = AL.p, g = geo(W, H, p), m = vp().m, l, c;
    for (l = 0; l < p; l++) for (c = 0; c < 23; c++) dCell(x, g, l, c, CL.fill, 0.9);
    laneLabels(x, g, 1);
    var pulse = t < 3 ? 6 + 8 * Math.sin(t * 7) : 0;
    for (l = 0; l < p; l++) dCell(x, g, l, 23, CL.cream, 1, pulse);
    var yy = g.y0 + p * g.rowH + 36, xc = W * 0.14;
    var k0 = sg(t, 1, 3);
    for (l = 0; l < p; l++) { var pt = cellXY(g, l, 23), kk = clamp01((k0 * 1.4) - l * 0.12); if (kk > 0 && kk < 1) { var px = lerp(pt[0] + g.cw / 2, xc, kk), py = lerp(pt[1] + g.ch, yy, kk); x.fillStyle = CL.cream; x.fillRect(px - 5, py - 5, 10, 10); } }
    x.save(); x.globalAlpha = sg(t, 0.8, 1.6); x.strokeStyle = CL.amber; x.lineWidth = 2; x.beginPath(); x.arc(xc, yy, 16, 0, 6.3); x.stroke(); txt(x, '\u2295', xc, yy, CL.amber, 20, 'center', true); x.restore();
    var cx = W * 0.3, aC = sg(t, 3, 4), aH = sg(t, 4.2, 5.2);
    arrow(x, xc + 18, yy, cx - 4, yy, CL.amber, aC); box(x, cx, yy - 16, 70, 32, 'C', CL.amber, aC);
    var hx = W * 0.46; arrow(x, cx + 72, yy, hx - 4, yy, CL.amber, aH); box(x, hx, yy - 16, 70, 32, "H'", CL.amber, aH, aH > 0.9 ? 8 : 0);
    var tx = W * 0.62, cs = Math.max(5, Math.min(12, (W - tx - 14) / 16 - 2)), n = Math.floor(sg(t, 5.2, 6.8) * 32);
    arrow(x, hx + 72, yy, tx - 6, yy, CL.amber, sg(t, 5, 5.4));
    if (t > 5.2) txt(x, 'tag \u00B7 32 bytes', tx, yy - 26, CL.mute, 12);
    for (var i = 0; i < n; i++) { x.fillStyle = 'rgba(142,226,156,' + (0.35 + 0.65 * hv(i, 1, 5)) + ')'; x.fillRect(tx + (i % 16) * (cs + 2), yy - cs - 1 + Math.floor(i / 16) * (cs + 2), cs, cs); }
    var s = '$argon2id$v=19$m=' + m + ',t=' + AL.T + ',p=' + p + '$<salt>$<tag>', len = Math.floor(clamp01((t - 7) / 2.2) * s.length);
    txt(x, 'Encoded string:', 14, H - 48, CL.mute, 12); txt(x, s.slice(0, len), 14, H - 26, CL.cream, 13, 'left', true);
  }
  var ALSC = [s1, s2, s3, s4, s5, s6, s7];

  function alInfo() {
    var S = ALS[AL.step];
    put('al-title', S.title); put('al-text', S.text); put('al-math', S.math); put('al-why', S.why);
    document.querySelectorAll('.al-chip').forEach(function (b, i) { b.classList.toggle('on', i === AL.step); b.querySelector('i').style.width = i < AL.step ? '100%' : '0'; });
  }
  function alDraw() {
    var c = $('al-cv'), W = c.clientWidth || 800, H = W < 560 ? 400 : 380, dpr = window.devicePixelRatio || 1, d = durOf(AL.step);
    if (c.width !== Math.round(W * dpr) || c.height !== Math.round(H * dpr)) { c.width = Math.round(W * dpr); c.height = Math.round(H * dpr); c.style.height = H + 'px'; }
    var x = c.getContext('2d'); x.setTransform(dpr, 0, 0, dpr, 0, 0); x.clearRect(0, 0, W, H);
    ALSC[AL.step](x, W, H, Math.min(AL.t, d));
    x.fillStyle = CL.amber; x.fillRect(0, H - 3, W * Math.min(1, AL.t / d), 3);
    var chip = document.querySelectorAll('.al-chip')[AL.step]; if (chip) chip.querySelector('i').style.width = (100 * Math.min(1, AL.t / d)) + '%';
    if (AL.play) $('al-scrub').value = Math.round(1000 * Math.min(1, AL.t / d));
  }
  function alGo(i, keep) { AL.step = (i + ALS.length) % ALS.length; AL.t = 0; alInfo(); alDraw(); }
  function alSetPlay(on) { AL.play = on; $('al-play').textContent = on ? '\u23F8 Pause' : '\u25B6 Play'; }
  function alTick(now) {
    if (AL.play) { var dt = Math.min(0.05, (now - AL.last) / 1000); AL.t += dt * AL.speed; if (AL.t >= durOf(AL.step)) alGo(AL.step + 1); }
    AL.last = now; alDraw(); AL.raf = requestAnimationFrame(alTick);
  }
  function alRun(on) {
    if (on && !AL.raf) { AL.last = performance.now(); AL.raf = requestAnimationFrame(alTick); }
    else if (!on && AL.raf) { cancelAnimationFrame(AL.raf); AL.raf = 0; }
  }
  function algInit() {
    var c = $('al-cv'), st = $('al-steps');
    if (!c) return;
    ALS.forEach(function (S, i) {
      var b = el('button', (i + 1) + '. ' + S.n, 'al-chip'); b.type = 'button'; b.appendChild(document.createElement('i'));
      b.addEventListener('click', function () { alGo(i); }); st.appendChild(b);
    });
    on('al-prev', function () { alGo(AL.step - 1); }); on('al-next', function () { alGo(AL.step + 1); });
    on('al-rep', function () { AL.t = 0; alDraw(); }); on('al-play', function () { alSetPlay(!AL.play); });
    $('al-speed').addEventListener('input', function () { AL.speed = Number(this.value) || 1; });
    $('al-p').addEventListener('change', function () { AL.p = Number(this.value); alDraw(); });
    $('al-t').addEventListener('change', function () { AL.T = Number(this.value); AL.t = Math.min(AL.t, durOf(AL.step)); alDraw(); });
    $('al-scrub').addEventListener('input', function () { alSetPlay(false); AL.t = Number(this.value) / 1000 * durOf(AL.step); alDraw(); });
    if (reduce) alSetPlay(false);
    alInfo(); alDraw();
    if (window.IntersectionObserver) new IntersectionObserver(function (en) { alRun(en[0].isIntersecting); }).observe(c); else alRun(true);
  }
  /* ALGO-END */

  function procInit() {
    var box = $('proc-box');
    if (!box) return;
    var P = [
      { t: 'Type a password', d: 'In the Simulation tab type a password, for example correct horse battery staple. The strength bar reacts as you type.', go: '#a2-pw', r: [['input', '#a2-pw']] },
      { t: 'Generate a random salt', d: 'Click Random salt for a 16-byte salt (or type 8 or more characters). Same password plus a different salt gives a completely different hash.', go: '#a2-rand', r: [['click', '#a2-rand']] },
      { t: 'Set m, t and p', d: 'Use the \u2212 / + buttons, sliders or number boxes. Read the live hint under each control and watch the memory grid change shape.', go: '.pgrid', r: [['click', '.pm'], ['input', '#a2-mem,#a2-iter,#a2-par,#sl-m,#sl-t,#sl-p']] },
      { t: 'Generate the Argon2id hash', d: 'Click Generate. The process diagram lights up node by node while the real Argon2id runs in the background.', go: '#a2-hash', r: [['click', '#a2-hash']] },
      { t: 'Inspect the memory visualizer', d: 'Pause, replay, change the speed and hover squares to see lane, slice and phase (blue = data-independent, orange = data-dependent).', go: '.vz', r: [['click', '#a2-vplay,#a2-vpause,#a2-vreplay'], ['input', '#a2-speed']] },
      { t: 'Change one parameter, hash again', d: 'Change only m (for example 4096, then 65536) and generate again. Compare the measured times in the Observations table.', go: '#a2-hash', need: 2, r: [['click', '#a2-hash']] },
      { t: 'Verify: right, then wrong password', d: 'In Verify password click Verify with the correct password (MATCH), then with a wrong one (NO MATCH).', go: '#a2-verify', need: 2, r: [['click', '#a2-verify']] },
      { t: 'Compare algorithms and A vs B', d: 'Click Run comparison for MD5, SHA-1, SHA-256, PBKDF2 and Argon2id, then Compare A vs B for two Argon2id settings.', go: '#a2-compare', r: [['click', '#a2-compare,#a2-cfg']] },
      { t: 'Run the Attack lab', d: 'Click Launch dictionary attack. Note who is cracked under SHA-256 and under Argon2id, then change m, launch again and read the GPU calculator.', go: 'ATTACK', r: [['click', 'ATTACK']] },
      { t: 'Take the quiz', d: 'Answer all 10 compulsory questions in the Quiz tab and submit.', tab: 'quiz', go: '#a2-qsubmit', r: [['click', '#a2-qsubmit']] }
    ];
    var top = el('div', undefined, 'pr-top'), bar = el('div', undefined, 'bar'), fill = el('i'), cnt = el('b'), nxt = el('button', 'Take me to the next step', 'a2-btn'), rst = el('button', 'Reset', 'a2-btn');
    nxt.type = 'button'; rst.type = 'button'; bar.appendChild(fill); top.append(cnt, bar, nxt, rst); box.appendChild(top);
    var msg = el('p', '', 'a2-ok'); box.appendChild(msg);
    var cards = P.map(function (s, i) {
      var c = el('div', undefined, 'pr-card'), n = el('button', undefined, 'pr-n'), tx = el('div'), g = el('button', 'Show me', 'a2-btn');
      n.type = 'button'; n.setAttribute('aria-label', 'Mark step ' + (i + 1) + ' done or not done'); n.innerHTML = '<span>' + (i + 1) + '</span><svg viewBox="0 0 24 24"><path d="M4 13l5 5 11-12"/></svg>';
      tx.appendChild(el('b', s.t)); tx.appendChild(el('p', s.d)); g.type = 'button';
      n.addEventListener('click', function () { s.done = !s.done; s.n = s.done ? Math.max(s.n || 0, s.need || 1) : 0; render(); });
      g.addEventListener('click', function () { go(i); });
      c.append(n, tx, g); box.appendChild(c); return c;
    });
    function render() {
      var d = 0, cur = -1;
      P.forEach(function (s, i) { if (s.done) d++; else if (cur < 0) cur = i; cards[i].classList.toggle('done', !!s.done); cards[i].classList.toggle('cur', i === cur); });
      cnt.textContent = d + ' / ' + P.length + ' completed'; fill.style.width = (100 * d / P.length) + '%';
      nxt.disabled = cur < 0; msg.textContent = d === P.length ? 'All steps complete. Great work!' : '';
    }
    function setDone(i) { if (!P[i].done) { P[i].done = true; render(); } }
    function go(i) {
      var s = P[i], tb = document.querySelector('.tab-btn[data-tab="' + (s.tab || 'simulation') + '"]');
      if (tb) tb.click();
      setTimeout(function () {
        var t = s.go === 'ATTACK' ? (Array.prototype.filter.call(document.querySelectorAll('#simulation button'), function (b) { return /attack/i.test(b.textContent); })[0] || $('a2-compare')) : document.querySelector(s.go);
        if (!t) return;
        t.scrollIntoView({ behavior: 'smooth', block: 'center' }); t.classList.remove('a2-pulse'); void t.offsetWidth; t.classList.add('a2-pulse');
        setTimeout(function () { t.classList.remove('a2-pulse'); }, 2600);
      }, 180);
    }
    function hit(e) {
      var tg = e.target; if (!tg || !tg.closest) return;
      P.forEach(function (s, i) {
        if (s.done) return;
        s.r.forEach(function (r) {
          if (r[0] !== e.type) return;
          var ok = r[1] === 'ATTACK' ? (function () { var b = tg.closest('button'); return b && /attack/i.test(b.textContent); })() : tg.closest(r[1]);
          if (ok) s.n = (s.n || 0) + 1;
        });
        if ((s.n || 0) >= (s.need || 1)) setDone(i);
      });
    }
    document.addEventListener('click', hit); document.addEventListener('input', hit);
    nxt.addEventListener('click', function () { for (var i = 0; i < P.length; i++) if (!P[i].done) { go(i); return; } });
    rst.addEventListener('click', function () { P.forEach(function (s) { s.done = false; s.n = 0; }); render(); });
    render();
  }

  function strength() {
    var pw = $('a2-pw').value, pool = 0;
    if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26; if (/\d/.test(pw)) pool += 10; if (/[^A-Za-z0-9]/.test(pw)) pool += 32;
    var bits = pw.length ? Math.round(pw.length * Math.log(pool || 1) / Math.LN2) : 0, lbl = bits < 40 ? 'Weak' : bits < 60 ? 'Fair' : bits < 80 ? 'Good' : 'Strong';
    $('a2-sbar').style.width = Math.min(100, bits) + '%';
    $('a2-stxt').textContent = pw.length ? 'Rough strength: ' + lbl + ' (about ' + bits + ' bits if chosen at random). Real passwords are guessed from patterns, and famous phrases are far weaker, so treat this as an upper bound.' : 'Type a password to see a rough strength estimate.';
  }
  function hoverInit() {
    var c = $('a2-cv');
    function info(e) {
      var g = viz.geo, r = c.getBoundingClientRect(), h = $('a2-hover');
      if (!g) return;
      var mx = e.clientX - r.left - g.pad - g.lab, my = e.clientY - r.top - g.pad, lane = Math.floor(my / (g.lh + g.gap)), yy = my - lane * (g.lh + g.gap);
      var col = Math.floor(mx / (g.cw + 1)), row = Math.floor(yy / (g.ch + 2));
      if (mx < 0 || my < 0 || lane >= viz.P.p || yy > g.lh || col < 0 || col >= g.q || row < 0 || row > 3) { h.textContent = 'Hover or tap a square to inspect it.'; return; }
      var i = row * g.q + col, k = (g.done || i < g.pos) ? g.pass : g.pass - 1, st;
      if (g.alloc) st = i < (viz.s / viz.A) * g.per ? 'allocated, not yet processed' : 'empty (not yet allocated)';
      else if (!g.done && i === Math.floor(g.pos)) st = 'being processed now';
      else if (k < 0) st = 'allocated, not yet processed';
      else st = 'processed in pass ' + (k + 1) + ' (' + (k === 0 ? (i < g.per / 2 ? 'data-independent' : 'data-dependent') : 'later pass, data-dependent') + ')';
      h.textContent = 'Lane ' + (lane + 1) + ', slice ' + (row + 1) + ', square ' + (col + 1) + ' (about ' + (viz.P.m / (viz.P.p * g.per)).toFixed(1) + ' blocks): ' + st + '.';
    }
    c.addEventListener('mousemove', info); c.addEventListener('click', info);
  }
  function extrasInit() {
    $('a2-pw').addEventListener('input', strength); strength();
    document.querySelectorAll('[data-cf]').forEach(function (b) {
      b.addEventListener('click', function () {
        var P = vp(), k = b.getAttribute('data-cf');
        $('cf' + k + '-m').value = P.m; $('cf' + k + '-t').value = P.t; $('cf' + k + '-p').value = P.p;
      });
    });
  }

  /* ---------- wiring (each part isolated so one failure cannot stop the rest) ---------- */
  function init() {
    var steps = [
      function () {
        if (!hw) showError('The Argon2id library (js/vendor/hash-wasm.min.js) did not load. Open the page through http://localhost and check the console (F12).');
        on('a2-hash', onHash); on('a2-compare', onCompare); on('a2-verify', onVerify); on('a2-cfg', onCfg);
        $('a2-pw').addEventListener('keydown', function (e) { if (e.key === 'Enter') onHash(); });
        on('a2-clear', function () { obs = []; renderObs(); });
        renderObs();
      },
      function () {
        on('a2-rand', function () { $('a2-salt').value = toHex(crypto.getRandomValues(new Uint8Array(16))); sync(); });
        $('a2-show').addEventListener('change', function (e) { $('a2-pw').type = e.target.checked ? 'text' : 'password'; });
      },
      paramInit, vizInit, hoverInit, algInit, procInit, extrasInit,
      function () { $('a2-qsubmit').addEventListener('click', submitQuiz); $('a2-qreset').addEventListener('click', renderQuiz); renderQuiz(); }
    ];
    steps.forEach(function (s) { try { s(); } catch (e) { console.error('Argon2id init step failed:', e); } });
  }
  window.addEventListener('error', function (e) { var b = $('a2-error'); if (b && !b.textContent) b.textContent = 'Script error: ' + e.message; });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();