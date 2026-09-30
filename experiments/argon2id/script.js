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
  var BUSY = '#a2-hash,#a2-compare,#a2-verify,#a2-cfg,#a2-rand,#a2-pw,#a2-salt,#a2-mem,#a2-iter,#a2-par,#sl-m,#sl-t,#sl-p,#simulation .pm,#simulation .pcard';
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
  var viz = { s: 0, T: 1, A: 1, per: 64, P: { m: 19456, t: 2, p: 1 }, play: false, hold: false, fast: false, speed: 1, last: 0, raf: 0, busy: false, t0: 0, clock: 0, dp: Promise.resolve() };
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
    $('pn-m').textContent = P.m > OW.m ? 'Higher memory \u2192 harder for attackers to run many guesses at once (and more RAM per login for you).' : P.m < OW.m ? 'Lower memory \u2192 cheaper for the server, but easier for attackers to run many guesses at once.' : 'Controls how much memory Argon2id uses (OWASP minimum shown).';
    $('pn-t').textContent = P.t > OW.t ? 'Higher time \u2192 more computation per password.' : P.t < OW.t ? 'Lower time \u2192 less computation per password.' : 'Controls the number of passes over the memory.';
    $('pn-p').textContent = P.p > OW.p ? 'Higher parallelism \u2192 more lanes processed concurrently (this browser runs the library on one thread, so time may not drop).' : 'Controls the number of parallel processing lanes.';
    document.querySelectorAll('.pcard').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-preset') === P.m + ',' + P.t + ',' + P.p); });
    if (!viz.busy) { put('pd-pars', fmtMem(P.m) + ' \u00B7 t=' + P.t + ' \u00B7 p=' + P.p); vsetup(P); viz.play = false; viz.s = viz.T; draw(performance.now()); }
  }
  function fixInputs() {
    var p = clampI($('a2-par').value, 1, 4); $('a2-par').value = p;
    $('a2-iter').value = clampI($('a2-iter').value, 1, 10);
    $('a2-mem').value = clampI($('a2-mem').value, 8 * p, 65536);
  }
  function tween(id, to) {
    var e = $(id), from = Number(e.value) || to, t0 = performance.now();
    if (reduce) { e.value = to; sync(); return; }
    (function f(n) { var k = Math.min(1, (n - t0) / 180); e.value = Math.round(from + (to - from) * k); sync(); if (k < 1) requestAnimationFrame(f); })(t0);
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
    document.querySelectorAll('.pcard').forEach(function (b) {
      b.addEventListener('click', function () {
        var a = b.getAttribute('data-preset').split(',').map(Number);
        tween('a2-mem', a[0]); tween('a2-iter', a[1]); tween('a2-par', a[2]);
        setTimeout(function () { if (!viz.busy) { vsetup(vp()); viz.s = 0; viz.hold = false; viz.fast = false; vplay(); } }, reduce ? 0 : 200);
      });
    });
  }
  function vizInit() {
    $('a2-speed').addEventListener('input', function () { viz.speed = Number(this.value) || 1; });
    on('a2-vplay', vplay); on('a2-vpause', vpause);
    on('a2-vreplay', function () { if (viz.busy) return; vsetup(vp()); viz.s = 0; viz.hold = false; viz.fast = false; vplay(); });
    window.addEventListener('resize', function () { draw(performance.now()); });
    if (window.ResizeObserver) new ResizeObserver(function () { draw(performance.now()); }).observe($('a2-cv'));
    tipInit(); sync();
  }

  /* ---------- configuration comparison ---------- */
  var CFG = { light: [4096, 1, 1], owasp: [19456, 2, 1], heavy: [65536, 3, 2] };
  function cfgOf(k) { if (k === 'cur') { var P = vp(); return [P.m, P.t, P.p]; } return CFG[k]; }
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
    var cfgs = [cfgOf($('cf-a').value), cfgOf($('cf-b').value)], out = $('cf-out'), res = [];
    setBusy(true); out.replaceChildren(el('p', 'Running configurations A and B\u2026'));
    try {
      await argon({ pw: 'warmup', salt: 'warmup00', m: 8, t: 1, p: 1 });
      for (var i = 0; i < 2; i++) {
        var c = cfgs[i], r = await argon({ pw: base.pw, salt: base.salt, m: Math.max(c[0], 8 * c[2]), t: c[1], p: c[2] });
        res.push({ c: c, ms: r.ms });
      }
      out.replaceChildren(
        cfBars('Memory', [res[0].c[0], res[1].c[0]], fmtMem), cfBars('Time cost t (passes)', [res[0].c[1], res[1].c[1]], String),
        cfBars('Parallelism p (lanes)', [res[0].c[2], res[1].c[2]], String), cfBars('Measured time', [res[0].ms, res[1].ms], fmt),
        el('p', 'Measured times are observations from this device and browser (single runs after a warm-up), not universal benchmarks.', 'a2-hint'));
    } catch (e) { showError('Comparison failed: ' + (e && e.message ? e.message : e)); out.replaceChildren(); }
    setBusy(false);
  }

  /* ---------- quiz ---------- */
  var QUIZ = [
    { q: 'Why is SHA-256 alone a poor choice for storing passwords?', o: ['It produces a hash that is too short to store', 'It is very fast, so attackers can test guesses quickly', 'It can be decrypted with a key', 'It cannot take a salt'], a: 1, why: 'Speed is the problem: fast hashes let an attacker try enormous numbers of guesses per second.' },
    { q: 'What is the purpose of a salt?', o: ['To encrypt the password', 'To make the hash shorter', 'To make identical passwords produce different hashes', 'To keep the hash secret'], a: 2, why: 'A unique random salt defeats precomputed tables and hides repeated passwords. It is stored openly with the hash.' },
    { q: 'In Argon2id, what does the memory cost parameter control?', o: ['How many bytes the salt has', 'How much memory is filled and used per hash', 'How many characters the password may have', 'The number of users supported'], a: 1, why: 'Memory cost m (in KiB) sets the size of the memory block, which makes large-scale parallel cracking expensive.' },
    { q: 'What does the time cost (iterations) parameter change?', o: ['The number of passes over the memory', 'The version of Argon2', 'The length of the password', 'The character set of the salt'], a: 0, why: 'Time cost t is the number of passes; more passes means more work for every guess.' },
    { q: 'Argon2id is best described as:', o: ['A reversible cipher', 'A hybrid of Argon2i and Argon2d', 'A public-key signature scheme', 'A checksum for files'], a: 1, why: 'Argon2id starts with data-independent access (like Argon2i) and continues with data-dependent access (like Argon2d).' },
    { q: 'How does Argon2id verify a password at login?', o: ['It decrypts the stored hash', 'It sends the password to the server unhashed', 'It re-hashes the entered password with the stored salt and parameters and compares', 'It compares the password length'], a: 2, why: 'Parameters and salt are read from the encoded string, the entered password is hashed, and the digests are compared.' },
    { q: 'An attacker stores only half of the memory blocks to save RAM. What happens?', o: ['Nothing, the hash is unchanged', 'Missing blocks must be recomputed, so the work grows a lot', 'The hash becomes reversible', 'The salt stops working'], a: 1, why: 'Each block depends on earlier blocks, so every missing block has to be rebuilt. This is the time-memory trade-off.' },
    { q: 'Why does Argon2id need a lot of memory per guess?', o: ['To store the password for later', 'GPUs and ASICs have little memory per core, so it limits parallel guessing', 'To make the hash reversible', 'Because the salt is large'], a: 1, why: 'Memory, not just time, is what cheap parallel hardware lacks. That is what memory-hard means.' }
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
        r.type = 'radio'; r.name = 'a2-q' + i; r.id = id; r.value = String(j);
        lab.appendChild(r); lab.appendChild(document.createTextNode(opt)); fs.appendChild(lab);
      });
      var fb = el('p', '', 'a2-hint'); fb.id = 'a2-fb' + i; fs.appendChild(fb);
      box.appendChild(fs);
    });
    $('a2-qresult').textContent = '';
  }
  function submitQuiz() {
    var score = 0, un = 0;
    QUIZ.forEach(function (item, i) {
      var sel = document.querySelector('input[name="a2-q' + i + '"]:checked'), fb = $('a2-fb' + i);
      if (!sel) { un++; fb.textContent = 'Not answered.'; fb.className = 'a2-hint a2-bad'; return; }
      if (Number(sel.value) === item.a) { score++; fb.textContent = 'Correct. ' + item.why; fb.className = 'a2-hint a2-ok'; }
      else { fb.textContent = 'Incorrect. Correct answer: ' + item.o[item.a] + '. ' + item.why; fb.className = 'a2-hint a2-bad'; }
    });
    var msg = 'Score: ' + score + ' / ' + QUIZ.length + '.';
    msg += un ? ' ' + un + ' question(s) unanswered.' : score === QUIZ.length ? ' Excellent work.' : ' Review the Theory tab and try again.';
    $('a2-qresult').textContent = msg;
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
      paramInit, vizInit,
      function () { $('a2-qsubmit').addEventListener('click', submitQuiz); $('a2-qreset').addEventListener('click', renderQuiz); renderQuiz(); }
    ];
    steps.forEach(function (s) { try { s(); } catch (e) { console.error('Argon2id init step failed:', e); } });
  }
  window.addEventListener('error', function (e) { var b = $('a2-error'); if (b && !b.textContent) b.textContent = 'Script error: ' + e.message; });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();