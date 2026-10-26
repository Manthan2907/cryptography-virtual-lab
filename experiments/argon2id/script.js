/* Argon2id experiment - uses hash-wasm (js/vendor) for Argon2id, CryptoJS for MD5,
   and the browser Web Crypto API for SHA-1, SHA-256 and PBKDF2. */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var enc = new TextEncoder();
  var hw = window.hashwasm || window.hashWasm;
  var obsRows = [];
  var lastEncoded = '';

  /* ---------- helpers ---------- */
  function toHex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('');
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
  function showError(msg) { $('a2-error').textContent = msg || ''; }
  function setBusy(busy) {
    ['a2-hash', 'a2-compare', 'a2-verify'].forEach(function (id) { $(id).disabled = busy; });
  }
  function makeTable(headers, rows) {
    var t = el('table', undefined, 'a2-table');
    var thead = el('thead'), hr = el('tr');
    headers.forEach(function (h) { hr.appendChild(el('th', h)); });
    thead.appendChild(hr); t.appendChild(thead);
    var tb = el('tbody');
    rows.forEach(function (r) {
      var tr = el('tr');
      r.forEach(function (c) {
        var td = el('td', c.text !== undefined ? c.text : c, c.mono ? 'a2-mono' : '');
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    return t;
  }
  function fmtMs(ms) { return ms < 1 ? ms.toFixed(3) + ' ms' : ms.toFixed(1) + ' ms'; }

  /* ---------- input validation ---------- */
  function readInputs() {
    var pw = $('a2-pw').value;
    var salt = $('a2-salt').value;
    var m = Number($('a2-mem').value);
    var t = Number($('a2-iter').value);
    var p = Number($('a2-par').value);
    if (pw.length === 0) return { error: 'Enter a password. An empty password is not allowed.' };
    if (enc.encode(salt).length < 8) return { error: 'Salt must be at least 8 bytes. Use Random salt or type 8 or more characters.' };
    if (!Number.isInteger(p) || p < 1 || p > 4) return { error: 'Parallelism must be a whole number from 1 to 4.' };
    if (!Number.isInteger(t) || t < 1 || t > 10) return { error: 'Time cost must be a whole number from 1 to 10.' };
    if (!Number.isInteger(m) || m < 8 * p || m > 65536) {
      return { error: 'Memory cost must be a whole number from ' + (8 * p) + ' to 65536 KiB (at least 8 KiB per lane, at most 64 MiB).' };
    }
    return { pw: pw, salt: salt, m: m, t: t, p: p };
  }

  /* ---------- Argon2id ---------- */
  function libsReady() {
    if (!hw || typeof hw.argon2id !== 'function' || typeof hw.argon2Verify !== 'function') {
      showError('The Argon2id library (js/vendor/hash-wasm.min.js) did not load. Run the page through a local server and check the console.');
      return false;
    }
    return true;
  }
  async function argon2idHash(v) {
    var t0 = performance.now();
    var encoded = await hw.argon2id({
      password: v.pw, salt: enc.encode(v.salt),
      parallelism: v.p, iterations: v.t, memorySize: v.m,
      hashLength: 32, outputType: 'encoded'
    });
    return { encoded: encoded, ms: performance.now() - t0 };
  }
  function parseEncoded(s) {
    var parts = s.split('$');
    if (parts.length !== 6 || parts[1] !== 'argon2id') return null;
    var params = {};
    parts[3].split(',').forEach(function (kv) { var a = kv.split('='); params[a[0]] = a[1]; });
    return { version: parts[2], m: params.m, t: params.t, p: params.p, saltB64: parts[4], hashB64: parts[5] };
  }

  async function onHash() {
    showError('');
    var v = readInputs();
    if (v.error) { showError(v.error); return; }
    if (!libsReady()) return;
    setBusy(true);
    $('a2-out').replaceChildren(el('p', 'Computing Argon2id (' + v.m + ' KiB, t=' + v.t + ', p=' + v.p + ')...'));
    try {
      var r = await argon2idHash(v);
      var f = parseEncoded(r.encoded);
      lastEncoded = r.encoded;
      $('a2-vhash').value = r.encoded;
      var out = $('a2-out');
      out.replaceChildren(
        el('p', 'Argon2id encoded hash:'),
        el('p', r.encoded, 'a2-mono'),
        makeTable(['Field', 'Value'], [
          ['Algorithm', 'argon2id'],
          ['Version', f.version + ' (v=19 means 0x13)'],
          ['Memory cost m', f.m + ' KiB'],
          ['Time cost t', f.t + ' iterations'],
          ['Parallelism p', f.p + ' lane(s)'],
          ['Salt (UTF-8 bytes, base64)', { text: f.saltB64, mono: true }],
          ['Digest (32 bytes, hex)', { text: b64ToHex(f.hashB64), mono: true }],
          ['Measured time (this browser)', fmtMs(r.ms)]
        ])
      );
      obsRows.push([String(obsRows.length + 1), v.m + ' KiB', String(v.t), String(v.p), fmtMs(r.ms), { text: b64ToHex(f.hashB64).slice(0, 16) + '...', mono: true }]);
      if (obsRows.length > 12) obsRows.shift();
      renderObs();
    } catch (e) {
      showError('Hashing failed: ' + (e && e.message ? e.message : e));
    }
    setBusy(false);
  }

  function renderObs() {
    var box = $('a2-obs');
    if (!obsRows.length) { box.replaceChildren(el('p', 'No runs yet.')); return; }
    box.replaceChildren(makeTable(['Run', 'Memory m', 'Time t', 'Parallelism p', 'Measured time', 'Digest (first 8 bytes)'], obsRows));
  }

  async function onVerify() {
    showError('');
    var box = $('a2-verify-out');
    var stored = $('a2-vhash').value.trim();
    var pw = $('a2-vpw').value;
    if (!stored) { showError('Paste or generate an Argon2id hash first.'); return; }
    if (!parseEncoded(stored)) { showError('That is not a valid Argon2id encoded hash. It must look like $argon2id$v=19$m=...,t=...,p=...$salt$hash'); return; }
    if (pw.length === 0) { showError('Enter the password to check.'); return; }
    if (!libsReady()) return;
    setBusy(true);
    try {
      var t0 = performance.now();
      var ok = await hw.argon2Verify({ password: pw, hash: stored });
      var ms = performance.now() - t0;
      var msg = el('p', ok ? 'MATCH: the password produces the stored hash.' : 'NO MATCH: the password does not produce the stored hash.', ok ? 'a2-ok' : 'a2-bad');
      box.replaceChildren(msg, el('p', 'Verification time (measured in this browser): ' + fmtMs(ms), 'a2-hint'));
    } catch (e) {
      showError('Verification failed: the hash string is malformed or unsupported.');
    }
    setBusy(false);
  }

  /* ---------- comparison ---------- */
  async function avgTime(fn, n) {
    var t0 = performance.now();
    var last;
    for (var i = 0; i < n; i++) last = await fn();
    return { value: last, ms: (performance.now() - t0) / n };
  }
  async function webDigest(name, data) { return toHex(await crypto.subtle.digest(name, data)); }

  async function onCompare() {
    showError('');
    var v = readInputs();
    if (v.error) { showError(v.error); return; }
    if (!libsReady()) return;
    if (!window.crypto || !crypto.subtle) { showError('Web Crypto is unavailable. Open the page via http://localhost, not as a file.'); return; }
    setBusy(true);
    $('a2-cmp').replaceChildren(el('p', 'Running comparison...'));
    try {
      var data = enc.encode(v.pw), saltBytes = enc.encode(v.salt), N = 200;
      var rows = [];
      if (window.CryptoJS) {
        var md5 = await avgTime(async function () { return CryptoJS.MD5(v.pw).toString(); }, N);
        rows.push(['MD5', 'Legacy hash; shows the weakest, fastest baseline', '128-bit, ' + md5.value.length + ' hex chars', 'None (unsalted, no cost setting)', fmtMs(md5.ms) + ' (avg of ' + N + ')', 'No: broken and very fast', md5.value]);
      } else {
        rows.push(['MD5', 'Legacy hash', 'unavailable', 'CryptoJS did not load', '-', 'No', '-']);
      }
      var sha1 = await avgTime(function () { return webDigest('SHA-1', data); }, N);
      rows.push(['SHA-1', 'Older hash; collisions demonstrated', '160-bit, ' + sha1.value.length + ' hex chars', 'None (unsalted, no cost setting)', fmtMs(sha1.ms) + ' (avg of ' + N + ')', 'No: broken and very fast', sha1.value]);
      var sha256 = await avgTime(function () { return webDigest('SHA-256', data); }, N);
      rows.push(['SHA-256', 'Secure general hash; still designed to be fast', '256-bit, ' + sha256.value.length + ' hex chars', 'None (unsalted, no cost setting)', fmtMs(sha256.ms) + ' (avg of ' + N + ')', 'Not on its own: too fast', sha256.value]);

      var ITER = 600000;
      var t0 = performance.now();
      var key = await crypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits']);
      var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: ITER }, key, 256);
      var pbMs = performance.now() - t0;
      var pbHex = toHex(bits);
      rows.push(['PBKDF2-SHA256', 'Standard iterated hash; CPU cost only, no memory cost', '256-bit, ' + pbHex.length + ' hex chars', 'Salt + ' + ITER + ' iterations (no memory cost)', fmtMs(pbMs) + ' (1 run)', 'Acceptable, but not memory-hard', pbHex]);

      var a = await argon2idHash(v);
      rows.push(['Argon2id', 'Memory-hard password hash under test', 'Encoded string (32-byte digest)', 'Salt + m=' + v.m + ' KiB, t=' + v.t + ', p=' + v.p, fmtMs(a.ms) + ' (1 run)', 'Yes: recommended', a.encoded]);

      $('a2-cmp').replaceChildren(
        makeTable(['Algorithm', 'Why included', 'Output', 'Cost parameters', 'Measured time', 'Suitable for passwords?', 'Output value'],
          rows.map(function (r) { r[6] = { text: r[6], mono: true }; return r; })),
        el('p', 'Times are measured in your browser on this run and vary between devices and runs. Fast hashes are averaged over ' + N + ' runs because one run is too short to time. Argon2id memory use is the configured m value, not a measured figure: browsers do not report per-call memory.', 'a2-hint')
      );
    } catch (e) {
      showError('Comparison failed: ' + (e && e.message ? e.message : e));
    }
    setBusy(false);
  }

  /* ---------- quiz ---------- */
  var QUIZ = [
    { q: 'Why is SHA-256 alone a poor choice for storing passwords?', o: ['It produces a hash that is too short to store', 'It is very fast, so attackers can test guesses quickly', 'It can be decrypted with a key', 'It cannot take a salt'], a: 1, why: 'Speed is the problem: fast hashes let an attacker try enormous numbers of guesses per second.' },
    { q: 'What is the purpose of a salt?', o: ['To encrypt the password', 'To make the hash shorter', 'To make identical passwords produce different hashes', 'To keep the hash secret'], a: 2, why: 'A unique random salt defeats precomputed tables and hides repeated passwords. It is stored openly with the hash.' },
    { q: 'In Argon2id, what does the memory cost parameter control?', o: ['How many bytes the salt has', 'How much memory is filled and used per hash', 'How many characters the password may have', 'The number of users supported'], a: 1, why: 'Memory cost m (in KiB) sets the size of the memory block, which makes large-scale parallel cracking expensive.' },
    { q: 'What does the time cost (iterations) parameter change?', o: ['The number of passes over the memory', 'The version of Argon2', 'The length of the password', 'The character set of the salt'], a: 0, why: 'Time cost t is the number of passes; more passes means more work for every guess.' },
    { q: 'Argon2id is best described as:', o: ['A reversible cipher', 'A hybrid of Argon2i and Argon2d', 'A public-key signature scheme', 'A checksum for files'], a: 1, why: 'Argon2id starts with data-independent access (like Argon2i) and continues with data-dependent access (like Argon2d).' },
    { q: 'How does Argon2id verify a password at login?', o: ['It decrypts the stored hash', 'It sends the password to the server unhashed', 'It re-hashes the entered password with the stored salt and parameters and compares', 'It compares the password length'], a: 2, why: 'Parameters and salt are read from the encoded string, the entered password is hashed, and the digests are compared.' }
  ];

  function renderQuiz() {
    var box = $('a2-quiz');
    box.replaceChildren();
    QUIZ.forEach(function (item, i) {
      var fs = el('fieldset'), lg = el('legend', (i + 1) + '. ' + item.q);
      fs.appendChild(lg);
      item.o.forEach(function (opt, j) {
        var id = 'a2-q' + i + '-' + j, lab = el('label');
        lab.setAttribute('for', id);
        var r = document.createElement('input');
        r.type = 'radio'; r.name = 'a2-q' + i; r.id = id; r.value = String(j);
        lab.appendChild(r); lab.appendChild(document.createTextNode(opt));
        fs.appendChild(lab);
      });
      fs.appendChild(el('p', '', 'a2-hint'));
      fs.lastChild.id = 'a2-fb' + i;
      box.appendChild(fs);
    });
    $('a2-qresult').textContent = '';
  }
  function submitQuiz() {
    var score = 0, unanswered = 0;
    QUIZ.forEach(function (item, i) {
      var sel = document.querySelector('input[name="a2-q' + i + '"]:checked');
      var fb = $('a2-fb' + i);
      if (!sel) { unanswered++; fb.textContent = 'Not answered.'; fb.className = 'a2-hint a2-bad'; return; }
      if (Number(sel.value) === item.a) { score++; fb.textContent = 'Correct. ' + item.why; fb.className = 'a2-hint a2-ok'; }
      else { fb.textContent = 'Incorrect. Correct answer: ' + item.o[item.a] + '. ' + item.why; fb.className = 'a2-hint a2-bad'; }
    });
    var msg = 'Score: ' + score + ' / ' + QUIZ.length + '.';
    if (unanswered) msg += ' ' + unanswered + ' question(s) unanswered.';
    else if (score === QUIZ.length) msg += ' Excellent work.';
    else msg += ' Review the Theory tab and try again.';
    $('a2-qresult').textContent = msg;
  }

  /* ---------- wiring ---------- */
  function randomSalt() {
    var b = crypto.getRandomValues(new Uint8Array(16));
    $('a2-salt').value = toHex(b);
  }
  document.addEventListener('DOMContentLoaded', function () {
    if (!hw) showError('The Argon2id library (js/vendor/hash-wasm.min.js) did not load. Run the page through a local server and check the console.');
    $('a2-hash').addEventListener('click', onHash);
    $('a2-compare').addEventListener('click', onCompare);
    $('a2-verify').addEventListener('click', onVerify);
    $('a2-rand').addEventListener('click', randomSalt);
    $('a2-show').addEventListener('change', function (e) {
      $('a2-pw').type = e.target.checked ? 'text' : 'password';
    });
    $('a2-pw').addEventListener('keydown', function (e) { if (e.key === 'Enter') onHash(); });
    $('a2-clear').addEventListener('click', function () { obsRows = []; renderObs(); });
    $('a2-qsubmit').addEventListener('click', submitQuiz);
    $('a2-qreset').addEventListener('click', renderQuiz);
    renderObs();
    renderQuiz();
  });
})();