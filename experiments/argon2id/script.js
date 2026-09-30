/* Attack Lab add-on for the Argon2id experiment.
   Load AFTER script.js:  <script src="attack-lab.js"></script>
   Uses hash-wasm (Argon2id) and Web Crypto (SHA-256). Injects its own UI into the Simulation tab. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var enc = new TextEncoder();
  var hw = window.hashwasm || window.hashWasm;

  var USERS = [
    ['alice', 'iloveyou'], ['dave', 'iloveyou'], ['bob', 'monkey123'],
    ['carol', 'correct horse battery staple']
  ];
  var WORDLIST = ['123456', 'password', 'qwerty', 'letmein', 'iloveyou', 'dragon', 'monkey123', 'cricket2020', 'welcome1', 'sunshine'];

  function el(tag, text, cls) {
    var e = document.createElement(tag);
    if (text !== undefined) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }
  function hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  async function sha256(s) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(s))); }
  function rnd() { return hex(crypto.getRandomValues(new Uint8Array(8))); }
  function fmtTime(sec) {
    if (sec < 1) return (sec * 1000).toFixed(1) + ' ms';
    var u = [['years', 31557600], ['days', 86400], ['hours', 3600], ['minutes', 60], ['seconds', 1]];
    for (var i = 0; i < u.length; i++) if (sec >= u[i][1]) return (sec / u[i][1]).toLocaleString(undefined, { maximumFractionDigits: 1 }) + ' ' + u[i][0];
    return sec.toFixed(1) + ' s';
  }
  function params() {
    var m = Math.min(65536, Math.max(8, Number($('a2-mem').value) || 19456));
    var t = Math.min(10, Math.max(1, Number($('a2-iter').value) || 2));
    var p = Math.min(4, Math.max(1, Number($('a2-par').value) || 1));
    return { m: Math.max(m, 8 * p), t: t, p: p };
  }
  function table(headers, rows) {
    var t = el('table', undefined, 'a2-table'), tr = el('tr');
    headers.forEach(function (h) { tr.appendChild(el('th', h)); });
    t.appendChild(tr);
    rows.forEach(function (r) {
      var row = el('tr');
      r.forEach(function (c) { row.appendChild(el('td', c.text !== undefined ? c.text : c, c.cls || '')); });
      t.appendChild(row);
    });
    var w = el('div', undefined, 'a2-table-wrap'); w.appendChild(t); return w;
  }

  var state = { shaRate: 0, argRate: 0 };

  async function launch() {
    var out = $('atk-out'), btn = $('atk-go');
    if (!hw || !hw.argon2id) { out.replaceChildren(el('p', 'Argon2id library not loaded.', 'a2-err')); return; }
    btn.disabled = true;
    var P = params(), log = el('p', '', 'a2-hint'), box = el('div');
    out.replaceChildren(box);
    function say(s) { log.textContent = s; }
    box.appendChild(log);

    /* Stolen database A: unsalted SHA-256 */
    var shaDb = [];
    for (var i = 0; i < USERS.length; i++) shaDb.push({ u: USERS[i][0], h: await sha256(USERS[i][1]) });
    /* Stolen database B: salted Argon2id with the parameters currently set above */
    say('Creating the stolen Argon2id database (' + USERS.length + ' users, m=' + P.m + ', t=' + P.t + ', p=' + P.p + ')...');
    var argDb = [];
    for (i = 0; i < USERS.length; i++) {
      var salt = rnd();
      argDb.push({ u: USERS[i][0], salt: salt, h: await hw.argon2id({ password: USERS[i][1], salt: enc.encode(salt), parallelism: P.p, iterations: P.t, memorySize: P.m, hashLength: 32, outputType: 'hex' }) });
    }

    /* Attack A: SHA-256. One hash per guess is compared against EVERY user. */
    say('Attacking the SHA-256 database...');
    var shaCracked = {}, shaCount = 0, t0 = performance.now();
    for (var w = 0; w < WORDLIST.length; w++) {
      var gh = await sha256(WORDLIST[w]); shaCount++;
      shaDb.forEach(function (r) { if (r.h === gh && !shaCracked[r.u]) shaCracked[r.u] = WORDLIST[w]; });
    }
    for (var k = 0; k < 2000; k++) await sha256('guess' + k);   /* enough runs to time it */
    var shaMs = performance.now() - t0;
    state.shaRate = (shaCount + 2000) / (shaMs / 1000);

    /* Attack B: Argon2id. Every guess must be re-hashed with EACH user's own salt. */
    var argCracked = {}, argCount = 0, t1 = performance.now();
    for (var u = 0; u < argDb.length; u++) {
      for (w = 0; w < WORDLIST.length; w++) {
        say('Argon2id attack: user ' + argDb[u].u + ', guess ' + (w + 1) + '/' + WORDLIST.length + ' (total hashes so far: ' + argCount + ')');
        var g = await hw.argon2id({ password: WORDLIST[w], salt: enc.encode(argDb[u].salt), parallelism: P.p, iterations: P.t, memorySize: P.m, hashLength: 32, outputType: 'hex' });
        argCount++;
        if (g === argDb[u].h) { argCracked[argDb[u].u] = WORDLIST[w]; break; }
      }
    }
    var argMs = performance.now() - t1;
    state.argRate = argCount / (argMs / 1000);
    say('');

    var rows = USERS.map(function (x, n) {
      var s = shaCracked[x[0]], a = argCracked[x[0]];
      return [x[0], { text: shaDb[n].h.slice(0, 12) + '...', cls: 'a2-mono' }, { text: s ? 'CRACKED: ' + s : 'safe', cls: s ? 'a2-bad' : 'a2-ok' },
        { text: argDb[n].salt.slice(0, 6) + '.. / ' + argDb[n].h.slice(0, 8) + '..', cls: 'a2-mono' }, { text: a ? 'CRACKED: ' + a : 'safe (not in wordlist)', cls: a ? 'a2-bad' : 'a2-ok' }];
    });
    var sameSha = shaDb[0].h === shaDb[1].h, sameArg = argDb[0].h === argDb[1].h;
    box.replaceChildren(
      table(['User', 'SHA-256 hash (unsalted)', 'Attack on SHA-256', 'Argon2id salt / hash', 'Attack on Argon2id'], rows),
      el('p', 'Look at alice and dave: same password. SHA-256 hashes identical? ' + (sameSha ? 'YES, so the attacker sees they share a password.' : 'no') + '  Argon2id hashes identical? ' + (sameArg ? 'yes' : 'NO, each salt makes them different, so each user must be attacked separately.'), 'a2-hint'),
      table(['', 'SHA-256', 'Argon2id (your m, t, p)'], [
        ['Hashes computed', String(shaCount + 2000), String(argCount)],
        ['Time taken', shaMs.toFixed(0) + ' ms', argMs.toFixed(0) + ' ms'],
        ['Guesses per second (this browser)', Math.round(state.shaRate).toLocaleString(), state.argRate.toFixed(1)],
        [{ text: 'Time to try 1 billion guesses on this browser', cls: '' }, fmtTime(1e9 / state.shaRate), fmtTime(1e9 / state.argRate)]
      ]),
      el('p', 'SHA-256 is about ' + Math.round(state.shaRate / state.argRate).toLocaleString() + 'x faster for the attacker. Carol survives only because her long passphrase is not in any wordlist: a slow hash slows the attacker, but strong passwords are still needed.', 'a2-ok')
    );
    btn.disabled = false;
    gpu();
  }

  /* GPU calculator: why memory, not just time, protects passwords */
  function gpu() {
    var ram = Math.max(1, Number($('atk-ram').value) || 24), cores = Math.max(1, Number($('atk-cores').value) || 10000);
    var P = params(), inst = Math.max(1, Math.min(cores, Math.floor(ram * 1048576 / P.m)));
    var box = $('atk-gpu'), perSec = state.argRate || 0;
    var rows = [
      ['SHA-256 needs about', 'a few bytes per guess', 'all ' + cores.toLocaleString() + ' cores busy'],
      ['Argon2id needs', P.m.toLocaleString() + ' KiB (' + (P.m / 1024).toFixed(1) + ' MiB) per guess', ram + ' GiB of RAM fits only ' + Math.floor(ram * 1048576 / P.m).toLocaleString() + ' guesses at once'],
      ['Usable parallel guesses', cores.toLocaleString(), inst.toLocaleString() + (inst < cores ? ' (' + Math.round((1 - inst / cores) * 100) + '% of the cores sit idle, waiting for memory)' : '')]
    ];
    var kids = [table(['', 'Per guess', 'On this GPU'], rows)];
    if (perSec) kids.push(el('p', 'Rough estimate: if each of those ' + inst.toLocaleString() + ' lanes ran at this browser\'s Argon2id speed, 1 billion guesses would take about ' + fmtTime(1e9 / (perSec * inst)) + '. Real GPUs differ; this is an illustration built from your measured speed and the numbers you typed.', 'a2-hint'));
    else kids.push(el('p', 'Run the attack once to add a time estimate.', 'a2-hint'));
    box.replaceChildren.apply(box, kids);
  }

  function build() {
    var host = document.querySelector('#simulation .simulation-output') || $('simulation');
    if (!host) return;
    var s = el('div');
    s.id = 'atk-lab';
    var h1 = el('h2', 'Attack lab: steal the database and try to crack it'); h1.style.marginTop = '24px';
    var go = el('button', 'Launch dictionary attack'); go.id = 'atk-go'; go.type = 'button';
    var out = el('div'); out.id = 'atk-out';
    out.appendChild(el('p', 'Click Launch to play the attacker.', 'a2-hint'));
    var h2 = el('h2', 'Why memory matters: the GPU calculator'); h2.style.marginTop = '24px';
    var ctl = el('div', undefined, 'a2-row');
    ctl.innerHTML = '<div><label for="atk-ram">GPU memory (GiB)</label><input id="atk-ram" type="number" min="1" max="200" value="24"></div>' +
                    '<div><label for="atk-cores">GPU cores</label><input id="atk-cores" type="number" min="1" max="100000" value="10000"></div>';
    var g = el('div'); g.id = 'atk-gpu';
    s.appendChild(h1);
    s.appendChild(el('p', 'You are the attacker. Four users\' password hashes have leaked. You have a tiny wordlist of ' + WORDLIST.length + ' common passwords. The lab stores the same four passwords twice: once as plain unsalted SHA-256, once as salted Argon2id with the m, t, p you set above (change them and relaunch to see the effect). Then it really runs the attack in your browser.', 'a2-hint'));
    s.appendChild(go); s.appendChild(out); s.appendChild(h2);
    s.appendChild(el('p', 'Each Argon2id guess needs m KiB of RAM. A GPU has thousands of cores but a fixed amount of memory, so memory, not core count, limits how many guesses it can run at once. Change m above or the GPU specs here and watch the numbers change. The GPU figures are illustrative assumptions, not benchmarks.', 'a2-hint'));
    s.appendChild(ctl); s.appendChild(g);
    host.appendChild(s);
    go.addEventListener('click', launch);
    ['atk-ram', 'atk-cores', 'a2-mem', 'a2-iter', 'a2-par'].forEach(function (id) { $(id).addEventListener('input', gpu); });
    gpu();
  }
  document.addEventListener('DOMContentLoaded', build);
  if (document.readyState !== 'loading') build();
})();