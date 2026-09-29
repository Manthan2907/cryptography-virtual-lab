(function () {
  const $ = (id) => document.getElementById(id);
  const DEFAULTS = { mem: 16384, it: 3, par: 1 };
  let last = null;

  const titleEl = $("exp-title");
  const descEl = $("exp-description");
  if (titleEl) titleEl.textContent = "Argon2id Password Hashing";
  if (descEl) descEl.textContent = "Hash passwords with Argon2id and compare it with MD5, SHA-1, SHA-256, PBKDF2 and bcrypt.";
  document.title = "Argon2id | Virtual Cryptography Laboratory";

  function tick() {
    return new Promise((r) => setTimeout(r, 30));
  }

  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  function toHex(arr) {
    return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function randomSalt(n) {
    const s = new Uint8Array(n);
    crypto.getRandomValues(s);
    return s;
  }

  function human(sec) {
    if (sec < 1) return "under 1 second";
    if (sec < 60) return sec.toFixed(1) + " seconds";
    if (sec < 3600) return (sec / 60).toFixed(1) + " minutes";
    if (sec < 86400) return (sec / 3600).toFixed(1) + " hours";
    if (sec < 31536000) return (sec / 86400).toFixed(1) + " days";
    return (sec / 31536000).toFixed(1) + " years";
  }

  function avgTime(fn, n) {
    const t0 = performance.now();
    for (let i = 0; i < n; i++) fn();
    return (performance.now() - t0) / n;
  }

  function params() {
    return {
      memorySize: +$("a2-mem").value,
      iterations: +$("a2-it").value,
      parallelism: +$("a2-par").value
    };
  }

  function setStatus(msg) {
    $("a2-status").textContent = msg;
  }

  function libsReady() {
    if (typeof hashwasm === "undefined" || typeof CryptoJS === "undefined" || typeof dcodeIO === "undefined") {
      setStatus("A required library did not load. Run the portal with: python3 -m http.server 8000");
      return false;
    }
    return true;
  }

  function bindSlider(id, labelId) {
    $(id).addEventListener("input", () => {
      $(labelId).textContent = $(id).value;
    });
  }

  bindSlider("a2-mem", "a2-mem-val");
  bindSlider("a2-it", "a2-it-val");
  bindSlider("a2-par", "a2-par-val");

  async function runArgon() {
    if (!libsReady()) return;
    const pw = $("a2-pw").value;
    if (!pw) {
      setStatus("Enter a password first.");
      return;
    }
    const p = params();
    const salt = randomSalt(16);
    setStatus("Hashing with Argon2id...");
    $("a2-verify").textContent = "";
    await tick();
    try {
      const t0 = performance.now();
      const encoded = await hashwasm.argon2id({
        password: pw,
        salt: salt,
        iterations: p.iterations,
        memorySize: p.memorySize,
        parallelism: p.parallelism,
        hashLength: 32,
        outputType: "encoded"
      });
      const ms = performance.now() - t0;
      last = { encoded: encoded, ms: ms, p: p };
      $("a2-hash").textContent = encoded;
      $("a2-meta").textContent =
        "Time: " + ms.toFixed(1) + " ms | Memory: " + p.memorySize + " KB | Iterations: " + p.iterations +
        " | Parallelism: " + p.parallelism + " | Salt: " + toHex(salt) + " | Digest: 256 bits";
      setStatus("Argon2id hash generated. The encoded string holds the parameters, salt and digest.");
    } catch (e) {
      setStatus("Error: " + e.message);
    }
  }

  async function runVerify() {
    if (!libsReady()) return;
    if (!last) {
      setStatus("Generate an Argon2id hash first.");
      return;
    }
    const v = $("a2-vpw").value;
    if (!v) {
      setStatus("Type a password to verify.");
      return;
    }
    setStatus("Verifying...");
    await tick();
    try {
      const ok = await hashwasm.argon2Verify({ password: v, hash: last.encoded });
      $("a2-verify").textContent = ok ? "Verification result: MATCH (password is correct)" : "Verification result: NO MATCH (password is wrong)";
      setStatus("Verification complete.");
    } catch (e) {
      setStatus("Error: " + e.message);
    }
  }

  async function runCompare() {
    if (!libsReady()) return;
    const pw = $("a2-pw").value;
    if (!pw) {
      setStatus("Enter a password first.");
      return;
    }
    const p = params();
    setStatus("Comparing algorithms, please wait...");
    $("a2-table").innerHTML = "";
    await tick();
    const rows = [];

    rows.push({ n: "MD5", o: CryptoJS.MD5(pw).toString(), ms: avgTime(() => CryptoJS.MD5(pw).toString(), 2000), m: "None", ok: "No (broken, too fast)" });
    rows.push({ n: "SHA-1", o: CryptoJS.SHA1(pw).toString(), ms: avgTime(() => CryptoJS.SHA1(pw).toString(), 2000), m: "None", ok: "No (too fast)" });
    rows.push({ n: "SHA-256", o: CryptoJS.SHA256(pw).toString(), ms: avgTime(() => CryptoJS.SHA256(pw).toString(), 2000), m: "None", ok: "No (too fast)" });

    await tick();
    let t0 = performance.now();
    const pb = CryptoJS.PBKDF2(pw, CryptoJS.lib.WordArray.random(16), { keySize: 8, iterations: 100000, hasher: CryptoJS.algo.SHA256 }).toString();
    rows.push({ n: "PBKDF2-SHA256 (100000 iterations)", o: pb, ms: performance.now() - t0, m: "Very low", ok: "Acceptable" });

    await tick();
    t0 = performance.now();
    const bsalt = dcodeIO.bcrypt.genSaltSync(10);
    const bh = dcodeIO.bcrypt.hashSync(pw, bsalt);
    rows.push({ n: "bcrypt (cost 10)", o: bh, ms: performance.now() - t0, m: "About 4 KB", ok: "Good" });

    await tick();
    try {
      t0 = performance.now();
      const ah = await hashwasm.argon2id({
        password: pw,
        salt: randomSalt(16),
        iterations: p.iterations,
        memorySize: p.memorySize,
        parallelism: p.parallelism,
        hashLength: 32,
        outputType: "hex"
      });
      rows.push({ n: "Argon2id (m=" + p.memorySize + " KB, t=" + p.iterations + ", p=" + p.parallelism + ")", o: ah, ms: performance.now() - t0, m: (p.memorySize / 1024).toFixed(0) + " MB", ok: "Best" });
    } catch (e) {
      setStatus("Error: " + e.message);
      return;
    }

    let html = "<table><thead><tr><th>Algorithm</th><th>Output (first 32 chars)</th><th>Time per hash (ms)</th><th>Guesses per second</th><th>Time for 1 billion guesses</th><th>Memory used</th><th>Suitable for passwords</th></tr></thead><tbody>";
    rows.forEach((r) => {
      const ms = Math.max(r.ms, 0.0001);
      const gps = 1000 / ms;
      const secForBillion = 1e9 / gps;
      const shown = r.o.length > 32 ? r.o.slice(0, 32) + "..." : r.o;
      html += "<tr><td>" + esc(r.n) + "</td><td>" + esc(shown) + "</td><td>" + r.ms.toFixed(r.ms < 1 ? 4 : 1) + "</td><td>" +
        Math.round(gps).toLocaleString() + "</td><td>" + human(secForBillion) + "</td><td>" + esc(r.m) + "</td><td>" + esc(r.ok) + "</td></tr>";
    });
    html += "</tbody></table><p>Times are measured in this browser on one thread. MD5, SHA-1 and SHA-256 are averaged over 2000 runs.</p>";
    $("a2-table").innerHTML = html;
    setStatus("Comparison complete.");
  }

  function resetAll() {
    $("a2-pw").value = "correct horse battery staple";
    $("a2-mem").value = DEFAULTS.mem;
    $("a2-it").value = DEFAULTS.it;
    $("a2-par").value = DEFAULTS.par;
    $("a2-mem-val").textContent = DEFAULTS.mem;
    $("a2-it-val").textContent = DEFAULTS.it;
    $("a2-par-val").textContent = DEFAULTS.par;
    $("a2-vpw").value = "";
    $("a2-hash").textContent = "";
    $("a2-meta").textContent = "";
    $("a2-verify").textContent = "";
    $("a2-table").innerHTML = "";
    setStatus("Results will appear here after the simulation runs.");
    last = null;
  }

  $("a2-hash-btn").addEventListener("click", runArgon);
  $("a2-verify-btn").addEventListener("click", runVerify);
  $("a2-compare-btn").addEventListener("click", runCompare);
  $("a2-reset-btn").addEventListener("click", resetAll);

  const QUIZ = [
    {
      q: "Which Argon2 variant is recommended for password hashing?",
      o: ["Argon2d", "Argon2i", "Argon2id", "Argon2x"],
      a: 2,
      e: "Argon2id combines Argon2i (side-channel resistance) with Argon2d (GPU resistance)."
    },
    {
      q: "Why is Argon2id hard to attack with GPUs?",
      o: ["It uses a very long password", "It needs a large amount of memory per guess", "It has no salt", "It outputs a shorter hash"],
      a: 1,
      e: "It is memory-hard, so each guess needs a lot of RAM and GPUs cannot run many guesses in parallel."
    },
    {
      q: "What does a salt do?",
      o: ["Makes the hash reversible", "Speeds up hashing", "Makes the same password give different hashes", "Encrypts the password"],
      a: 2,
      e: "A random salt makes every hash unique and defeats rainbow tables."
    },
    {
      q: "Which Argon2id parameter sets the RAM used?",
      o: ["Memory size (m)", "Iterations (t)", "Parallelism (p)", "Hash length"],
      a: 0,
      e: "Memory size m is the RAM in KB. Iterations t is the number of passes and p is the number of lanes."
    },
    {
      q: "Why is plain SHA-256 a poor choice for storing passwords?",
      o: ["Its output is too long", "It is too fast, so guesses are cheap", "It cannot be computed in a browser", "It always needs a key"],
      a: 1,
      e: "SHA-256 is designed for speed, so attackers can test billions of guesses per second."
    }
  ];

  function renderQuiz() {
    let html = "";
    QUIZ.forEach((item, i) => {
      html += "<fieldset id=\"a2-q" + i + "\"><legend>" + (i + 1) + ". " + esc(item.q) + "</legend>";
      item.o.forEach((opt, j) => {
        html += "<div><label><input type=\"radio\" name=\"a2-q" + i + "\" value=\"" + j + "\"> " + esc(opt) + "</label></div>";
      });
      html += "<p id=\"a2-fb" + i + "\"></p></fieldset>";
    });
    $("a2-quiz").innerHTML = html;
    $("a2-quiz-result").textContent = "";
  }

  function submitQuiz() {
    let score = 0;
    let answered = 0;
    QUIZ.forEach((item, i) => {
      const chosen = document.querySelector("input[name=\"a2-q" + i + "\"]:checked");
      const fb = $("a2-fb" + i);
      if (!chosen) {
        fb.textContent = "Not answered. " + item.e;
        return;
      }
      answered++;
      if (+chosen.value === item.a) {
        score++;
        fb.textContent = "Correct. " + item.e;
      } else {
        fb.textContent = "Incorrect. " + item.e;
      }
    });
    $("a2-quiz-result").textContent = "Score: " + score + " / " + QUIZ.length + " (" + answered + " answered)";
  }

  $("a2-quiz-submit").addEventListener("click", submitQuiz);
  $("a2-quiz-reset").addEventListener("click", renderQuiz);
  renderQuiz();
})();