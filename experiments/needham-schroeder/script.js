/**
 * Needham-Schroeder Symmetric Key Protocol Simulation
 * Uses Web Crypto API for AES-GCM simulation.
 */

const AppState = {
  kas: null, kbs: null, kab: null,
  aliceNa: null, bobNb: null,
  ticket: null,
  currentStep: 0,
  scenario: 'normal',
  autoPlayTimer: null
};

// --- Crypto Helpers ---

// Derives a 256-bit AES-GCM key from a short string (for simulation purposes)
async function deriveKey(passphrase) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits", "deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("fixed-salt-for-sim"), iterations: 1000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
}

// Generate a random AES-GCM key (for Kab)
async function generateSessionKey() {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
}

// Export key to hex for display
async function exportKeyHex(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return buf2hex(raw).substring(0, 16) + "...";
}

// AES-GCM Encrypt
async function encrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv }, key, enc.encode(plaintext)
  );
  // Return concat of iv and ciphertext in hex
  return buf2hex(iv.buffer) + buf2hex(ciphertext);
}

// AES-GCM Decrypt
async function decrypt(key, hexStr) {
  try {
    const iv = hex2buf(hexStr.substring(0, 24));
    const ciphertext = hex2buf(hexStr.substring(24));
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv }, key, ciphertext
    );
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    return null; // Decryption failed
  }
}

// Utilities
function buf2hex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}
function hex2buf(hexString) {
  const bytes = new Uint8Array(Math.ceil(hexString.length / 2));
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
  return bytes;
}
function generateNonce() {
  return Math.floor(Math.random() * 1000000).toString();
}

// --- UI & Simulation Engine ---

async function initSimulation() {
  AppState.kas = await deriveKey("AliceSecretKey123");
  AppState.kbs = await deriveKey("BobSecretKey456");
  
  document.getElementById('alice-kas').innerText = await exportKeyHex(AppState.kas);
  document.getElementById('kdc-kas').innerText = await exportKeyHex(AppState.kas);
  document.getElementById('bob-kbs').innerText = await exportKeyHex(AppState.kbs);
  document.getElementById('kdc-kbs').innerText = await exportKeyHex(AppState.kbs);
  
  resetSimulation();
}

function resetSimulation() {
  AppState.currentStep = 0;
  AppState.aliceNa = null;
  AppState.bobNb = null;
  AppState.kab = null;
  AppState.ticket = null;
  AppState.scenario = document.getElementById('scenario-select').value;
  
  clearTimeout(AppState.autoPlayTimer);
  
  document.getElementById('alice-na').innerHTML = '<span class="text-muted">Waiting...</span>';
  document.getElementById('alice-kab').innerHTML = '<span class="text-muted">Unknown</span>';
  document.getElementById('alice-ticket').innerHTML = '<span class="text-muted">None</span>';
  document.getElementById('kdc-kab').innerHTML = '<span class="text-muted">Waiting...</span>';
  document.getElementById('bob-nb').innerHTML = '<span class="text-muted">Waiting...</span>';
  document.getElementById('bob-kab').innerHTML = '<span class="text-muted">Unknown</span>';
  
  document.getElementById('log-tbody').innerHTML = '';
  document.getElementById('res-scenario').innerText = AppState.scenario;
  document.getElementById('res-expected').innerText = getExpectedResult(AppState.scenario);
  document.getElementById('res-actual').innerText = '-';
  document.getElementById('res-key').innerText = '-';
  document.getElementById('res-auth').innerText = '-';
  document.getElementById('btn-next').disabled = false;
  document.getElementById('btn-auto').disabled = false;
}

function getExpectedResult(scenario) {
  switch(scenario) {
    case 'normal': return "Mutual auth, key established.";
    case 'wrong_kas': return "Alice fails to decrypt msg 2.";
    case 'tampered_ticket': return "Bob fails to decrypt ticket.";
    case 'nonce_mismatch': return "Alice rejects msg 2 (Na mismatch).";
    case 'wrong_nb1': return "Bob rejects msg 5 (Nb-1 wrong).";
    case 'replay_attack': return "Bob accepts old ticket (auth bypassed).";
    case 'replay_timestamp': return "Bob rejects stale ticket.";
    default: return "-";
  }
}

async function runNextStep() {
  AppState.currentStep++;
  const s = AppState.currentStep;
  
  try {
    if (s === 1) await step1();
    else if (s === 2) await step2();
    else if (s === 3) await step3();
    else if (s === 4) await step4();
    else if (s === 5) await step5();
    else {
      AppState.currentStep = 5;
      return;
    }
  } catch (err) {
    console.error("Step error", err);
    logMessage(s, "Error", "Error", "Error", "Execution halted", false);
    document.getElementById('btn-next').disabled = true;
  }
  
  if (AppState.currentStep >= 5 || document.getElementById('btn-next').disabled) {
    document.getElementById('btn-next').disabled = true;
    document.getElementById('btn-auto').disabled = true;
    updateResults();
  }
}

async function step1() {
  AppState.aliceNa = generateNonce();
  document.getElementById('alice-na').innerText = AppState.aliceNa;
  animateArrow('panel-alice', 'panel-kdc', 'A, B, Na');
  logMessage(1, "A &rarr; S", `A, B, ${AppState.aliceNa}`, "(Plaintext)", "OK");
}

async function step2() {
  // KDC generates Kab
  AppState.kab = await generateSessionKey();
  const kabHex = await exportKeyHex(AppState.kab);
  document.getElementById('kdc-kab').innerText = kabHex;
  
  let ticketPlain = JSON.stringify({ key: kabHex, id: "A", timestamp: Date.now() });
  
  if (AppState.scenario === 'replay_attack' || AppState.scenario === 'replay_timestamp') {
    // Simulate an old ticket
    ticketPlain = JSON.stringify({ key: "OLD_COMPROMISED_KEY", id: "A", timestamp: Date.now() - 10000000 });
  }
  
  let ticket = await encrypt(AppState.kbs, ticketPlain);
  if (AppState.scenario === 'tampered_ticket') {
    ticket = ticket.substring(0, ticket.length - 4) + "0000"; // Corrupt the tag
  }
  
  let naToUse = AppState.aliceNa;
  if (AppState.scenario === 'nonce_mismatch') naToUse = "999999";
  
  let msg2Plain = JSON.stringify({ Na: naToUse, id: "B", key: kabHex, ticket: ticket });
  let kToUse = AppState.kas;
  
  if (AppState.scenario === 'wrong_kas') {
    kToUse = await deriveKey("WrongKey");
  }
  
  const msg2Cipher = await encrypt(kToUse, msg2Plain);
  
  animateArrow('panel-kdc', 'panel-alice', 'Msg 2');
  
  // Alice processes
  const decrypted = await decrypt(AppState.kas, msg2Cipher);
  if (!decrypted) {
    logMessage(2, "S &rarr; A", "(Unknown)", msg2Cipher, "FAIL: Decryption failed", false);
    document.getElementById('btn-next').disabled = true;
    return;
  }
  
  const parsed = JSON.parse(decrypted);
  if (parsed.Na !== AppState.aliceNa) {
    logMessage(2, "S &rarr; A", decrypted, msg2Cipher, "FAIL: Na mismatch", false);
    document.getElementById('btn-next').disabled = true;
    return;
  }
  
  AppState.ticket = parsed.ticket;
  
  if (AppState.scenario === 'replay_attack' || AppState.scenario === 'replay_timestamp') {
     // Attacker sets up old Kab
     document.getElementById('alice-kab').innerHTML = "OLD_COMPROMISED_KEY (Attacker)";
  } else {
     document.getElementById('alice-kab').innerText = parsed.key;
  }
  
  document.getElementById('alice-ticket').innerText = AppState.ticket.substring(0,16)+"...";
  logMessage(2, "S &rarr; A", decrypted, msg2Cipher, "OK: Na matched");
}

async function step3() {
  animateArrow('panel-alice', 'panel-bob', 'Ticket');
  
  // Bob processes
  const decrypted = await decrypt(AppState.kbs, AppState.ticket);
  if (!decrypted) {
    logMessage(3, "A &rarr; B", "(Unknown)", AppState.ticket, "FAIL: Ticket decryption failed", false);
    document.getElementById('btn-next').disabled = true;
    return;
  }
  
  const parsed = JSON.parse(decrypted);
  
  if (AppState.scenario === 'replay_timestamp') {
    const age = Date.now() - parsed.timestamp;
    if (age > 50000) { // Reject if too old
      logMessage(3, "A &rarr; B", decrypted, AppState.ticket, "FAIL: Ticket stale (Timestamp rejected)", false);
      document.getElementById('btn-next').disabled = true;
      return;
    }
  }
  
  document.getElementById('bob-kab').innerText = parsed.key;
  logMessage(3, "A &rarr; B", decrypted, AppState.ticket, "OK: Ticket decrypted");
}

async function step4() {
  AppState.bobNb = generateNonce();
  document.getElementById('bob-nb').innerText = AppState.bobNb;
  
  // Need the actual crypto key obj for Kab for Bob
  // Since Kab is passed as hex in sim, we just derive a sim key from it to make Web Crypto work
  const kabHex = document.getElementById('bob-kab').innerText;
  const simKab = await deriveKey(kabHex);
  
  const msg4Plain = JSON.stringify({ Nb: AppState.bobNb });
  const msg4Cipher = await encrypt(simKab, msg4Plain);
  
  animateArrow('panel-bob', 'panel-alice', '{Nb}Kab');
  
  // Alice processes
  const aliceKabHex = document.getElementById('alice-kab').innerText;
  const aliceSimKab = await deriveKey(aliceKabHex);
  const decrypted = await decrypt(aliceSimKab, msg4Cipher);
  
  if (!decrypted) {
    logMessage(4, "B &rarr; A", "(Unknown)", msg4Cipher, "FAIL: Decryption failed", false);
    document.getElementById('btn-next').disabled = true;
    return;
  }
  
  logMessage(4, "B &rarr; A", decrypted, msg4Cipher, "OK: Decrypted");
}

async function step5() {
  const aliceKabHex = document.getElementById('alice-kab').innerText;
  const aliceSimKab = await deriveKey(aliceKabHex);
  
  // Normally Alice reads Nb from msg 4. We simplify by reading state.
  let replyNb = parseInt(AppState.bobNb) - 1;
  if (AppState.scenario === 'wrong_nb1') replyNb = parseInt(AppState.bobNb) + 99;
  
  const msg5Plain = JSON.stringify({ Nb_minus_1: replyNb });
  const msg5Cipher = await encrypt(aliceSimKab, msg5Plain);
  
  animateArrow('panel-alice', 'panel-bob', '{Nb-1}Kab');
  
  // Bob processes
  const bobKabHex = document.getElementById('bob-kab').innerText;
  const bobSimKab = await deriveKey(bobKabHex);
  const decrypted = await decrypt(bobSimKab, msg5Cipher);
  
  if (!decrypted) {
    logMessage(5, "A &rarr; B", "(Unknown)", msg5Cipher, "FAIL: Decryption failed", false);
    return;
  }
  
  const parsed = JSON.parse(decrypted);
  if (parsed.Nb_minus_1 !== parseInt(AppState.bobNb) - 1) {
    logMessage(5, "A &rarr; B", decrypted, msg5Cipher, "FAIL: Nb-1 incorrect", false);
    return;
  }
  
  logMessage(5, "A &rarr; B", decrypted, msg5Cipher, "OK: Authenticated");
}

function updateResults() {
  const trs = document.querySelectorAll('#log-tbody tr');
  let auth = 'No';
  let kEst = 'No';
  let actual = 'Failed early';
  
  if (trs.length === 5) {
    const lastMsg = trs[trs.length - 1];
    if (lastMsg.innerText.includes('OK')) {
      auth = 'Yes'; kEst = 'Yes'; actual = 'Protocol completed successfully';
    } else {
      actual = 'Failed at step 5';
    }
  } else {
    actual = `Failed at step ${trs.length}`;
  }
  
  if (AppState.scenario === 'replay_attack' && auth === 'Yes') {
    actual = 'Attacker successfully impersonated Alice (Replay successful)';
  }
  
  document.getElementById('res-actual').innerText = actual;
  document.getElementById('res-key').innerText = kEst;
  document.getElementById('res-auth').innerText = auth;
}

function logMessage(step, senderReceiver, plain, cipher, verif, isOk = true) {
  const tbody = document.getElementById('log-tbody');
  const tr = document.createElement('tr');
  if (!isOk) tr.style.backgroundColor = '#ffebee';
  
  let cipherHtml = cipher;
  if (cipher !== "(Plaintext)") {
    cipherHtml = `<span class="clickable-cipher" data-plain='${plain}' data-cipher='${cipher}' title="Click to view details">${cipher.substring(0,16)}...</span>`;
  }
  
  tr.innerHTML = `
    <td>${step}</td>
    <td>${senderReceiver}</td>
    <td class="mono">${plain}</td>
    <td class="mono">${cipherHtml}</td>
    <td class="${isOk ? 'text-success' : 'text-error'}"><strong>${verif}</strong></td>
  `;
  tbody.appendChild(tr);
  
  const clickable = tr.querySelector('.clickable-cipher');
  if (clickable) {
    clickable.addEventListener('click', (e) => {
      document.getElementById('modal-ciphertext').innerText = e.target.getAttribute('data-cipher');
      document.getElementById('modal-plaintext').innerText = e.target.getAttribute('data-plain');
      document.getElementById('crypto-modal').classList.remove('hidden');
    });
  }
}

function animateArrow(fromId, toId, text) {
  const arrow = document.getElementById('message-arrow');
  const fromEl = document.getElementById(fromId);
  const toEl = document.getElementById(toId);
  const area = document.getElementById('anim-area-kdc'); // reference container
  
  if (!fromEl || !toEl || !area) return;
  
  const fromRect = fromEl.getBoundingClientRect();
  const toRect = toEl.getBoundingClientRect();
  const areaRect = area.getBoundingClientRect();
  
  const startX = fromRect.left + (fromRect.width/2) - areaRect.left;
  const endX = toRect.left + (toRect.width/2) - areaRect.left;
  
  arrow.innerText = text;
  arrow.classList.remove('hidden');
  arrow.classList.remove('left', 'right');
  arrow.style.transition = 'none';
  arrow.style.left = startX + 'px';
  
  if (startX < endX) arrow.classList.add('right');
  else arrow.classList.add('left');
  
  // Force reflow
  void arrow.offsetWidth;
  
  arrow.style.transition = 'left 0.8s ease-in-out';
  arrow.style.left = endX + 'px';
  
  setTimeout(() => { arrow.classList.add('hidden'); }, 1000);
}

function autoPlay() {
  const speed = 6 - document.getElementById('speed-slider').value; // 1 to 5 mapping to 5s to 1s
  if (document.getElementById('btn-next').disabled) return;
  runNextStep();
  AppState.autoPlayTimer = setTimeout(autoPlay, speed * 1000);
}

// --- Quiz Logic ---
const quizData = [
  { q: "What is the primary purpose of a nonce in cryptographic protocols?", opts: ["To establish a session key", "To prevent replay attacks by ensuring freshness", "To encrypt the payload", "To compress the message"], ans: 1, diff: "easy" },
  { q: "In the Needham-Schroeder protocol, who generates the session key (Kab)?", opts: ["Alice", "Bob", "The KDC (Key Distribution Center)", "It is derived from Kas and Kbs"], ans: 2, diff: "easy" },
  { q: "Which key is used to encrypt the 'Ticket' sent to Bob?", opts: ["Kas", "Kbs", "Kab", "Alice's public key"], ans: 1, diff: "easy" },
  { q: "Why does Alice send {Nb - 1} encrypted with Kab in the final step?", opts: ["To prove she has the session key Kab and can decrypt Nb", "To establish a new nonce", "To notify the KDC that the session started", "To close the connection"], ans: 0, diff: "easy" },
  { q: "What is the Denning-Sacco vulnerability in the original protocol?", opts: ["Kas can be brute-forced", "Bob cannot verify the freshness of the ticket (Message 3)", "Alice does not authenticate the KDC", "Nonces are predictable"], ans: 1, diff: "medium" },
  { q: "How can the Denning-Sacco vulnerability be fixed?", opts: ["By using RSA instead of AES", "By adding timestamps or lifetimes to the ticket", "By making the nonce longer", "By removing the KDC"], ans: 1, diff: "medium" },
  { q: "In Message 2, why is Alice's nonce (Na) included inside the ciphertext encrypted with Kas?", opts: ["So Bob can read it later", "To ensure the KDC didn't replay an old session key message to Alice", "Because AES requires a nonce", "To pad the block size"], ans: 1, diff: "medium" },
  { q: "Who can read the contents of the ticket during transmission?", opts: ["Only Alice", "Only Bob and the KDC", "Alice and Bob", "Anyone listening"], ans: 1, diff: "medium" },
  { q: "Unlike Needham-Schroeder, Kerberos mitigates replay attacks inherently by:", opts: ["Not using a KDC", "Relying strictly on synchronized clocks and timestamps", "Using asymmetric encryption", "Using biometric authentication"], ans: 1, diff: "hard" },
  { q: "If an attacker intercepts Message 3 and replays it to Bob while the timestamp fix is active, what happens?", opts: ["Bob accepts it and establishes the session", "Bob rejects it because the ticket has expired", "Alice detects the replay and aborts", "The KDC revokes the key"], ans: 1, diff: "hard" }
];

function renderQuiz() {
  const container = document.getElementById('quiz-container');
  quizData.forEach((item, index) => {
    const qDiv = document.createElement('div');
    qDiv.className = 'quiz-question mb-4';
    let optionsHtml = '';
    item.opts.forEach((opt, oIdx) => {
      optionsHtml += `
        <label style="display:block; margin:5px 0;">
          <input type="radio" name="q${index}" value="${oIdx}"> ${opt}
        </label>
      `;
    });
    qDiv.innerHTML = `<p><strong>Q${index + 1}. (${item.diff}) ${item.q}</strong></p>${optionsHtml}`;
    container.appendChild(qDiv);
  });
}

function submitQuiz() {
  let score = 0;
  quizData.forEach((item, index) => {
    const selected = document.querySelector(`input[name="q${index}"]:checked`);
    const qDiv = document.querySelectorAll('.quiz-question')[index];
    if (selected && parseInt(selected.value) === item.ans) {
      score++;
      qDiv.style.color = 'green';
    } else {
      qDiv.style.color = 'red';
    }
  });
  const scoreDiv = document.getElementById('quiz-score');
  scoreDiv.innerHTML = `<h3>Your Score: ${score} / 10</h3>`;
  scoreDiv.classList.remove('hidden');
  document.getElementById('btn-submit-quiz').classList.add('hidden');
  document.getElementById('btn-retry-quiz').classList.remove('hidden');
}

function retryQuiz() {
  document.querySelectorAll('input[type="radio"]').forEach(el => el.checked = false);
  document.querySelectorAll('.quiz-question').forEach(el => el.style.color = '');
  document.getElementById('quiz-score').classList.add('hidden');
  document.getElementById('btn-submit-quiz').classList.remove('hidden');
  document.getElementById('btn-retry-quiz').classList.add('hidden');
}

// --- Init & Events ---
document.addEventListener('DOMContentLoaded', () => {
  // Tabs logic
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => {
        b.classList.remove('active'); b.setAttribute('aria-selected', 'false');
      });
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      
      const target = e.target;
      target.classList.add('active'); target.setAttribute('aria-selected', 'true');
      document.getElementById(target.getAttribute('data-tab')).classList.add('active');
    });
  });
  
  // Sim controls
  document.getElementById('btn-next').addEventListener('click', runNextStep);
  document.getElementById('btn-reset').addEventListener('click', resetSimulation);
  document.getElementById('scenario-select').addEventListener('change', resetSimulation);
  document.getElementById('btn-auto').addEventListener('click', autoPlay);
  
  document.getElementById('btn-demo').addEventListener('click', () => {
     document.getElementById('scenario-select').value = 'normal';
     resetSimulation();
     setTimeout(() => runNextStep(), 500);
     setTimeout(() => runNextStep(), 2000);
     setTimeout(() => runNextStep(), 3500);
     setTimeout(() => runNextStep(), 5000);
     setTimeout(() => runNextStep(), 6500);
  });
  
  document.getElementById('btn-print').addEventListener('click', () => {
     window.print();
  });
  
  // Modal close
  document.querySelector('.close-modal').addEventListener('click', () => {
    document.getElementById('crypto-modal').classList.add('hidden');
  });
  
  // Quiz
  renderQuiz();
  document.getElementById('btn-submit-quiz').addEventListener('click', submitQuiz);
  document.getElementById('btn-retry-quiz').addEventListener('click', retryQuiz);
  
  // Feedback
  document.getElementById('feedback-form').addEventListener('submit', (e) => {
    e.preventDefault();
    document.getElementById('fb-message').innerText = 'Thank you for your feedback!';
    const data = {
      name: document.getElementById('fb-name').value,
      rating: document.querySelector('input[name="rating"]:checked')?.value || 'Not rated',
      clarity: document.getElementById('fb-clarity').value,
      difficulty: document.getElementById('fb-difficulty').value,
      comments: document.getElementById('fb-comments').value
    };
    localStorage.setItem('ns_feedback', JSON.stringify(data));
    document.getElementById('btn-copy-feedback').classList.remove('hidden');
  });
  
  document.getElementById('btn-copy-feedback').addEventListener('click', () => {
    const data = localStorage.getItem('ns_feedback');
    navigator.clipboard.writeText(data).then(() => alert('Copied to clipboard!'));
  });
  
  initSimulation();
});
