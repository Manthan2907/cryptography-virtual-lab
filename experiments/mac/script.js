/**
 * MAC Experiment - script.js
 * Virtual Cryptography Laboratory | Fr. CRCE
 *
 * Sender → (optional Attacker) → Receiver MAC simulation
 * using HMAC-SHA256 via Web Crypto API.
 */

'use strict';

/* ============================================================
   CRYPTOGRAPHY & UTILITY HELPERS
   ============================================================ */

function strToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function escapeHTML(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Compute HMAC-SHA256(key, message) using Web Crypto API
 */
async function computeHMAC(keyStr, messageStr) {
  const keyBytes = strToBytes(keyStr);
  const msgBytes = strToBytes(messageStr);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, msgBytes);
  return bytesToHex(new Uint8Array(signature));
}

/* ============================================================
   SIMULATION STATE
   ============================================================ */

let simState = {
  senderMessage: '',
  senderKey: '',
  senderMAC: '',
  attackerEnabled: false,
  attackerMessage: '',
  attackerMAC: '',
  attackerRandomKey: '',
  transmitted: false
};

/* ============================================================
   UTILITY: SHOW / HIDE ELEMENTS
   ============================================================ */

function showElement(id) {
  const el = document.getElementById(id);
  if (el) el.removeAttribute('hidden');
}

function hideElement(id) {
  const el = document.getElementById(id);
  if (el) el.setAttribute('hidden', '');
}

/* ============================================================
   SENDER LOGIC
   ============================================================ */

function initSender() {
  const btnGenerate = document.getElementById('btnSenderGenerate');
  const senderError = document.getElementById('sender-error');
  const senderResult = document.getElementById('sender-result');
  const senderTagDisplay = document.getElementById('sender-tag-display');
  const senderMeta = document.getElementById('sender-meta');
  const senderTransmitted = document.getElementById('sender-transmitted');

  if (!btnGenerate) return;

  btnGenerate.addEventListener('click', async () => {
    const message = document.getElementById('sender-message').value;
    const key = document.getElementById('sender-key').value.trim();

    // Reset downstream
    hideElement('sim-attacker-wrapper');
    hideElement('sim-reset-area');
    hideElement('attacker-forged-result');
    document.getElementById('receiver-got-msg').textContent = '[Awaiting Transmission]';
    document.getElementById('receiver-got-mac').textContent = '[Awaiting Transmission]';
    senderError.setAttribute('hidden', '');
    senderResult.setAttribute('hidden', '');

    const receiverResult = document.getElementById('receiver-result');
    if (receiverResult) receiverResult.setAttribute('hidden', '');

    if (!key) {
      senderError.textContent = 'Please enter a secret key (K).';
      senderError.removeAttribute('hidden');
      return;
    }
    if (!message) {
      senderError.textContent = 'Please enter a message (M).';
      senderError.removeAttribute('hidden');
      return;
    }

    btnGenerate.disabled = true;
    btnGenerate.textContent = 'Computing HMAC-SHA256…';

    try {
      const mac = await computeHMAC(key, message);

      simState.senderMessage = message;
      simState.senderKey = key;
      simState.senderMAC = mac;
      simState.transmitted = true;

      // Display sender results
      senderTagDisplay.textContent = mac;
      senderMeta.innerHTML = `Tag: <strong>${mac.length * 4} bits</strong> (${mac.length / 2} bytes) &middot; <strong>HMAC-SHA256</strong>`;
      senderTransmitted.innerHTML = `<span class="transmitted-msg">${escapeHTML(message)}</span><span class="transmitted-separator">||</span><span class="transmitted-mac">${mac}</span>`;
      senderResult.removeAttribute('hidden');

      // Check if attacker is enabled
      updateChannelState();

      // Check if attacker is enabled
      const attackerToggle = document.getElementById('attackerToggle');
      if (attackerToggle && attackerToggle.checked) {
        // Attacker enabled - show attacker panel, wait for user action
        populateAttacker(message, mac);
        showElement('sim-attacker-wrapper');
      } else {
        // No attacker - send directly to receiver
        showReceiverDirect(message, mac);
      }

    } catch (err) {
      senderError.textContent = 'Error computing MAC: ' + err.message;
      senderError.removeAttribute('hidden');
    } finally {
      btnGenerate.disabled = false;
      btnGenerate.innerHTML = 'Generate MAC &amp; Send';
    }
  });
}

/* ============================================================
   CHANNEL & ATTACKER TOGGLE
   ============================================================ */

function updateChannelState() {
  const toggle = document.getElementById('attackerToggle');
  const label = document.getElementById('channelLabel');
  if (!toggle || !label) return;

  if (toggle.checked) {
    label.innerHTML = 'Compromised Channel';
    label.classList.add('channel-hub-label-danger');
  } else {
    label.innerHTML = 'Secure Channel';
    label.classList.remove('channel-hub-label-danger');
  }
}

function initAttackerToggle() {
  const toggle = document.getElementById('attackerToggle');
  if (!toggle) return;

  toggle.addEventListener('change', () => {
    simState.attackerEnabled = toggle.checked;
    updateChannelState();

    if (toggle.checked) {
      if (simState.transmitted) {
        populateAttacker(simState.senderMessage, simState.senderMAC);
      } else {
        populateAttacker('[Awaiting Transmission]', '[Awaiting Transmission]');
      }
      showElement('sim-attacker-wrapper');
    } else {
      hideElement('sim-attacker-wrapper');
      if (simState.transmitted) {
        showReceiverDirect(simState.senderMessage, simState.senderMAC);
      }
    }
    
    if (simState.transmitted) {
      hideElement('sim-reset-area');
      hideElement('attacker-forged-result');
      document.getElementById('receiver-got-msg').textContent = '[Awaiting Transmission]';
      document.getElementById('receiver-got-mac').textContent = '[Awaiting Transmission]';
      const receiverResult = document.getElementById('receiver-result');
      if (receiverResult) receiverResult.setAttribute('hidden', '');
    }
  });
}

/* ============================================================
   ATTACKER LOGIC
   ============================================================ */

function populateAttacker(message, mac) {
  document.getElementById('attacker-original-msg').textContent = message;
  document.getElementById('attacker-original-mac').textContent = mac;
  document.getElementById('attacker-modified-msg').value = message;
  hideElement('attacker-forged-result');
}

function initAttacker() {
  const btnTamper = document.getElementById('btnAttackerTamper');
  const btnForward = document.getElementById('btnAttackerForward');
  const modifiedMsg = document.getElementById('attacker-modified-msg');

  if (btnTamper) {
    btnTamper.addEventListener('click', () => {
      let current = modifiedMsg.value;
      if (current.includes('$5,000')) {
        modifiedMsg.value = current.replace('$5,000', '$95,000');
      } else if (current.includes('$95,000')) {
        modifiedMsg.value = current.replace('$95,000', '$5,000');
      } else {
        modifiedMsg.value = current + ' [TAMPERED]';
      }
      modifiedMsg.classList.add('tampered-highlight');
      setTimeout(() => modifiedMsg.classList.remove('tampered-highlight'), 1500);
      hideElement('attacker-forged-result');
    });
  }

  if (btnForward) {
    btnForward.addEventListener('click', async () => {
      const attackerMsg = modifiedMsg.value;

      btnForward.disabled = true;
      btnForward.textContent = 'Forging MAC…';

      try {
        // Generate a random key
        const randBytes = new Uint8Array(16);
        crypto.getRandomValues(randBytes);
        const randomKey = bytesToHex(randBytes);

        // Compute forged MAC
        const forgedMAC = await computeHMAC(randomKey, attackerMsg);

        // Display
        document.getElementById('attacker-random-key').textContent = randomKey;
        document.getElementById('attacker-forged-mac').textContent = forgedMAC;
        showElement('attacker-forged-result');

        simState.attackerMessage = attackerMsg;
        simState.attackerMAC = forgedMAC;
        simState.attackerRandomKey = randomKey;

        // Show receiver with tampered data
        showReceiverDirect(attackerMsg, forgedMAC);
      } catch (err) {
        console.error('Error generating forged MAC:', err);
      } finally {
        btnForward.disabled = false;
        btnForward.innerHTML = 'Forge MAC &amp; Forward';
      }
    });
  }
}

/* ============================================================
   RECEIVER LOGIC
   ============================================================ */

function showReceiverDirect(message, mac) {
  document.getElementById('receiver-got-msg').textContent = message;
  document.getElementById('receiver-got-mac').textContent = mac;

  const receiverResult = document.getElementById('receiver-result');
  if (receiverResult) receiverResult.setAttribute('hidden', '');

  showElement('sim-reset-area');
}

function initReceiver() {
  const btnVerify = document.getElementById('btnReceiverVerify');
  if (!btnVerify) return;

  btnVerify.addEventListener('click', async () => {
    const receivedMsg = document.getElementById('receiver-got-msg').textContent;
    const receivedMac = document.getElementById('receiver-got-mac').textContent;
    const receiverResult = document.getElementById('receiver-result');
    const computedMacEl = document.getElementById('receiver-computed-mac');
    const verdictEl = document.getElementById('receiver-verdict');

    btnVerify.disabled = true;
    btnVerify.textContent = 'Computing MAC…';

    try {
      const computedMac = await computeHMAC(simState.senderKey, receivedMsg);
      computedMacEl.textContent = computedMac;

      const isMatch = computedMac === receivedMac;

      if (isMatch) {
        verdictEl.className = 'ver-result-box result-success';
        verdictEl.innerHTML = `
          <span class="result-icon"></span>
          <div>
            <strong>Verification PASSED - Message is Authentic!</strong>
            <div class="verdict-details">
              Computed MAC: <code class="monospace">${computedMac}</code><br>
              Received MAC: <code class="monospace">${receivedMac}</code>
            </div>
            <div class="verdict-status verdict-status-pass">
              - Data Integrity: Verified - No tampering detected.<br>
              - Origin Authenticity: Verified - Sender holds key K.
            </div>
          </div>
        `;
      } else {
        verdictEl.className = 'ver-result-box result-failure';
        verdictEl.innerHTML = `
          <span class="result-icon"></span>
          <div>
            <strong>Verification FAILED - TAMPERING DETECTED!</strong>
            <div class="verdict-details">
              Computed MAC: <code class="monospace">${computedMac}</code><br>
              Received MAC: <code class="monospace verdict-mismatch">${receivedMac}</code>
            </div>
            <div class="verdict-status verdict-status-fail">
              - MAC mismatch! Message was modified in transit.<br>
              - Attacker could not forge a valid MAC without the key.
            </div>
          </div>
        `;
      }

      receiverResult.removeAttribute('hidden');
    } catch (err) {
      verdictEl.className = 'ver-result-box result-failure';
      verdictEl.innerHTML = `<strong>Error:</strong> ${escapeHTML(err.message)}`;
      receiverResult.removeAttribute('hidden');
    } finally {
      btnVerify.disabled = false;
      btnVerify.innerHTML = 'Verify - Compute MAC(K, M) and Compare';
    }
  });
}

/* ============================================================
   RESET
   ============================================================ */

function initReset() {
  const btnReset = document.getElementById('btnResetSim');
  if (!btnReset) return;

  btnReset.addEventListener('click', () => {
    simState = {
      senderMessage: '',
      senderKey: '',
      senderMAC: '',
      attackerEnabled: false,
      attackerMessage: '',
      attackerMAC: '',
      attackerRandomKey: '',
      transmitted: false
    };

    const attackerToggle = document.getElementById('attackerToggle');
    if (attackerToggle) {
      attackerToggle.checked = false;
      updateChannelState();
    }

    hideElement('sender-result');
    hideElement('sender-error');
    hideElement('sim-attacker-wrapper');
    hideElement('attacker-forged-result');
    hideElement('sim-reset-area');
    document.getElementById('receiver-got-msg').textContent = '[Awaiting Transmission]';
    document.getElementById('receiver-got-mac').textContent = '[Awaiting Transmission]';

    const receiverResult = document.getElementById('receiver-result');
    if (receiverResult) receiverResult.setAttribute('hidden', '');

    document.getElementById('sender-message').value = 'Transfer $5,000 to Account #98412';
    document.getElementById('sender-key').value = 'mysecretkey123';
  });
}

/* ============================================================
   QUIZ CONTROLLER
   ============================================================ */

function initQuiz() {
  const questions = document.querySelectorAll('.quiz-question');
  const btnSubmit = document.getElementById('btnSubmitQuiz');
  const btnReset = document.getElementById('btnResetQuiz');
  const quizScore = document.getElementById('quizScore');

  questions.forEach(q => {
    const btns = q.querySelectorAll('.quiz-option-btn');
    btns.forEach(btn => {
      btn.addEventListener('click', () => {
        btns.forEach(b => b.classList.remove('selected'));
        btn.classList.add('selected');
      });
    });
  });

  if (btnSubmit) {
    btnSubmit.addEventListener('click', () => {
      let score = 0;

      questions.forEach(q => {
        const correctIdx = parseInt(q.dataset.correct, 10);
        const btns = q.querySelectorAll('.quiz-option-btn');
        const reason = q.querySelector('.quiz-reason');
        let selectedIdx = -1;

        btns.forEach((btn, idx) => {
          if (btn.classList.contains('selected')) selectedIdx = idx;
        });

        if (selectedIdx !== -1) {
          if (selectedIdx === correctIdx) {
            score++;
            btns[selectedIdx].classList.add('correct');
          } else {
            btns[selectedIdx].classList.add('incorrect');
            btns[correctIdx].classList.add('correct');
          }
        } else {
          btns[correctIdx].classList.add('correct');
        }

        if (reason) reason.removeAttribute('hidden');
      });

      if (quizScore) {
        const pct = Math.round((score / questions.length) * 100);
        quizScore.className = 'quiz-score ' + (pct >= 60 ? 'score-pass' : 'score-fail');
        quizScore.innerHTML = `Your Score: <strong>${score} / ${questions.length}</strong> (${pct}%) - ` +
          (pct >= 60 ? 'Great job!' : 'Review the theory and try again.');
        quizScore.removeAttribute('hidden');
      }
    });
  }

  if (btnReset) {
    btnReset.addEventListener('click', () => {
      questions.forEach(q => {
        const btns = q.querySelectorAll('.quiz-option-btn');
        btns.forEach(b => b.classList.remove('selected', 'correct', 'incorrect'));
        const reason = q.querySelector('.quiz-reason');
        if (reason) reason.setAttribute('hidden', '');
      });
      if (quizScore) {
        quizScore.setAttribute('hidden', '');
        quizScore.innerHTML = '';
      }
    });
  }
}

/* ============================================================
   INIT ON DOM READY
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {
  initSender();
  initAttackerToggle();
  initAttacker();
  initReceiver();
  initReset();
  initQuiz();
});
