/**
 * MAC Experiment — script.js
 * Virtual Cryptography Laboratory | Fr. CRCE
 *
 * Implements CBC-MAC (AES-128 block chaining simulation),
 * CMAC (NIST SP 800-38B subkeys K1, K2), and Keyed-MAC (SHA-256 secret prefix).
 *
 * Pure client-side cryptography using Web Crypto API.
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

function hexToBytes(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

function concatBytes(a, b) {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

function xorBlocks(a, b) {
  const len = Math.min(a.length, b.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

function escapeHTML(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ============================================================
   ALGORITHM IMPLEMENTATIONS
   ============================================================ */

/**
 * Keyed-MAC: SHA-256(Key || Message)
 */
async function computeKeyedMAC(keyStr, messageStr) {
  const keyBytes = strToBytes(keyStr);
  const msgBytes = strToBytes(messageStr);
  const input = concatBytes(keyBytes, msgBytes);
  const hashBuffer = await crypto.subtle.digest('SHA-256', input);
  return bytesToHex(new Uint8Array(hashBuffer));
}

/**
 * Standard AES-128 Raw Block Encrypt using Web Crypto AES-CBC with IV=0
 */
async function aesEncryptBlock(key16Bytes, block16Bytes) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key16Bytes,
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  );
  // Zero IV
  const iv = new Uint8Array(16);
  // Web Crypto AES-CBC applies PKCS7 padding by default, so 16 bytes becomes 32 bytes.
  // The first 16 bytes of ciphertext corresponds to raw AES_K(block ^ IV).
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    block16Bytes
  );
  return new Uint8Array(ciphertextBuffer).slice(0, 16);
}

/**
 * Derive 16-byte key from user input
 */
async function derive16ByteKey(keyInput) {
  const cleanHex = keyInput.trim().replace(/[^0-9a-fA-F]/g, '');
  if (cleanHex.length === 32) {
    return hexToBytes(cleanHex);
  }
  const hash = await crypto.subtle.digest('SHA-256', strToBytes(keyInput));
  return new Uint8Array(hash).slice(0, 16);
}

/**
 * Split message into 16-byte blocks
 */
function partitionBlocks(msgBytes, paddingType = 'PKCS7') {
  const blockSize = 16;
  const blocks = [];
  const total = msgBytes.length;
  
  if (total === 0) {
    if (paddingType === 'PKCS7') {
      const pad = new Uint8Array(16).fill(16);
      blocks.push(pad);
    } else {
      const pad = new Uint8Array(16);
      pad[0] = 0x80;
      blocks.push(pad);
    }
    return blocks;
  }

  for (let i = 0; i < total; i += blockSize) {
    const chunk = msgBytes.slice(i, i + blockSize);
    if (chunk.length === blockSize) {
      blocks.push(chunk);
    } else {
      // Need padding
      const padLen = blockSize - chunk.length;
      const padded = new Uint8Array(blockSize);
      padded.set(chunk, 0);
      if (paddingType === 'PKCS7') {
        for (let p = chunk.length; p < blockSize; p++) padded[p] = padLen;
      } else {
        // Bit padding (1000...): 0x80 then 0x00
        padded[chunk.length] = 0x80;
        for (let p = chunk.length + 1; p < blockSize; p++) padded[p] = 0x00;
      }
      blocks.push(padded);
    }
  }

  // If PKCS7 and length was exact multiple, append full padding block
  if (paddingType === 'PKCS7' && total % blockSize === 0) {
    const pad = new Uint8Array(16).fill(16);
    blocks.push(pad);
  }

  return blocks;
}

/**
 * CBC-MAC computation with step execution tracking
 */
async function computeCBCMAC(key16, msgBytes) {
  const blocks = partitionBlocks(msgBytes, 'PKCS7');
  let state = new Uint8Array(16); // IV = 0
  const steps = [];

  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];
    const xored = xorBlocks(block, state);
    const encrypted = await aesEncryptBlock(key16, xored);
    steps.push({
      blockIndex: i + 1,
      inputBlock: bytesToHex(block),
      previousState: bytesToHex(state),
      xorResult: bytesToHex(xored),
      outputState: bytesToHex(encrypted)
    });
    state = encrypted;
  }

  return {
    tag: bytesToHex(state),
    blocks,
    steps
  };
}

/**
 * CMAC (NIST SP 800-38B) Subkey Derivation and MAC
 */
async function computeCMAC(key16, msgBytes) {
  // 1. L = AES_K(0^128)
  const zeroBlock = new Uint8Array(16);
  const L = await aesEncryptBlock(key16, zeroBlock);

  // Helper: left shift 1 bit in GF(2^128)
  function shiftLeft(b) {
    const out = new Uint8Array(16);
    let overflow = 0;
    for (let i = 15; i >= 0; i--) {
      out[i] = ((b[i] << 1) | overflow) & 0xff;
      overflow = (b[i] & 0x80) ? 1 : 0;
    }
    if (b[0] & 0x80) {
      out[15] ^= 0x87; // Rb for 128-bit block
    }
    return out;
  }

  const K1 = shiftLeft(L);
  const K2 = shiftLeft(K1);

  // 2. Partition message without premature padding
  const blockSize = 16;
  const blocks = [];
  const total = msgBytes.length;
  let isCompleteLastBlock = true;

  if (total === 0) {
    const padded = new Uint8Array(16);
    padded[0] = 0x80;
    blocks.push(padded);
    isCompleteLastBlock = false;
  } else {
    for (let i = 0; i < total; i += blockSize) {
      const chunk = msgBytes.slice(i, i + blockSize);
      if (chunk.length === blockSize) {
        blocks.push(chunk);
      } else {
        isCompleteLastBlock = false;
        const padded = new Uint8Array(blockSize);
        padded.set(chunk, 0);
        padded[chunk.length] = 0x80;
        blocks.push(padded);
      }
    }
  }

  // 3. XOR last block with K1 (if complete) or K2 (if padded)
  const lastIdx = blocks.length - 1;
  const subkeyUsed = isCompleteLastBlock ? K1 : K2;
  blocks[lastIdx] = xorBlocks(blocks[lastIdx], subkeyUsed);

  // 4. CBC chaining
  let state = new Uint8Array(16);
  const steps = [];

  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];
    const xored = xorBlocks(block, state);
    const encrypted = await aesEncryptBlock(key16, xored);
    steps.push({
      blockIndex: i + 1,
      inputBlock: bytesToHex(block),
      previousState: bytesToHex(state),
      xorResult: bytesToHex(xored),
      outputState: bytesToHex(encrypted)
    });
    state = encrypted;
  }

  return {
    tag: bytesToHex(state),
    blocks,
    steps,
    subkeys: {
      L: bytesToHex(L),
      K1: bytesToHex(K1),
      K2: bytesToHex(K2)
    }
  };
}

/* ============================================================
   UI CONTROLLER & SIMULATION
   ============================================================ */

let stateLastGenerated = {
  tag: '',
  key: '',
  message: '',
  algo: ''
};

function renderBlockPreview() {
  const msg = document.getElementById('message-input').value;
  const algo = document.getElementById('algo-select').value;
  const grid = document.getElementById('blockPreviewGrid');
  if (!grid) return;

  const msgBytes = strToBytes(msg);
  const blocks = partitionBlocks(msgBytes, algo === 'CMAC' ? 'BIT' : 'PKCS7');

  grid.innerHTML = blocks.map((b, i) => {
    const hex = bytesToHex(b);
    return `
      <div class="block-preview-card">
        <div class="block-card-title">Block P<sub>${i + 1}</sub> (128-bit)</div>
        <div class="block-card-hex">${hex}</div>
        <div class="block-card-meta">${b.length} bytes &middot; ${b.length * 8} bits</div>
      </div>
    `;
  }).join('');
}

function initAutoKey() {
  const btnAutoKey = document.getElementById('btnAutoKey');
  const secretKeyInput = document.getElementById('secret-key');

  if (btnAutoKey && secretKeyInput) {
    btnAutoKey.addEventListener('click', () => {
      const randBytes = new Uint8Array(16);
      crypto.getRandomValues(randBytes);
      secretKeyInput.value = bytesToHex(randBytes);
      renderBlockPreview();
    });
  }
}

function initSimulationHandlers() {
  const algoSelect = document.getElementById('algo-select');
  const secretKeyInput = document.getElementById('secret-key');
  const messageInput = document.getElementById('message-input');
  const btnGenerateMac = document.getElementById('btnGenerateMac');
  const genError = document.getElementById('gen-error');
  const genResult = document.getElementById('gen-result');
  const genTagDisplay = document.getElementById('gen-tag-display');
  const genAlgoBadge = document.getElementById('gen-algo-badge');
  const genMeta = document.getElementById('gen-meta');
  const chainStepsContainer = document.getElementById('chain-steps-container');
  const btnCopyTag = document.getElementById('btnCopyTag');
  const btnTransferVerify = document.getElementById('btnTransferVerify');

  if (messageInput) {
    messageInput.addEventListener('input', renderBlockPreview);
  }
  if (algoSelect) {
    algoSelect.addEventListener('change', renderBlockPreview);
  }

  // Initial preview render
  renderBlockPreview();

  if (btnGenerateMac) {
    btnGenerateMac.addEventListener('click', async () => {
      const keyVal = secretKeyInput.value.trim();
      const msgVal = messageInput.value;
      const algoVal = algoSelect.value;

      genError.setAttribute('hidden', '');
      genResult.setAttribute('hidden', '');

      if (!keyVal) {
        genError.textContent = 'Please enter or auto-generate a secret key (K).';
        genError.removeAttribute('hidden');
        return;
      }

      btnGenerateMac.disabled = true;
      btnGenerateMac.textContent = 'Computing MAC Tag…';

      try {
        let tag = '';
        let stepsHtml = '';
        const key16 = await derive16ByteKey(keyVal);
        const msgBytes = strToBytes(msgVal);

        if (algoVal === 'CBC-MAC') {
          const res = await computeCBCMAC(key16, msgBytes);
          tag = res.tag;
          stepsHtml = res.steps.map(s => `
            <div class="chain-step-card">
              <div class="chain-step-header">Block P<sub>${s.blockIndex}</sub> Processing</div>
              <div class="chain-step-grid">
                <div><span class="chain-label">Input Block (P<sub>${s.blockIndex}</sub>):</span> <code class="monospace">${s.inputBlock}</code></div>
                <div><span class="chain-label">XOR Chaining (T<sub>${s.blockIndex - 1}</sub> &oplus; P<sub>${s.blockIndex}</sub>):</span> <code class="monospace">${s.xorResult}</code></div>
                <div><span class="chain-label">AES-128 Cipher Output (T<sub>${s.blockIndex}</sub>):</span> <code class="monospace highlight-tag">${s.outputState}</code></div>
              </div>
            </div>
          `).join('');
        } else if (algoVal === 'CMAC') {
          const res = await computeCMAC(key16, msgBytes);
          tag = res.tag;
          stepsHtml = `
            <div class="chain-step-card" style="border-left-color: var(--color-secondary);">
              <div class="chain-step-header">NIST SP 800-38B Subkey Derivation</div>
              <div class="chain-step-grid">
                <div><span class="chain-label">L = AES<sub>K</sub>(0<sup>128</sup>):</span> <code class="monospace">${res.subkeys.L}</code></div>
                <div><span class="chain-label">Subkey K<sub>1</sub> (L &lt;&lt; 1 &oplus; R<sub>b</sub>):</span> <code class="monospace">${res.subkeys.K1}</code></div>
                <div><span class="chain-label">Subkey K<sub>2</sub> (K<sub>1</sub> &lt;&lt; 1 &oplus; R<sub>b</sub>):</span> <code class="monospace">${res.subkeys.K2}</code></div>
              </div>
            </div>
          ` + res.steps.map(s => `
            <div class="chain-step-card">
              <div class="chain-step-header">Block P<sub>${s.blockIndex}</sub> Processing</div>
              <div class="chain-step-grid">
                <div><span class="chain-label">Input Block:</span> <code class="monospace">${s.inputBlock}</code></div>
                <div><span class="chain-label">XOR Chained:</span> <code class="monospace">${s.xorResult}</code></div>
                <div><span class="chain-label">Cipher Output (T<sub>${s.blockIndex}</sub>):</span> <code class="monospace highlight-tag">${s.outputState}</code></div>
              </div>
            </div>
          `).join('');
        } else {
          // Keyed-MAC
          tag = await computeKeyedMAC(keyVal, msgVal);
          stepsHtml = `
            <div class="chain-step-card">
              <div class="chain-step-header">Keyed-MAC Secret Prefix Chaining</div>
              <div class="chain-step-grid">
                <div><span class="chain-label">Key Payload:</span> <code class="monospace">${bytesToHex(strToBytes(keyVal))}</code></div>
                <div><span class="chain-label">Message Payload:</span> <code class="monospace">${bytesToHex(strToBytes(msgVal))}</code></div>
                <div><span class="chain-label">Concatenated Hash SHA-256(K || M):</span> <code class="monospace highlight-tag">${tag}</code></div>
              </div>
            </div>
          `;
        }

        stateLastGenerated = {
          tag,
          key: keyVal,
          message: msgVal,
          algo: algoVal
        };

        genTagDisplay.textContent = tag;
        genAlgoBadge.textContent = algoVal;
        genMeta.innerHTML = `Tag Length: <strong>${tag.length * 4} bits</strong> (${tag.length / 2} bytes) &middot; Status: <strong style="color:var(--color-success,#4ec9b0);">Generated Successfully</strong>`;
        chainStepsContainer.innerHTML = stepsHtml;
        genResult.removeAttribute('hidden');
        genResult.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Prepopulate verifier fields
        const verTag = document.getElementById('ver-tag');
        if (verTag) verTag.value = tag;
        const verMessage = document.getElementById('ver-message');
        if (verMessage) verMessage.value = msgVal;

      } catch (err) {
        genError.textContent = 'Error computing MAC tag: ' + err.message;
        genError.removeAttribute('hidden');
      } finally {
        btnGenerateMac.disabled = false;
        btnGenerateMac.innerHTML = '&#9889; Generate MAC Tag C(K, M)';
      }
    });
  }

  if (btnCopyTag) {
    btnCopyTag.addEventListener('click', () => {
      if (!stateLastGenerated.tag) return;
      navigator.clipboard.writeText(stateLastGenerated.tag);
      const originalText = btnCopyTag.innerHTML;
      btnCopyTag.innerHTML = '&#10003; Copied!';
      setTimeout(() => { btnCopyTag.innerHTML = originalText; }, 1800);
    });
  }

  if (btnTransferVerify) {
    btnTransferVerify.addEventListener('click', () => {
      const verSection = document.getElementById('sim-step4');
      if (verSection) {
        verSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  }
}

/* ============================================================
   VERIFICATION & MITM TAMPER SIMULATOR
   ============================================================ */

function initVerifyAndTamper() {
  const btnVerifyMac = document.getElementById('btnVerifyMac');
  const verMessageInput = document.getElementById('ver-message');
  const verTagInput = document.getElementById('ver-tag');
  const verResult = document.getElementById('ver-result');
  const algoSelect = document.getElementById('algo-select');
  const secretKeyInput = document.getElementById('secret-key');

  const btnTamperMsg = document.getElementById('btnTamperMsg');
  const btnCorruptTag = document.getElementById('btnCorruptTag');
  const btnResetVerify = document.getElementById('btnResetVerify');

  if (btnVerifyMac) {
    btnVerifyMac.addEventListener('click', async () => {
      const keyVal = secretKeyInput.value.trim();
      const msgVal = verMessageInput.value;
      const tagVal = verTagInput.value.trim().toLowerCase();
      const algoVal = algoSelect.value;

      verResult.setAttribute('hidden', '');

      if (!keyVal || !tagVal) {
        verResult.className = 'ver-result-box result-failure';
        verResult.innerHTML = '<span class="result-icon">&#9888;</span> <strong>Missing Input:</strong> Secret key (K) and received MAC tag (T) are required for verification.';
        verResult.removeAttribute('hidden');
        return;
      }

      try {
        let expectedTag = '';
        const key16 = await derive16ByteKey(keyVal);
        const msgBytes = strToBytes(msgVal);

        if (algoVal === 'CBC-MAC') {
          const res = await computeCBCMAC(key16, msgBytes);
          expectedTag = res.tag;
        } else if (algoVal === 'CMAC') {
          const res = await computeCMAC(key16, msgBytes);
          expectedTag = res.tag;
        } else {
          expectedTag = await computeKeyedMAC(keyVal, msgVal);
        }

        const isValid = expectedTag.toLowerCase() === tagVal;

        if (isValid) {
          verResult.className = 'ver-result-box result-success';
          verResult.innerHTML = `
            <span class="result-icon">&#10004;</span>
            <div>
              <strong>Verification Successful &mdash; Tag Matches!</strong>
              <div style="margin-top:6px;font-size:0.9rem;">
                Computed Tag: <code class="monospace">${expectedTag}</code><br>
                Received Tag: <code class="monospace">${tagVal}</code>
              </div>
              <div style="margin-top:6px;color:#7ee787;">
                &#10003; Data Integrity: Verified (Payload has not been tampered with).<br>
                &#10003; Origin Authenticity: Verified (Sender possesses shared secret key K).
              </div>
            </div>
          `;
        } else {
          verResult.className = 'ver-result-box result-failure';
          verResult.innerHTML = `
            <span class="result-icon">&#10008;</span>
            <div>
              <strong>Verification FAILED &mdash; Tag Mismatch Detected!</strong>
              <div style="margin-top:6px;font-size:0.9rem;">
                Recomputed Tag: <code class="monospace">${expectedTag}</code><br>
                Received Tag: &nbsp;&nbsp;<code class="monospace" style="color:#ff7b72;">${tagVal}</code>
              </div>
              <div style="margin-top:6px;color:#ff7b72;">
                &#9888; Warning: The message has been modified in transit OR generated with an incorrect key!
              </div>
            </div>
          `;
        }
        verResult.removeAttribute('hidden');
      } catch (err) {
        verResult.className = 'ver-result-box result-failure';
        verResult.innerHTML = `<span class="result-icon">&#9888;</span> <strong>Verification Error:</strong> ${escapeHTML(err.message)}`;
        verResult.removeAttribute('hidden');
      }
    });
  }

  // Active Tamper: Modify Message Payload
  if (btnTamperMsg) {
    btnTamperMsg.addEventListener('click', () => {
      let current = verMessageInput.value;
      if (current.includes('$5,000')) {
        verMessageInput.value = current.replace('$5,000', '$95,000');
      } else if (current.endsWith('.')) {
        verMessageInput.value = current.slice(0, -1);
      } else {
        verMessageInput.value = current + ' [TAMPERED]';
      }
      if (btnVerifyMac) btnVerifyMac.click();
    });
  }

  // Active Tamper: Corrupt Tag
  if (btnCorruptTag) {
    btnCorruptTag.addEventListener('click', () => {
      let currentTag = verTagInput.value.trim();
      if (!currentTag) return;
      const chars = currentTag.split('');
      // Flip first hex char
      const first = chars[0];
      chars[0] = (first === '0' || first === 'a') ? 'f' : '0';
      verTagInput.value = chars.join('');
      if (btnVerifyMac) btnVerifyMac.click();
    });
  }

  // Reset to original
  if (btnResetVerify) {
    btnResetVerify.addEventListener('click', () => {
      verMessageInput.value = stateLastGenerated.message || document.getElementById('message-input').value;
      verTagInput.value = stateLastGenerated.tag || '';
      verResult.setAttribute('hidden', '');
    });
  }
}

/* ============================================================
   SUMMARY TABLE
   ============================================================ */

function initSummaryTable() {
  const btnUpdate = document.getElementById('btnUpdateSummary');
  const toast = document.getElementById('sum-updated-toast');
  const sumMsg = document.getElementById('sum-message');
  const sumAlgo = document.getElementById('sum-algorithm');
  const sumKey = document.getElementById('sum-key');
  const sumTag = document.getElementById('sum-tag');

  if (btnUpdate) {
    btnUpdate.addEventListener('click', () => {
      const msg = document.getElementById('message-input').value;
      const algo = document.getElementById('algo-select').value;
      const key = document.getElementById('secret-key').value;
      const tag = stateLastGenerated.tag || '(Click Generate MAC first)';

      sumMsg.textContent = msg || '-';
      sumAlgo.textContent = algo || '-';
      sumKey.textContent = key || '-';
      sumTag.textContent = tag;

      if (toast) {
        toast.removeAttribute('hidden');
        setTimeout(() => toast.setAttribute('hidden', ''), 2500);
      }
    });
  }
}

/* ============================================================
   QUIZ CONTROLLER
   ============================================================ */

function initQuiz() {
  const questions = document.querySelectorAll('.quiz-question');
  const btnSubmit = document.getElementById('btnSubmitQuiz');
  const btnReset = document.getElementById('btnResetQuiz');
  const quizScore = document.getElementById('quizScore');

  // Handle option selection
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
      let answeredCount = 0;
      let score = 0;

      questions.forEach(q => {
        const correctIdx = parseInt(q.dataset.correct, 10);
        const btns = q.querySelectorAll('.quiz-option-btn');
        const reason = q.querySelector('.quiz-reason');
        let selectedIdx = -1;

        btns.forEach((btn, idx) => {
          if (btn.classList.contains('selected')) {
            selectedIdx = idx;
          }
        });

        if (selectedIdx !== -1) {
          answeredCount++;
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
        quizScore.innerHTML = `Your Score: <strong>${score} / ${questions.length}</strong> (${pct}%) &mdash; ` +
          (pct >= 60 ? '&#127881; Great job!' : '&#128161; Review the theory and try again.');
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

function initTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-content');

  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const selectedTab = button.dataset.tab;

      tabButtons.forEach(tabButton => {
        const isSelected = tabButton === button;
        tabButton.classList.toggle('active', isSelected);
        tabButton.setAttribute('aria-selected', String(isSelected));
      });

      tabPanels.forEach(panel => {
        const isSelected = panel.dataset.tabPanel === selectedTab;
        panel.classList.toggle('active', isSelected);
        panel.toggleAttribute('hidden', !isSelected);
      });
    });
  });
}

/* ============================================================
   INIT ON DOM READY
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initAutoKey();
  initSimulationHandlers();
  initVerifyAndTamper();
  initSummaryTable();
  initQuiz();
});
