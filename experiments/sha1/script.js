/**
 * ============================================================
 * SHA-1 Cryptographic Hash Algorithm - Client Implementation
 * Implements FIPS PUB 180-4 standard SHA-1 algorithm & simulations
 * ============================================================
 */

(() => {
  'use strict';

  // ============================================================
  // 1. Pure JavaScript Implementation of SHA-1 (FIPS PUB 180-4)
  // ============================================================
  function rotl(n, s) {
    return ((n << s) | (n >>> (32 - s))) >>> 0;
  }

  function sha1(message) {
    // Convert UTF-8 message string to array of bytes
    const msgBytes = [];
    for (let i = 0; i < message.length; i++) {
      const code = message.charCodeAt(i);
      if (code < 0x80) {
        msgBytes.push(code);
      } else if (code < 0x800) {
        msgBytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
      } else if (code < 0xd800 || code >= 0xe000) {
        msgBytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      } else {
        i++;
        const val = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(i) & 0x3ff));
        msgBytes.push(0xf0 | (val >> 18), 0x80 | ((val >> 12) & 0x3f), 0x80 | ((val >> 6) & 0x3f), 0x80 | (val & 0x3f));
      }
    }

    const bitLength = msgBytes.length * 8;

    // Append 0x80 (single '1' bit followed by seven '0' bits)
    msgBytes.push(0x80);

    // Append '0' bytes until length === 56 mod 64 (448 mod 512 bits)
    while ((msgBytes.length % 64) !== 56) {
      msgBytes.push(0);
    }

    // Append 64-bit big-endian length
    msgBytes.push(0, 0, 0, 0); // High 32 bits for realistic string sizes
    msgBytes.push((bitLength >>> 24) & 0xff);
    msgBytes.push((bitLength >>> 16) & 0xff);
    msgBytes.push((bitLength >>> 8) & 0xff);
    msgBytes.push(bitLength & 0xff);

    // Initial 32-bit state registers (FIPS PUB 180-4 standard)
    let H0 = 0x67452301;
    let H1 = 0xefcdab89;
    let H2 = 0x98badcfe;
    let H3 = 0x10325476;
    let H4 = 0xc3d2e1f0;

    // Process each 512-bit (64-byte) block
    for (let i = 0; i < msgBytes.length; i += 64) {
      const W = new Array(80);

      // Load initial 16 words (32-bit big-endian)
      for (let t = 0; t < 16; t++) {
        W[t] = (
          (msgBytes[i + t * 4] << 24) |
          (msgBytes[i + t * 4 + 1] << 16) |
          (msgBytes[i + t * 4 + 2] << 8) |
          (msgBytes[i + t * 4 + 3])
        ) >>> 0;
      }

      // Expand to 80 words
      for (let t = 16; t < 80; t++) {
        W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
      }

      // Initialize working variables
      let A = H0;
      let B = H1;
      let C = H2;
      let D = H3;
      let E = H4;

      // 80 Rounds
      for (let t = 0; t < 80; t++) {
        let f, K;
        if (t < 20) {
          f = (B & C) | ((~B) & D);
          K = 0x5a827999;
        } else if (t < 40) {
          f = B ^ C ^ D;
          K = 0x6ed9eba1;
        } else if (t < 60) {
          f = (B & C) | (B & D) | (C & D);
          K = 0x8f1bbcdc;
        } else {
          f = B ^ C ^ D;
          K = 0xca62c1d6;
        }

        const temp = (rotl(A, 5) + f + E + K + W[t]) >>> 0;
        E = D;
        D = C;
        C = rotl(B, 30);
        B = A;
        A = temp;
      }

      // Add intermediate result to accumulators
      H0 = (H0 + A) >>> 0;
      H1 = (H1 + B) >>> 0;
      H2 = (H2 + C) >>> 0;
      H3 = (H3 + D) >>> 0;
      H4 = (H4 + E) >>> 0;
    }

    // Format 160-bit digest as 40 hexadecimal characters
    function toHex(val) {
      return ('00000000' + val.toString(16)).slice(-8);
    }

    return (toHex(H0) + toHex(H1) + toHex(H2) + toHex(H3) + toHex(H4)).toLowerCase();
  }

  // Helper: Count Hamming distance (number of bit differences between two hex digests)
  function computeBitDifferences(hex1, hex2) {
    let diffBits = 0;
    for (let i = 0; i < hex1.length; i++) {
      const n1 = parseInt(hex1[i], 16);
      const n2 = parseInt(hex2[i], 16);
      let xor = n1 ^ n2;
      while (xor > 0) {
        diffBits += xor & 1;
        xor >>= 1;
      }
    }
    return diffBits;
  }

  // ============================================================
  // 2. DOM Binding & Live Simulation
  // ============================================================
  const inputMsg = document.getElementById('sha1InputText');
  const outputHex = document.getElementById('sha1HexOutput');
  const computeBtn = document.getElementById('computeHashBtn');
  const loadPresetBtn = document.getElementById('loadPresetBtn');
  const copyBtn = document.getElementById('copyDigestBtn');

  const avalancheMsg1 = document.getElementById('avalancheMsg1');
  const avalancheMsg2 = document.getElementById('avalancheMsg2');
  const avalancheHash1 = document.getElementById('avalancheHash1');
  const avalancheHash2 = document.getElementById('avalancheHash2');
  const avalancheStatsText = document.getElementById('avalancheStatsText');

  const quizForm = document.getElementById('sha1QuizForm');
  const submitQuizBtn = document.getElementById('submitQuizBtn');
  const resetQuizBtn = document.getElementById('resetQuizBtn');
  const quizScoreResult = document.getElementById('quizScoreResult');
  const quizScoreSummary = document.getElementById('quizScoreSummary');

  function updateSimulation() {
    if (!inputMsg || !outputHex) return;
    const msg = inputMsg.value;
    const digest = sha1(msg);
    outputHex.textContent = digest;
  }

  function updateAvalanche() {
    if (!avalancheMsg1 || !avalancheMsg2 || !avalancheHash1 || !avalancheHash2 || !avalancheStatsText) return;
    const h1 = sha1(avalancheMsg1.value);
    const h2 = sha1(avalancheMsg2.value);
    avalancheHash1.textContent = h1;
    avalancheHash2.textContent = h2;

    const diff = computeBitDifferences(h1, h2);
    const percentage = ((diff / 160) * 100).toFixed(1);

    avalancheStatsText.innerHTML = `
      Comparing 160 bits: <strong>${diff} / 160 bits flipped (${percentage}% Diffusion)</strong> &mdash; 
      ${percentage >= 40 && percentage <= 60 ? 'Satisfies the Strict Avalanche Criterion (SAC).' : 'Observation recorded.'}
    `;
  }

  // Preset messages
  const PRESETS = [
    'The quick brown fox jumps over the lazy dog',
    'Cryptography & System Security Lab Manual',
    'Fr. Conceicao Rodrigues College of Engineering',
    'SHA-1 Avalanche Effect Demo'
  ];
  let presetIdx = 0;

  if (computeBtn) {
    computeBtn.addEventListener('click', updateSimulation);
  }

  if (inputMsg) {
    inputMsg.addEventListener('input', updateSimulation);
  }

  if (loadPresetBtn) {
    loadPresetBtn.addEventListener('click', () => {
      if (inputMsg) {
        inputMsg.value = PRESETS[presetIdx % PRESETS.length];
        presetIdx++;
        updateSimulation();
        window.showToast('Sample message loaded.');
      }
    });
  }

  if (copyBtn && outputHex) {
    copyBtn.addEventListener('click', () => {
      if (navigator.clipboard) {
        navigator.clipboard.writeText(outputHex.textContent).then(() => {
          window.showToast('SHA-1 digest copied to clipboard!');
        });
      }
    });
  }

  if (avalancheMsg1 && avalancheMsg2) {
    avalancheMsg1.addEventListener('input', updateAvalanche);
    avalancheMsg2.addEventListener('input', updateAvalanche);
  }

  // ============================================================
  // 3. Concept Quiz Evaluation
  // ============================================================
  if (submitQuizBtn && quizForm) {
    submitQuizBtn.addEventListener('click', () => {
      const cards = quizForm.querySelectorAll('.quiz-card');
      let score = 0;
      let total = cards.length;

      cards.forEach((card, idx) => {
        const correct = card.dataset.correct;
        const selected = card.querySelector(`input[name="q${idx + 1}"]:checked`);
        const labels = card.querySelectorAll('.quiz-option-label');

        labels.forEach((label) => {
          label.classList.remove('correct', 'incorrect');
        });

        if (selected) {
          if (selected.value === correct) {
            score++;
            selected.closest('.quiz-option-label').classList.add('correct');
          } else {
            selected.closest('.quiz-option-label').classList.add('incorrect');
            const correctInput = card.querySelector(`input[value="${correct}"]`);
            if (correctInput) {
              correctInput.closest('.quiz-option-label').classList.add('correct');
            }
          }
        }
      });

      if (quizScoreResult && quizScoreSummary) {
        quizScoreResult.style.display = 'block';
        quizScoreSummary.innerHTML = `You scored <strong>${score} / ${total}</strong> (${Math.round((score / total) * 100)}%). ${score === total ? 'Excellent mastery of SHA-1 concepts!' : 'Review the theory and try again.'}`;
        quizScoreResult.scrollIntoView({ behavior: 'smooth' });
      }
    });
  }

  if (resetQuizBtn && quizForm) {
    resetQuizBtn.addEventListener('click', () => {
      quizForm.reset();
      const labels = quizForm.querySelectorAll('.quiz-option-label');
      labels.forEach((l) => l.classList.remove('correct', 'incorrect'));
      if (quizScoreResult) quizScoreResult.style.display = 'none';
      window.showToast('Quiz reset.');
    });
  }

  // Global reset helper for toolbar reset button
  window.resetSimulation = () => {
    if (inputMsg) inputMsg.value = 'Hello World';
    if (avalancheMsg1) avalancheMsg1.value = 'Hello World';
    if (avalancheMsg2) avalancheMsg2.value = 'Hello world';
    updateSimulation();
    updateAvalanche();
    if (quizForm) quizForm.reset();
    if (quizScoreResult) quizScoreResult.style.display = 'none';
  };

  // Initial calculation on load
  updateSimulation();
  updateAvalanche();
})();
