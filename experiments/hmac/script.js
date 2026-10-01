/**
 * HMAC Authentication and Verification Experiment
 * Virtual Cryptography Laboratory
 * 
 * Uses the standard W3C Web Crypto API (crypto.subtle)
 * Default Algorithm: HMAC-SHA-256
 */

(function () {
  'use strict';

  // --- DOM Elements Cache ---
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  // Generator elements
  const genMessage = document.getElementById('genMessage');
  const genKey = document.getElementById('genKey');
  const genAlgorithm = document.getElementById('genAlgorithm');
  const btnGenerate = document.getElementById('btnGenerate');
  const btnSendToVerify = document.getElementById('btnSendToVerify');
  const btnToggleGenKey = document.getElementById('btnToggleGenKey');
  const generatedHmacDisplay = document.getElementById('generatedHmacDisplay');
  const btnCopyGenerated = document.getElementById('btnCopyGenerated');
  const outputAlgoTag = document.getElementById('outputAlgoTag');
  const hexLenLabel = document.getElementById('hexLenLabel');
  const outCharCount = document.getElementById('outCharCount');
  const outBitLength = document.getElementById('outBitLength');

  // Verifier elements
  const verMessage = document.getElementById('verMessage');
  const verKey = document.getElementById('verKey');
  const verHmac = document.getElementById('verHmac');
  const btnVerify = document.getElementById('btnVerify');
  const btnFillFromGen = document.getElementById('btnFillFromGen');
  const btnToggleVerKey = document.getElementById('btnToggleVerKey');
  const verifyPendingMsg = document.getElementById('verifyPendingMsg');
  const verifySuccessBanner = document.getElementById('verifySuccessBanner');
  const verifyFailureBanner = document.getElementById('verifyFailureBanner');
  const verifySuccessDetails = document.getElementById('verifySuccessDetails');
  const verifyFailureDetails = document.getElementById('verifyFailureDetails');
  const verifyStatusBadge = document.getElementById('verifyStatusBadge');

  // Validation alert
  const validationNotice = document.getElementById('validationNotice');

  // Modification Analysis elements
  const btnTabModMsg = document.getElementById('btnTabModMsg');
  const btnTabModKey = document.getElementById('btnTabModKey');
  const sectionModMsg = document.getElementById('sectionModMsg');
  const sectionModKey = document.getElementById('sectionModKey');

  // Mod Msg elements
  const modOrigMsg = document.getElementById('modOrigMsg');
  const modMsgSharedKey = document.getElementById('modMsgSharedKey');
  const modTamperedMsg = document.getElementById('modTamperedMsg');
  const modOrigMsgHmac = document.getElementById('modOrigMsgHmac');
  const modTamperedMsgHmac = document.getElementById('modTamperedMsgHmac');
  const diffDisplayMsg = document.getElementById('diffDisplayMsg');
  const statMsgHexDiff = document.getElementById('statMsgHexDiff');
  const statMsgBitDiff = document.getElementById('statMsgBitDiff');
  const statMsgAvalanchePct = document.getElementById('statMsgAvalanchePct');
  const statMsgVerdict = document.getElementById('statMsgVerdict');

  // Mod Key elements
  const modKeySharedMsg = document.getElementById('modKeySharedMsg');
  const modOrigKey = document.getElementById('modOrigKey');
  const modTamperedKey = document.getElementById('modTamperedKey');
  const modOrigKeyHmac = document.getElementById('modOrigKeyHmac');
  const modTamperedKeyHmac = document.getElementById('modTamperedKeyHmac');
  const diffDisplayKey = document.getElementById('diffDisplayKey');
  const statKeyHexDiff = document.getElementById('statKeyHexDiff');
  const statKeyBitDiff = document.getElementById('statKeyBitDiff');
  const statKeyAvalanchePct = document.getElementById('statKeyAvalanchePct');
  const statKeyVerdict = document.getElementById('statKeyVerdict');

  // Stepper elements
  const flowSteps = [
    document.getElementById('step1'),
    document.getElementById('step2'),
    document.getElementById('step3'),
    document.getElementById('step4'),
    document.getElementById('step5')
  ];

  // Preset Buttons
  const loadPreset1 = document.getElementById('loadPreset1');
  const loadPreset2 = document.getElementById('loadPreset2');
  const loadPreset3 = document.getElementById('loadPreset3');
  const loadPreset4 = document.getElementById('loadPreset4');
  const loadPresetReset = document.getElementById('loadPresetReset');

  // Quiz Form
  const quizForm = document.getElementById('quizForm');
  const btnResetQuiz = document.getElementById('btnResetQuiz');
  const quizSummaryBox = document.getElementById('quizSummaryBox');
  const quizScoreText = document.getElementById('quizScoreText');
  const quizScoreMessage = document.getElementById('quizScoreMessage');

  // --- Web Crypto Core Functions ---

  /**
   * Generates an HMAC hex digest using the Web Crypto API
   * @param {string} message - Plaintext message
   * @param {string} secretKey - Plaintext secret key
   * @param {string} algorithm - Hash algorithm (SHA-256, SHA-384, SHA-512)
   * @returns {Promise<string>} Hexadecimal HMAC string
   */
  async function computeHmacHex(message, secretKey, algorithm = 'SHA-256') {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error('Web Crypto API is not supported in this browser environment. Ensure HTTPS or localhost is used.');
    }

    const encoder = new TextEncoder();
    const keyData = encoder.encode(secretKey);
    const messageData = encoder.encode(message);

    // Import secret key for HMAC
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyData,
      {
        name: 'HMAC',
        hash: { name: algorithm }
      },
      false,
      ['sign', 'verify']
    );

    // Sign the message data to generate HMAC
    const signatureBuffer = await window.crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      messageData
    );

    // Convert ArrayBuffer to Hex String
    const hashArray = Array.from(new Uint8Array(signatureBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Counts differing bits (Hamming Distance) between two hex strings
   */
  function calculateHammingDistance(hexA, hexB) {
    let diffBits = 0;
    const len = Math.min(hexA.length, hexB.length);
    for (let i = 0; i < len; i += 2) {
      const byteA = parseInt(hexA.substr(i, 2), 16) || 0;
      const byteB = parseInt(hexB.substr(i, 2), 16) || 0;
      let xor = byteA ^ byteB;
      while (xor > 0) {
        diffBits += (xor & 1);
        xor >>= 1;
      }
    }
    return diffBits;
  }

  /**
   * Generates colored character diff between two hex strings
   */
  function generateHexDiffHtml(origHex, newHex) {
    let html = '';
    const maxLen = Math.max(origHex.length, newHex.length);
    for (let i = 0; i < maxLen; i++) {
      const origChar = origHex[i] || '';
      const newChar = newHex[i] || '';
      if (origChar === newChar) {
        html += `<span class="diff-match">${newChar}</span>`;
      } else {
        html += `<span class="diff-mismatch">${newChar || ' '}</span>`;
      }
    }
    return html;
  }

  // --- Stepper Helper ---
  function setFlowStep(stepIndex) {
    flowSteps.forEach((step, idx) => {
      if (step) {
        if (idx <= stepIndex) {
          step.classList.add('active');
        } else {
          step.classList.remove('active');
        }
      }
    });
  }

  // --- Validation Notice Helper ---
  function showValidation(msg) {
    validationNotice.textContent = '⚠️ ' + msg;
    validationNotice.style.display = 'block';
    setTimeout(() => {
      validationNotice.style.display = 'none';
    }, 4500);
  }

  function clearValidation() {
    validationNotice.style.display = 'none';
  }

  // --- Tab Navigation Logic ---
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');

      tabBtns.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');

      const targetPane = document.getElementById('pane' + targetTab.charAt(0).toUpperCase() + targetTab.slice(1));
      if (targetPane) {
        targetPane.classList.add('active');
      }

      // If switching to simulation, refresh analysis
      if (targetTab === 'simulation') {
        updateMessageAnalysis();
        updateKeyAnalysis();
      }
    });
  });

  // Toggle Password Visibility
  btnToggleGenKey.addEventListener('click', () => {
    const isPass = genKey.type === 'password';
    genKey.type = isPass ? 'text' : 'password';
    btnToggleGenKey.textContent = isPass ? 'Hide' : 'Show';
  });

  btnToggleVerKey.addEventListener('click', () => {
    const isPass = verKey.type === 'password';
    verKey.type = isPass ? 'text' : 'password';
    btnToggleVerKey.textContent = isPass ? 'Hide' : 'Show';
  });

  // --- Feature 1: Generate HMAC ---
  async function handleGenerateHmac() {
    clearValidation();
    const msg = genMessage.value;
    const key = genKey.value;
    const algo = genAlgorithm.value;

    if (!key && !msg) {
      showValidation('Test Case 5: Empty input detected. Please provide both message and secret key.');
      return;
    }

    if (!key) {
      showValidation('Secret key cannot be empty. HMAC requires a secret key for authentication.');
      return;
    }

    try {
      btnGenerate.disabled = true;
      btnGenerate.style.opacity = '0.7';

      const hexHmac = await computeHmacHex(msg, key, algo);

      // Render HMAC output
      generatedHmacDisplay.innerHTML = `<span style="color:#7ee787;">${hexHmac}</span>`;
      outCharCount.textContent = hexHmac.length;
      outBitLength.textContent = hexHmac.length * 4;
      outputAlgoTag.textContent = `HMAC-${algo}`;
      hexLenLabel.textContent = `Hexadecimal Digest (${hexHmac.length} chars / ${hexHmac.length * 4} bits)`;

      setFlowStep(2); // Step 3: Output rendered

      // Automatically sync baseline values to modification analysis
      modOrigMsg.value = msg;
      modMsgSharedKey.value = key;
      modKeySharedMsg.value = msg;
      modOrigKey.value = key;

      updateMessageAnalysis();
      updateKeyAnalysis();

    } catch (err) {
      console.error('HMAC Generation Error:', err);
      generatedHmacDisplay.innerHTML = `<span style="color:#ff7b72;">Generation Error: ${err.message}</span>`;
    } finally {
      btnGenerate.disabled = false;
      btnGenerate.style.opacity = '1';
    }
  }

  btnGenerate.addEventListener('click', handleGenerateHmac);

  // Copy Generated HMAC to clipboard
  btnCopyGenerated.addEventListener('click', async () => {
    const text = generatedHmacDisplay.textContent.trim();
    if (!text || text.includes('Click "Generate HMAC"')) {
      showValidation('No HMAC generated yet to copy.');
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      const originalLabel = btnCopyGenerated.textContent;
      btnCopyGenerated.textContent = 'Copied!';
      btnCopyGenerated.style.background = '#2e7d32';
      setTimeout(() => {
        btnCopyGenerated.textContent = originalLabel;
        btnCopyGenerated.style.background = '';
      }, 1600);
    } catch {
      // Fallback
      showValidation('Failed to copy to clipboard.');
    }
  });

  // Transfer generator inputs & output to verification
  btnSendToVerify.addEventListener('click', async () => {
    verMessage.value = genMessage.value;
    verKey.value = genKey.value;
    const generatedText = generatedHmacDisplay.textContent.trim();
    if (!generatedText || generatedText.includes('Click "Generate HMAC"')) {
      // Generate first if not yet done
      await handleGenerateHmac();
    }
    verHmac.value = generatedHmacDisplay.textContent.trim();
    verHmac.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });

  btnFillFromGen.addEventListener('click', () => {
    verMessage.value = genMessage.value;
    verKey.value = genKey.value;
    const generatedText = generatedHmacDisplay.textContent.trim();
    if (generatedText && !generatedText.includes('Click "Generate HMAC"')) {
      verHmac.value = generatedText;
    }
  });

  // --- Feature 2: Verify HMAC ---
  async function handleVerifyHmac() {
    clearValidation();
    const message = verMessage.value;
    const key = verKey.value;
    const suppliedHmac = verHmac.value.trim().toLowerCase();
    const algo = genAlgorithm.value;

    if (!message && !key && !suppliedHmac) {
      showValidation('Verification inputs are empty. Please provide message, secret key, and HMAC.');
      return;
    }

    if (!suppliedHmac) {
      showValidation('Please supply an HMAC value to verify against.');
      return;
    }

    try {
      btnVerify.disabled = true;
      btnVerify.style.opacity = '0.7';

      // Recalculate HMAC strictly using the provided message and secret key
      const recalculatedHmac = (await computeHmacHex(message, key, algo)).toLowerCase();

      verifyPendingMsg.style.display = 'none';

      // Cryptographic comparison:
      const isMatch = (recalculatedHmac === suppliedHmac);

      if (isMatch) {
        verifyFailureBanner.style.display = 'none';
        verifySuccessBanner.style.display = 'flex';
        verifyStatusBadge.textContent = 'Verified ✓';
        verifyStatusBadge.className = 'badge-tag';
        verifyStatusBadge.style.background = 'rgba(63, 185, 80, 0.2)';
        verifyStatusBadge.style.color = '#7ee787';

        verifySuccessDetails.innerHTML = `
          <strong>Recalculated HMAC:</strong> ${recalculatedHmac}<br>
          <strong>Supplied HMAC:</strong> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${suppliedHmac}<br>
          <em>Status: Identical match. Message authenticity and cryptographic integrity confirmed.</em>
        `;
        setFlowStep(4); // Step 5: Verified
      } else {
        verifySuccessBanner.style.display = 'none';
        verifyFailureBanner.style.display = 'flex';
        verifyStatusBadge.textContent = 'Failed ✗';
        verifyStatusBadge.className = 'badge-tag';
        verifyStatusBadge.style.background = 'rgba(248, 81, 73, 0.2)';
        verifyStatusBadge.style.color = '#ff7b72';

        verifyFailureDetails.innerHTML = `
          <strong>Recalculated HMAC:</strong> ${recalculatedHmac}<br>
          <strong>Supplied HMAC:</strong> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${suppliedHmac}<br>
          <em>Mismatch detected! The message content has been altered, or the secret key is invalid.</em>
        `;
        setFlowStep(3); // Tamper detected
      }

    } catch (err) {
      console.error('Verification Error:', err);
      showValidation('Verification process encountered an error: ' + err.message);
    } finally {
      btnVerify.disabled = false;
      btnVerify.style.opacity = '1';
    }
  }

  btnVerify.addEventListener('click', handleVerifyHmac);

  // --- Feature 3 & 4: Modification Analysis ---

  // Tab switching between Section A and Section B
  btnTabModMsg.addEventListener('click', () => {
    btnTabModMsg.classList.add('active');
    btnTabModKey.classList.remove('active');
    sectionModMsg.style.display = 'block';
    sectionModKey.style.display = 'none';
    updateMessageAnalysis();
  });

  btnTabModKey.addEventListener('click', () => {
    btnTabModKey.classList.add('active');
    btnTabModMsg.classList.remove('active');
    sectionModKey.style.display = 'block';
    sectionModMsg.style.display = 'none';
    updateKeyAnalysis();
  });

  // Section A: Update Message Modification Analysis
  async function updateMessageAnalysis() {
    const origMsg = modOrigMsg.value;
    const key = modMsgSharedKey.value;
    const tamperedMsg = modTamperedMsg.value;
    const algo = 'SHA-256';

    try {
      const [origHmac, tamperedHmac] = await Promise.all([
        computeHmacHex(origMsg, key, algo),
        computeHmacHex(tamperedMsg, key, algo)
      ]);

      modOrigMsgHmac.textContent = origHmac;
      modTamperedMsgHmac.textContent = tamperedHmac;

      // Calculate diffs
      let hexDiffCount = 0;
      for (let i = 0; i < origHmac.length; i++) {
        if (origHmac[i] !== tamperedHmac[i]) hexDiffCount++;
      }

      const bitDiff = calculateHammingDistance(origHmac, tamperedHmac);
      const totalBits = origHmac.length * 4;
      const avalanchePct = ((bitDiff / totalBits) * 100).toFixed(1);

      statMsgHexDiff.textContent = `${hexDiffCount} / ${origHmac.length}`;
      statMsgBitDiff.textContent = `${bitDiff} / ${totalBits}`;
      statMsgAvalanchePct.textContent = `${avalanchePct}%`;

      diffDisplayMsg.innerHTML = generateHexDiffHtml(origHmac, tamperedHmac);

      if (origHmac === tamperedHmac) {
        statMsgVerdict.textContent = '✓ Identical (No Tampering)';
        statMsgVerdict.style.background = 'rgba(63, 185, 80, 0.2)';
        statMsgVerdict.style.color = '#7ee787';
      } else {
        statMsgVerdict.textContent = '✗ HMAC Mismatch: Tampering Detected';
        statMsgVerdict.style.background = 'rgba(248, 81, 73, 0.2)';
        statMsgVerdict.style.color = '#ff7b72';
      }
    } catch (err) {
      console.error('Message Analysis Error:', err);
    }
  }

  // Section B: Update Secret Key Modification Analysis
  async function updateKeyAnalysis() {
    const msg = modKeySharedMsg.value;
    const origKey = modOrigKey.value;
    const tamperedKey = modTamperedKey.value;
    const algo = 'SHA-256';

    try {
      const [origHmac, tamperedHmac] = await Promise.all([
        computeHmacHex(msg, origKey, algo),
        computeHmacHex(msg, tamperedKey, algo)
      ]);

      modOrigKeyHmac.textContent = origHmac;
      modTamperedKeyHmac.textContent = tamperedHmac;

      let hexDiffCount = 0;
      for (let i = 0; i < origHmac.length; i++) {
        if (origHmac[i] !== tamperedHmac[i]) hexDiffCount++;
      }

      const bitDiff = calculateHammingDistance(origHmac, tamperedHmac);
      const totalBits = origHmac.length * 4;
      const avalanchePct = ((bitDiff / totalBits) * 100).toFixed(1);

      statKeyHexDiff.textContent = `${hexDiffCount} / ${origHmac.length}`;
      statKeyBitDiff.textContent = `${bitDiff} / ${totalBits}`;
      statKeyAvalanchePct.textContent = `${avalanchePct}%`;

      diffDisplayKey.innerHTML = generateHexDiffHtml(origHmac, tamperedHmac);

      if (origHmac === tamperedHmac) {
        statKeyVerdict.textContent = '✓ Identical (Same Key)';
        statKeyVerdict.style.background = 'rgba(63, 185, 80, 0.2)';
        statKeyVerdict.style.color = '#7ee787';
      } else {
        statKeyVerdict.textContent = '✗ HMAC Mismatch: Key Modification Detected';
        statKeyVerdict.style.background = 'rgba(248, 81, 73, 0.2)';
        statKeyVerdict.style.color = '#ff7b72';
      }
    } catch (err) {
      console.error('Key Analysis Error:', err);
    }
  }

  // Real-time input listeners for Analysis
  modOrigMsg.addEventListener('input', updateMessageAnalysis);
  modMsgSharedKey.addEventListener('input', updateMessageAnalysis);
  modTamperedMsg.addEventListener('input', updateMessageAnalysis);

  modKeySharedMsg.addEventListener('input', updateKeyAnalysis);
  modOrigKey.addEventListener('input', updateKeyAnalysis);
  modTamperedKey.addEventListener('input', updateKeyAnalysis);

  // Quick Alteration Chips for Message
  document.getElementById('quickModMsgCase').addEventListener('click', () => {
    modTamperedMsg.value = 'Hello world';
    updateMessageAnalysis();
  });
  document.getElementById('quickModMsgExcl').addEventListener('click', () => {
    modTamperedMsg.value = 'Hello World!';
    updateMessageAnalysis();
  });
  document.getElementById('quickModMsgSpace').addEventListener('click', () => {
    modTamperedMsg.value = 'Hello World ';
    updateMessageAnalysis();
  });

  // Quick Alteration Chips for Key
  document.getElementById('quickModKeyUpper').addEventListener('click', () => {
    modTamperedKey.value = 'mysecretKey';
    updateKeyAnalysis();
  });
  document.getElementById('quickModKeyAppend').addEventListener('click', () => {
    modTamperedKey.value = 'mysecretkey123';
    updateKeyAnalysis();
  });
  document.getElementById('quickModKeyWrong').addEventListener('click', () => {
    modTamperedKey.value = 'wrongkey';
    updateKeyAnalysis();
  });

  // --- Preset Test Cases ---
  loadPreset1.addEventListener('click', async () => {
    // Normal Verification
    genMessage.value = 'Hello World';
    genKey.value = 'mysecretkey';
    genAlgorithm.value = 'SHA-256';
    await handleGenerateHmac();

    verMessage.value = 'Hello World';
    verKey.value = 'mysecretkey';
    verHmac.value = generatedHmacDisplay.textContent.trim();
    await handleVerifyHmac();
  });

  loadPreset2.addEventListener('click', async () => {
    // Modified Message
    genMessage.value = 'Hello World';
    genKey.value = 'mysecretkey';
    genAlgorithm.value = 'SHA-256';
    await handleGenerateHmac();

    verMessage.value = 'Hello World!'; // Note the exclamation mark
    verKey.value = 'mysecretkey';
    verHmac.value = generatedHmacDisplay.textContent.trim();
    await handleVerifyHmac();

    // Switch to analysis tab
    btnTabModMsg.click();
    modOrigMsg.value = 'Hello World';
    modTamperedMsg.value = 'Hello World!';
    updateMessageAnalysis();
  });

  loadPreset3.addEventListener('click', async () => {
    // Modified Key
    genMessage.value = 'Hello World';
    genKey.value = 'mysecretkey';
    genAlgorithm.value = 'SHA-256';
    await handleGenerateHmac();

    verMessage.value = 'Hello World';
    verKey.value = 'mysecretKey'; // Note capital K
    verHmac.value = generatedHmacDisplay.textContent.trim();
    await handleVerifyHmac();

    btnTabModKey.click();
    modOrigKey.value = 'mysecretkey';
    modTamperedKey.value = 'mysecretKey';
    updateKeyAnalysis();
  });

  loadPreset4.addEventListener('click', async () => {
    // Corrupted HMAC
    genMessage.value = 'Hello World';
    genKey.value = 'mysecretkey';
    genAlgorithm.value = 'SHA-256';
    await handleGenerateHmac();

    verMessage.value = 'Hello World';
    verKey.value = 'mysecretkey';
    // Deliberately corrupt the first 4 characters of the HMAC
    const realHmac = generatedHmacDisplay.textContent.trim();
    const badHmac = 'ffff' + realHmac.substring(4);
    verHmac.value = badHmac;
    await handleVerifyHmac();
  });

  loadPresetReset.addEventListener('click', () => {
    genMessage.value = 'Hello World';
    genKey.value = 'mysecretkey';
    verMessage.value = 'Hello World';
    verKey.value = 'mysecretkey';
    verHmac.value = '';
    generatedHmacDisplay.innerHTML = '<span class="hex-placeholder">Click "Generate HMAC" above to produce the authentication code...</span>';
    outCharCount.textContent = '0';
    outBitLength.textContent = '0';
    verifyPendingMsg.style.display = 'block';
    verifySuccessBanner.style.display = 'none';
    verifyFailureBanner.style.display = 'none';
    verifyStatusBadge.textContent = 'Pending';
    verifyStatusBadge.className = 'badge-tag';
    verifyStatusBadge.style.background = '#33261f';
    verifyStatusBadge.style.color = '#a89587';
    setFlowStep(0);
  });

  // --- Interactive Quiz Logic ---
  const quizAnswers = {
    q1: { correct: 'B', explanation: 'HMAC primarily provides message authentication and integrity verification using a symmetric secret key.' },
    q2: { correct: 'B', explanation: 'HMAC requires a plaintext message and a shared secret key.' },
    q3: { correct: 'B', explanation: 'Any change in the message alters the recalculated HMAC, causing verification to fail.' },
    q4: { correct: 'C', explanation: 'HMAC-SHA-256 is the standard default algorithm used throughout this lab.' },
    q5: { correct: 'B', explanation: 'If the secret key does not match the key used to generate the HMAC, verification fails.' },
    q6: { correct: 'C', explanation: 'Naive concatenation Hash(Key || Message) suffers from Length Extension Attacks; HMAC prevents this with its nested inner/outer hash structure.' }
  };

  quizForm.addEventListener('submit', (e) => {
    e.preventDefault();
    let score = 0;
    const total = Object.keys(quizAnswers).length;

    for (let qKey in quizAnswers) {
      const qNum = qKey.replace('q', '');
      const card = document.querySelector(`.quiz-question-card[data-q="${qNum}"]`);
      const selected = document.querySelector(`input[name="${qKey}"]:checked`);
      const feedback = document.getElementById(`feedbackQ${qNum}`);
      const options = card.querySelectorAll('.quiz-option');

      // Clear previous styles
      options.forEach(opt => {
        opt.classList.remove('correct', 'incorrect');
      });

      if (!selected) {
        feedback.className = 'quiz-feedback show-incorrect';
        feedback.textContent = 'Please select an answer for this question.';
        continue;
      }

      const val = selected.value;
      const isCorrect = (val === quizAnswers[qKey].correct);

      // Highlight options
      options.forEach(opt => {
        const radio = opt.querySelector('input');
        if (radio.value === quizAnswers[qKey].correct) {
          opt.classList.add('correct');
        } else if (radio.checked && !isCorrect) {
          opt.classList.add('incorrect');
        }
      });

      if (isCorrect) {
        score++;
        feedback.className = 'quiz-feedback show-correct';
        feedback.innerHTML = `<strong>Correct!</strong> ${quizAnswers[qKey].explanation}`;
      } else {
        feedback.className = 'quiz-feedback show-incorrect';
        feedback.innerHTML = `<strong>Incorrect.</strong> (Correct Answer: ${quizAnswers[qKey].correct}) ${quizAnswers[qKey].explanation}`;
      }
    }

    // Show summary box
    quizSummaryBox.style.display = 'block';
    quizScoreText.textContent = `${score} / ${total}`;

    const pct = (score / total) * 100;
    if (pct === 100) {
      quizScoreMessage.innerHTML = '<span style="color:#7ee787;">Outstanding! You have mastered HMAC principles and integrity verification.</span>';
    } else if (pct >= 60) {
      quizScoreMessage.innerHTML = '<span style="color:#60a5fa;">Good job! Review the Theory tab to clear up any missed concepts.</span>';
    } else {
      quizScoreMessage.innerHTML = '<span style="color:#fcd34d;">Keep practicing! Explore the Modification Analysis to see HMAC in action.</span>';
    }

    quizSummaryBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });

  btnResetQuiz.addEventListener('click', () => {
    quizForm.reset();
    document.querySelectorAll('.quiz-option').forEach(opt => {
      opt.classList.remove('correct', 'incorrect');
    });
    document.querySelectorAll('.quiz-feedback').forEach(fb => {
      fb.className = 'quiz-feedback';
      fb.style.display = 'none';
      fb.textContent = '';
    });
    quizSummaryBox.style.display = 'none';
  });

  // --- Initial Page Setup ---
  window.addEventListener('DOMContentLoaded', () => {
    handleGenerateHmac();
    updateMessageAnalysis();
    updateKeyAnalysis();
  });

})();
