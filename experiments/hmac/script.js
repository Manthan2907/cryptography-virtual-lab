/**
 * HMAC Authentication and Verification Experiment (EXP-HMAC)
 * Virtual Cryptography Laboratory
 * 
 * Features:
 * 1. Full Authenticated Pipeline (Encrypt-then-MAC: AES-256-CBC + HMAC-SHA-256 with Plaintext Decryption)
 * 2. In-Transit Network Channel & Attacker Simulator (Tamper Ciphertext, HMAC, Key)
 * 3. Standard RFC 2104 Keyed-Hash Message Authentication & Verification
 * 4. Modification Analysis (Hamming distance, Avalanche effect, Character-by-character diff)
 * 5. Educational Explainer on why HMAC is one-way and cannot be decrypted
 * 6. Interactive Self-Assessment Quiz
 * 
 * Cryptographic API: Standard W3C Web Crypto API (crypto.subtle)
 */

(function () {
  'use strict';

  // =========================================================================
  // 1. DOM Elements Cache
  // =========================================================================
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  // Mode Switcher Elements
  const btnModeEncryptMac = document.getElementById('btnModeEncryptMac');
  const btnModeHmacOnly = document.getElementById('btnModeHmacOnly');
  const panelEncryptMac = document.getElementById('panelEncryptMac');
  const panelHmacOnly = document.getElementById('panelHmacOnly');
  const outPanelEncryptMac = document.getElementById('outPanelEncryptMac');
  const outPanelHmacOnly = document.getElementById('outPanelHmacOnly');

  // Pipeline (Encrypt-then-MAC) - Sender
  const pipeMessage = document.getElementById('pipeMessage');
  const pipeKey = document.getElementById('pipeKey');
  const pipeCipher = document.getElementById('pipeCipher');
  const pipeHash = document.getElementById('pipeHash');
  const btnPipeEncrypt = document.getElementById('btnPipeEncrypt');
  const btnPipeTransmit = document.getElementById('btnPipeTransmit');
  const btnTogglePipeKey = document.getElementById('btnTogglePipeKey');

  // Pipeline - In-Transit Channel
  const channelStatusBadge = document.getElementById('channelStatusBadge');
  const packetIvDisplay = document.getElementById('packetIvDisplay');
  const packetCtDisplay = document.getElementById('packetCtDisplay');
  const packetHmacDisplay = document.getElementById('packetHmacDisplay');
  const btnChannelClean = document.getElementById('btnChannelClean');
  const btnChannelTamperCt = document.getElementById('btnChannelTamperCt');
  const btnChannelTamperHmac = document.getElementById('btnChannelTamperHmac');
  const btnChannelTamperKey = document.getElementById('btnChannelTamperKey');

  // Pipeline - Receiver
  const pipeRxCiphertext = document.getElementById('pipeRxCiphertext');
  const pipeRxIv = document.getElementById('pipeRxIv');
  const pipeRxKey = document.getElementById('pipeRxKey');
  const pipeRxHmac = document.getElementById('pipeRxHmac');
  const btnPipeVerifyDecrypt = document.getElementById('btnPipeVerifyDecrypt');
  const btnPipeForceDecrypt = document.getElementById('btnPipeForceDecrypt');
  const btnPipeCopySender = document.getElementById('btnPipeCopySender');
  const btnTogglePipeRxKey = document.getElementById('btnTogglePipeRxKey');

  // Pipeline - Outputs
  const pipeSenderAlgoTag = document.getElementById('pipeSenderAlgoTag');
  const pipeCiphertextDisplay = document.getElementById('pipeCiphertextDisplay');
  const pipeIvDisplay = document.getElementById('pipeIvDisplay');
  const pipeHmacDisplay = document.getElementById('pipeHmacDisplay');
  const pipeCtLen = document.getElementById('pipeCtLen');
  const pipeHmacLen = document.getElementById('pipeHmacLen');
  const btnCopyPipeCt = document.getElementById('btnCopyPipeCt');
  const btnCopyPipeIv = document.getElementById('btnCopyPipeIv');
  const btnCopyPipeHmac = document.getElementById('btnCopyPipeHmac');

  const pipeRxStatusBadge = document.getElementById('pipeRxStatusBadge');
  const pipeRxPendingMsg = document.getElementById('pipeRxPendingMsg');
  const pipeHmacSuccessBanner = document.getElementById('pipeHmacSuccessBanner');
  const pipeHmacSuccessDetails = document.getElementById('pipeHmacSuccessDetails');
  const pipeHmacFailureBanner = document.getElementById('pipeHmacFailureBanner');
  const pipeHmacFailureDetails = document.getElementById('pipeHmacFailureDetails');
  const pipeDecryptedSuccessBox = document.getElementById('pipeDecryptedSuccessBox');
  const pipeDecryptedTextDisplay = document.getElementById('pipeDecryptedTextDisplay');
  const btnCopyDecrypted = document.getElementById('btnCopyDecrypted');
  const pipeDecryptedAbortedBox = document.getElementById('pipeDecryptedAbortedBox');
  const pipeForcedDecryptBox = document.getElementById('pipeForcedDecryptBox');
  const pipeForcedDecryptErrorMsg = document.getElementById('pipeForcedDecryptErrorMsg');

  // Standard Mode - Generator Elements
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

  // Standard Mode - Verifier Elements
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

  // Educational Explainer
  const btnAttemptHmacDecrypt = document.getElementById('btnAttemptHmacDecrypt');
  const hmacDecryptResult = document.getElementById('hmacDecryptResult');
  const btnSwitchToPipelineFromExp = document.getElementById('btnSwitchToPipelineFromExp');

  // Validation Alert
  const validationNotice = document.getElementById('validationNotice');

  // Modification Analysis Elements
  const btnTabModMsg = document.getElementById('btnTabModMsg');
  const btnTabModKey = document.getElementById('btnTabModKey');
  const sectionModMsg = document.getElementById('sectionModMsg');
  const sectionModKey = document.getElementById('sectionModKey');

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

  // Flow Stepper
  const flowSteps = [
    document.getElementById('step1'),
    document.getElementById('step2'),
    document.getElementById('step3'),
    document.getElementById('step4'),
    document.getElementById('step5')
  ];

  // Presets
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

  // Active state tracker
  let activeSimulationMode = 'encryptMac'; // 'encryptMac' or 'hmacOnly'

  // =========================================================================
  // 2. Cryptographic Helper Functions (Web Crypto API)
  // =========================================================================

  function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function hexToBuffer(hex) {
    const cleanHex = hex.trim().replace(/\s+/g, '');
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16) || 0;
    }
    return bytes;
  }

  function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  function base64ToBuffer(base64) {
    const binary = window.atob(base64.trim());
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Derives a 256-bit AES-CBC CryptoKey from a passphrase using SHA-256
   */
  async function deriveAesKey(passphrase) {
    const encoder = new TextEncoder();
    const keyHash = await window.crypto.subtle.digest('SHA-256', encoder.encode(passphrase));
    return await window.crypto.subtle.importKey(
      'raw',
      keyHash,
      { name: 'AES-CBC' },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Derives an HMAC CryptoKey from a passphrase
   */
  async function deriveHmacKey(passphrase, hashAlgo = 'SHA-256') {
    const encoder = new TextEncoder();
    return await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      {
        name: 'HMAC',
        hash: { name: hashAlgo }
      },
      false,
      ['sign', 'verify']
    );
  }

  /**
   * Encrypts plaintext message with AES-256-CBC
   */
  async function encryptAesCbc(plaintext, aesKey) {
    const encoder = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      aesKey,
      encoder.encode(plaintext)
    );
    return {
      iv,
      ivHex: bufferToHex(iv),
      ciphertextBuffer,
      ciphertextBase64: bufferToBase64(ciphertextBuffer)
    };
  }

  /**
   * Decrypts AES-256-CBC ciphertext buffer using IV and AES key
   */
  async function decryptAesCbc(ciphertextBuffer, iv, aesKey) {
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      aesKey,
      ciphertextBuffer
    );
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  }

  /**
   * Computes HMAC over concatenated IV + Ciphertext (Encrypt-then-MAC standard)
   */
  async function computeHmacOverPayload(ivBytes, ciphertextBytes, hmacKey) {
    const combined = new Uint8Array(ivBytes.byteLength + ciphertextBytes.byteLength);
    combined.set(new Uint8Array(ivBytes), 0);
    combined.set(new Uint8Array(ciphertextBytes), ivBytes.byteLength);

    const signature = await window.crypto.subtle.sign(
      'HMAC',
      hmacKey,
      combined
    );
    return bufferToHex(signature);
  }

  /**
   * Standard HMAC generation over string data
   */
  async function computeHmacHex(message, secretKey, algorithm = 'SHA-256') {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secretKey);
    const messageData = encoder.encode(message);

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

    const signatureBuffer = await window.crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      messageData
    );

    return bufferToHex(signatureBuffer);
  }

  /**
   * Calculates Hamming Distance (differing bits) between two hex strings
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
   * Generates colored character diff HTML
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

  // =========================================================================
  // 3. UI Helpers
  // =========================================================================

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

  function showValidation(msg) {
    if (!validationNotice) return;
    validationNotice.textContent = '⚠️ ' + msg;
    validationNotice.style.display = 'block';
    setTimeout(() => {
      if (validationNotice) validationNotice.style.display = 'none';
    }, 4500);
  }

  function clearValidation() {
    if (validationNotice) validationNotice.style.display = 'none';
  }

  // =========================================================================
  // 4. Mode Switcher (Full Pipeline vs Standard HMAC)
  // =========================================================================

  function switchSimulationMode(mode) {
    activeSimulationMode = mode;
    if (mode === 'encryptMac') {
      btnModeEncryptMac.classList.add('active');
      btnModeHmacOnly.classList.remove('active');
      panelEncryptMac.style.display = 'block';
      panelHmacOnly.style.display = 'none';
      outPanelEncryptMac.style.display = 'block';
      outPanelHmacOnly.style.display = 'none';
    } else {
      btnModeHmacOnly.classList.add('active');
      btnModeEncryptMac.classList.remove('active');
      panelHmacOnly.style.display = 'block';
      panelEncryptMac.style.display = 'none';
      outPanelHmacOnly.style.display = 'block';
      outPanelEncryptMac.style.display = 'none';
    }
  }

  if (btnModeEncryptMac) {
    btnModeEncryptMac.addEventListener('click', () => switchSimulationMode('encryptMac'));
  }
  if (btnModeHmacOnly) {
    btnModeHmacOnly.addEventListener('click', () => switchSimulationMode('hmacOnly'));
  }

  if (btnSwitchToPipelineFromExp) {
    btnSwitchToPipelineFromExp.addEventListener('click', () => {
      switchSimulationMode('encryptMac');
      window.scrollTo({ top: panelEncryptMac.offsetTop - 100, behavior: 'smooth' });
    });
  }

  // Password Visibility Toggles
  if (btnTogglePipeKey) {
    btnTogglePipeKey.addEventListener('click', () => {
      const isPass = pipeKey.type === 'password';
      pipeKey.type = isPass ? 'text' : 'password';
      btnTogglePipeKey.textContent = isPass ? 'Hide' : 'Show';
    });
  }

  if (btnTogglePipeRxKey) {
    btnTogglePipeRxKey.addEventListener('click', () => {
      const isPass = pipeRxKey.type === 'password';
      pipeRxKey.type = isPass ? 'text' : 'password';
      btnTogglePipeRxKey.textContent = isPass ? 'Hide' : 'Show';
    });
  }

  if (btnToggleGenKey) {
    btnToggleGenKey.addEventListener('click', () => {
      const isPass = genKey.type === 'password';
      genKey.type = isPass ? 'text' : 'password';
      btnToggleGenKey.textContent = isPass ? 'Hide' : 'Show';
    });
  }

  if (btnToggleVerKey) {
    btnToggleVerKey.addEventListener('click', () => {
      const isPass = verKey.type === 'password';
      verKey.type = isPass ? 'text' : 'password';
      btnToggleVerKey.textContent = isPass ? 'Hide' : 'Show';
    });
  }

  // =========================================================================
  // 5. Full Pipeline: Encrypt-then-MAC Implementation
  // =========================================================================

  let currentPipelinePackage = {
    plaintext: '',
    key: '',
    hashAlgo: 'SHA-256',
    iv: null,
    ivHex: '',
    ciphertextBuffer: null,
    ciphertextBase64: '',
    hmacHex: ''
  };

  let activeChannelTamper = 'clean'; // 'clean', 'tamper_ct', 'tamper_hmac', 'tamper_key'

  async function handlePipeEncrypt() {
    clearValidation();
    const msg = pipeMessage.value;
    const key = pipeKey.value;
    const hashAlgo = pipeHash.value;

    if (!key && !msg) {
      showValidation('Please provide both message plaintext and secret key.');
      return;
    }

    if (!key) {
      showValidation('Secret key cannot be empty.');
      return;
    }

    try {
      btnPipeEncrypt.disabled = true;
      btnPipeEncrypt.style.opacity = '0.7';

      // 1. Derive AES key and HMAC key
      const aesKey = await deriveAesKey(key);
      const hmacKey = await deriveHmacKey(key, hashAlgo);

      // 2. Encrypt with AES-256-CBC
      const encResult = await encryptAesCbc(msg, aesKey);

      // 3. Compute HMAC over (IV + Ciphertext)
      const hmacHex = await computeHmacOverPayload(encResult.iv, encResult.ciphertextBuffer, hmacKey);

      currentPipelinePackage = {
        plaintext: msg,
        key: key,
        hashAlgo: hashAlgo,
        iv: encResult.iv,
        ivHex: encResult.ivHex,
        ciphertextBuffer: encResult.ciphertextBuffer,
        ciphertextBase64: encResult.ciphertextBase64,
        hmacHex: hmacHex
      };

      // 4. Update Sender Output UI
      pipeSenderAlgoTag.textContent = `AES-256-CBC + HMAC-${hashAlgo}`;
      pipeCiphertextDisplay.textContent = encResult.ciphertextBase64;
      pipeIvDisplay.textContent = encResult.ivHex;
      pipeHmacDisplay.textContent = hmacHex;
      pipeCtLen.textContent = encResult.ciphertextBuffer.byteLength;
      pipeHmacLen.textContent = hmacHex.length;

      // 5. Update Channel packet display and sync to receiver
      updateChannelDisplay();
      applyChannelToReceiver();

      // Reset Receiver Output displays to pending until verified
      resetPipeReceiverOutput();

      setFlowStep(2); // Output ready

      // Also sync to modification analysis baseline
      modOrigMsg.value = msg;
      modMsgSharedKey.value = key;
      modKeySharedMsg.value = msg;
      modOrigKey.value = key;
      updateMessageAnalysis();
      updateKeyAnalysis();

    } catch (err) {
      console.error('Pipe Encrypt Error:', err);
      showValidation('Encryption failed: ' + err.message);
    } finally {
      btnPipeEncrypt.disabled = false;
      btnPipeEncrypt.style.opacity = '1';
    }
  }

  function updateChannelDisplay() {
    packetIvDisplay.textContent = currentPipelinePackage.ivHex || '-';
    packetCtDisplay.textContent = currentPipelinePackage.ciphertextBase64 || '-';
    packetHmacDisplay.textContent = currentPipelinePackage.hmacHex || '-';
  }

  function setChannelTamper(mode) {
    activeChannelTamper = mode;

    [btnChannelClean, btnChannelTamperCt, btnChannelTamperHmac, btnChannelTamperKey].forEach(b => {
      if (b) b.classList.remove('chip-active');
    });

    if (mode === 'clean') {
      if (btnChannelClean) btnChannelClean.classList.add('chip-active');
      channelStatusBadge.className = 'badge-tag badge-green';
      channelStatusBadge.textContent = 'Status: Clean (No Tampering)';
    } else if (mode === 'tamper_ct') {
      if (btnChannelTamperCt) btnChannelTamperCt.classList.add('chip-active');
      channelStatusBadge.className = 'badge-tag badge-amber';
      channelStatusBadge.textContent = 'Status: ⚠️ Ciphertext Tampered';
    } else if (mode === 'tamper_hmac') {
      if (btnChannelTamperHmac) btnChannelTamperHmac.classList.add('chip-active');
      channelStatusBadge.className = 'badge-tag badge-amber';
      channelStatusBadge.textContent = 'Status: ⚠️ HMAC Tag Tampered';
    } else if (mode === 'tamper_key') {
      if (btnChannelTamperKey) btnChannelTamperKey.classList.add('chip-active');
      channelStatusBadge.className = 'badge-tag badge-amber';
      channelStatusBadge.textContent = 'Status: ⚠️ Wrong Receiver Key';
    }

    applyChannelToReceiver();
  }

  function applyChannelToReceiver() {
    if (!currentPipelinePackage.ciphertextBase64) return;

    pipeRxIv.value = currentPipelinePackage.ivHex;

    if (activeChannelTamper === 'clean') {
      pipeRxCiphertext.value = currentPipelinePackage.ciphertextBase64;
      pipeRxHmac.value = currentPipelinePackage.hmacHex;
      pipeRxKey.value = currentPipelinePackage.key;
    } else if (activeChannelTamper === 'tamper_ct') {
      const orig = currentPipelinePackage.ciphertextBase64;
      // Change the first character in base64
      const firstChar = orig.charAt(0);
      const flipped = (firstChar === 'A' ? 'B' : 'A');
      pipeRxCiphertext.value = flipped + orig.slice(1);
      pipeRxHmac.value = currentPipelinePackage.hmacHex;
      pipeRxKey.value = currentPipelinePackage.key;
    } else if (activeChannelTamper === 'tamper_hmac') {
      pipeRxCiphertext.value = currentPipelinePackage.ciphertextBase64;
      const orig = currentPipelinePackage.hmacHex;
      // Corrupt first 4 hex nibbles
      const corrupted = (orig.startsWith('ffff') ? '0000' : 'ffff') + orig.slice(4);
      pipeRxHmac.value = corrupted;
      pipeRxKey.value = currentPipelinePackage.key;
    } else if (activeChannelTamper === 'tamper_key') {
      pipeRxCiphertext.value = currentPipelinePackage.ciphertextBase64;
      pipeRxHmac.value = currentPipelinePackage.hmacHex;
      pipeRxKey.value = currentPipelinePackage.key + '_wrong';
    }
  }

  function resetPipeReceiverOutput() {
    pipeRxPendingMsg.style.display = 'block';
    pipeHmacSuccessBanner.style.display = 'none';
    pipeHmacFailureBanner.style.display = 'none';
    pipeDecryptedSuccessBox.style.display = 'none';
    pipeDecryptedAbortedBox.style.display = 'none';
    pipeForcedDecryptBox.style.display = 'none';
    pipeRxStatusBadge.textContent = 'Pending';
    pipeRxStatusBadge.className = 'badge-tag';
    pipeRxStatusBadge.style.background = '#33261f';
    pipeRxStatusBadge.style.color = '#a89587';
  }

  async function handlePipeVerifyAndDecrypt() {
    clearValidation();
    const rxCtBase64 = pipeRxCiphertext.value.trim();
    const rxIvHex = pipeRxIv.value.trim();
    const rxKey = pipeRxKey.value;
    const rxHmac = pipeRxHmac.value.trim().toLowerCase();
    const hashAlgo = pipeHash.value;

    if (!rxCtBase64 || !rxIvHex || !rxHmac || !rxKey) {
      showValidation('Please ensure Received Ciphertext, IV, Secret Key, and HMAC are all provided.');
      return;
    }

    try {
      btnPipeVerifyDecrypt.disabled = true;
      btnPipeVerifyDecrypt.style.opacity = '0.7';

      pipeRxPendingMsg.style.display = 'none';
      pipeForcedDecryptBox.style.display = 'none';

      // Parse binary IV and Ciphertext
      const rxIvBytes = hexToBuffer(rxIvHex);
      const rxCtBuffer = base64ToBuffer(rxCtBase64);

      // 1. Recalculate HMAC over (rxIv + rxCt) using receiver's key
      const hmacKey = await deriveHmacKey(rxKey, hashAlgo);
      const recalculatedHmac = (await computeHmacOverPayload(rxIvBytes, rxCtBuffer, hmacKey)).toLowerCase();

      const isHmacValid = (recalculatedHmac === rxHmac);

      if (isHmacValid) {
        // Step 1: Valid HMAC Tag
        pipeHmacFailureBanner.style.display = 'none';
        pipeHmacSuccessBanner.style.display = 'flex';
        pipeHmacSuccessDetails.innerHTML = `
          <strong>Recalculated HMAC:</strong> ${recalculatedHmac}<br>
          <strong>Supplied HMAC:</strong> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${rxHmac}<br>
          <em>Status: Tag Match confirmed. Ciphertext integrity and authenticity are valid!</em>
        `;

        // Step 2: Decrypt Ciphertext back to Plaintext
        const aesKey = await deriveAesKey(rxKey);
        const decryptedPlaintext = await decryptAesCbc(rxCtBuffer, rxIvBytes, aesKey);

        pipeDecryptedAbortedBox.style.display = 'none';
        pipeDecryptedSuccessBox.style.display = 'block';
        pipeDecryptedTextDisplay.textContent = decryptedPlaintext;

        pipeRxStatusBadge.textContent = 'Verified & Decrypted ✓';
        pipeRxStatusBadge.className = 'badge-tag';
        pipeRxStatusBadge.style.background = 'rgba(63, 185, 80, 0.2)';
        pipeRxStatusBadge.style.color = '#7ee787';

        setFlowStep(4); // Verified & Decrypted
      } else {
        // Step 1: HMAC Failure -> ABORT DECRYPTION
        pipeHmacSuccessBanner.style.display = 'none';
        pipeHmacFailureBanner.style.display = 'flex';
        pipeHmacFailureDetails.innerHTML = `
          <strong>Recalculated HMAC:</strong> ${recalculatedHmac}<br>
          <strong>Supplied HMAC:</strong> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;${rxHmac}<br>
          <em>Mismatch detected! In-transit tampering or unauthorized key identified.</em>
        `;

        // Security gate prevents decryption
        pipeDecryptedSuccessBox.style.display = 'none';
        pipeDecryptedAbortedBox.style.display = 'flex';

        pipeRxStatusBadge.textContent = 'Integrity Failed ✗';
        pipeRxStatusBadge.className = 'badge-tag';
        pipeRxStatusBadge.style.background = 'rgba(248, 81, 73, 0.2)';
        pipeRxStatusBadge.style.color = '#ff7b72';

        setFlowStep(3); // Tamper detected
      }

    } catch (err) {
      console.error('Verify & Decrypt Error:', err);
      showValidation('Verification or decryption error: ' + err.message);
    } finally {
      btnPipeVerifyDecrypt.disabled = false;
      btnPipeVerifyDecrypt.style.opacity = '1';
    }
  }

  async function handlePipeForceDecrypt() {
    clearValidation();
    const rxCtBase64 = pipeRxCiphertext.value.trim();
    const rxIvHex = pipeRxIv.value.trim();
    const rxKey = pipeRxKey.value;

    if (!rxCtBase64 || !rxIvHex || !rxKey) {
      showValidation('Received Ciphertext, IV, and Key required for forced decryption.');
      return;
    }

    try {
      const rxIvBytes = hexToBuffer(rxIvHex);
      const rxCtBuffer = base64ToBuffer(rxCtBase64);
      const aesKey = await deriveAesKey(rxKey);

      const decrypted = await decryptAesCbc(rxCtBuffer, rxIvBytes, aesKey);
      pipeForcedDecryptBox.style.display = 'flex';
      pipeForcedDecryptErrorMsg.innerHTML = `<strong>Decrypted (Corrupted Text):</strong> "${decrypted}"`;
    } catch (err) {
      pipeForcedDecryptBox.style.display = 'flex';
      pipeForcedDecryptErrorMsg.innerHTML = `<strong>Cryptographic Decryption Error:</strong> ${err.message} (PKCS#7 padding validation failed because ciphertext was altered without valid HMAC!)`;
    }
  }

  // Pipeline Button Listeners
  if (btnPipeEncrypt) btnPipeEncrypt.addEventListener('click', handlePipeEncrypt);
  if (btnPipeVerifyDecrypt) btnPipeVerifyDecrypt.addEventListener('click', handlePipeVerifyAndDecrypt);
  if (btnPipeForceDecrypt) btnPipeForceDecrypt.addEventListener('click', handlePipeForceDecrypt);

  if (btnPipeTransmit) {
    btnPipeTransmit.addEventListener('click', async () => {
      if (!currentPipelinePackage.ciphertextBase64) {
        await handlePipeEncrypt();
      }
      setChannelTamper('clean');
      const channelElem = document.querySelector('.channel-card');
      if (channelElem) channelElem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  }

  if (btnPipeCopySender) {
    btnPipeCopySender.addEventListener('click', () => {
      setChannelTamper('clean');
    });
  }

  // Channel Attack Simulation Buttons
  if (btnChannelClean) btnChannelClean.addEventListener('click', () => setChannelTamper('clean'));
  if (btnChannelTamperCt) btnChannelTamperCt.addEventListener('click', () => setChannelTamper('tamper_ct'));
  if (btnChannelTamperHmac) btnChannelTamperHmac.addEventListener('click', () => setChannelTamper('tamper_hmac'));
  if (btnChannelTamperKey) btnChannelTamperKey.addEventListener('click', () => setChannelTamper('tamper_key'));

  // Copy Buttons for Pipeline
  function setupCopyButton(btn, textGetter) {
    if (!btn) return;
    btn.addEventListener('click', async () => {
      const text = textGetter();
      if (!text || text === '-' || text.includes('Click "Encrypt')) {
        showValidation('Nothing to copy yet.');
        return;
      }
      try {
        await navigator.clipboard.writeText(text);
        const originalLabel = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.background = '#2e7d32';
        setTimeout(() => {
          btn.textContent = originalLabel;
          btn.style.background = '';
        }, 1600);
      } catch {
        showValidation('Failed to copy to clipboard.');
      }
    });
  }

  setupCopyButton(btnCopyPipeCt, () => pipeCiphertextDisplay.textContent.trim());
  setupCopyButton(btnCopyPipeIv, () => pipeIvDisplay.textContent.trim());
  setupCopyButton(btnCopyPipeHmac, () => pipeHmacDisplay.textContent.trim());
  setupCopyButton(btnCopyDecrypted, () => pipeDecryptedTextDisplay.textContent.trim());

  // =========================================================================
  // 6. Standard HMAC Mode (RFC 2104) Implementation
  // =========================================================================

  async function handleGenerateHmac() {
    clearValidation();
    const msg = genMessage.value;
    const key = genKey.value;
    const algo = genAlgorithm.value;

    if (!key && !msg) {
      showValidation('Please provide both message and secret key.');
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

      generatedHmacDisplay.innerHTML = `<span style="color:#7ee787;">${hexHmac}</span>`;
      outCharCount.textContent = hexHmac.length;
      outBitLength.textContent = hexHmac.length * 4;
      outputAlgoTag.textContent = `HMAC-${algo}`;
      hexLenLabel.textContent = `Hexadecimal Digest (${hexHmac.length} chars / ${hexHmac.length * 4} bits)`;

      setFlowStep(2);

      // Sync baseline to modification analysis
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

  if (btnGenerate) btnGenerate.addEventListener('click', handleGenerateHmac);

  setupCopyButton(btnCopyGenerated, () => generatedHmacDisplay.textContent.trim());

  if (btnSendToVerify) {
    btnSendToVerify.addEventListener('click', async () => {
      verMessage.value = genMessage.value;
      verKey.value = genKey.value;
      const generatedText = generatedHmacDisplay.textContent.trim();
      if (!generatedText || generatedText.includes('Click "Generate HMAC"')) {
        await handleGenerateHmac();
      }
      verHmac.value = generatedHmacDisplay.textContent.trim();
      verHmac.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  }

  if (btnFillFromGen) {
    btnFillFromGen.addEventListener('click', () => {
      verMessage.value = genMessage.value;
      verKey.value = genKey.value;
      const generatedText = generatedHmacDisplay.textContent.trim();
      if (generatedText && !generatedText.includes('Click "Generate HMAC"')) {
        verHmac.value = generatedText;
      }
    });
  }

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

      const recalculatedHmac = (await computeHmacHex(message, key, algo)).toLowerCase();

      verifyPendingMsg.style.display = 'none';

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
        setFlowStep(4);
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
        setFlowStep(3);
      }

    } catch (err) {
      console.error('Verification Error:', err);
      showValidation('Verification process encountered an error: ' + err.message);
    } finally {
      btnVerify.disabled = false;
      btnVerify.style.opacity = '1';
    }
  }

  if (btnVerify) btnVerify.addEventListener('click', handleVerifyHmac);

  // Educational "Attempt Decryption" on HMAC explainer toggle
  if (btnAttemptHmacDecrypt) {
    btnAttemptHmacDecrypt.addEventListener('click', () => {
      const isVisible = hmacDecryptResult.style.display === 'block';
      hmacDecryptResult.style.display = isVisible ? 'none' : 'block';
      btnAttemptHmacDecrypt.textContent = isVisible ? 'Attempt HMAC "Decryption" 🔍' : 'Hide Decryption Explainer ✕';
    });
  }

  // =========================================================================
  // 7. Modification Analysis (Avalanche Effect Demonstration)
  // =========================================================================

  if (btnTabModMsg) {
    btnTabModMsg.addEventListener('click', () => {
      btnTabModMsg.classList.add('active');
      btnTabModKey.classList.remove('active');
      sectionModMsg.style.display = 'block';
      sectionModKey.style.display = 'none';
      updateMessageAnalysis();
    });
  }

  if (btnTabModKey) {
    btnTabModKey.addEventListener('click', () => {
      btnTabModKey.classList.add('active');
      btnTabModMsg.classList.remove('active');
      sectionModKey.style.display = 'block';
      sectionModMsg.style.display = 'none';
      updateKeyAnalysis();
    });
  }

  async function updateMessageAnalysis() {
    if (!modOrigMsg || !modMsgSharedKey || !modTamperedMsg) return;
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

  async function updateKeyAnalysis() {
    if (!modKeySharedMsg || !modOrigKey || !modTamperedKey) return;
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

  // Analysis Inputs Listeners
  if (modOrigMsg) modOrigMsg.addEventListener('input', updateMessageAnalysis);
  if (modMsgSharedKey) modMsgSharedKey.addEventListener('input', updateMessageAnalysis);
  if (modTamperedMsg) modTamperedMsg.addEventListener('input', updateMessageAnalysis);

  if (modKeySharedMsg) modKeySharedMsg.addEventListener('input', updateKeyAnalysis);
  if (modOrigKey) modOrigKey.addEventListener('input', updateKeyAnalysis);
  if (modTamperedKey) modTamperedKey.addEventListener('input', updateKeyAnalysis);

  // Quick Alteration Buttons
  const btnModCase = document.getElementById('quickModMsgCase');
  const btnModExcl = document.getElementById('quickModMsgExcl');
  const btnModSpace = document.getElementById('quickModMsgSpace');
  const btnKeyUpper = document.getElementById('quickModKeyUpper');
  const btnKeyAppend = document.getElementById('quickModKeyAppend');
  const btnKeyWrong = document.getElementById('quickModKeyWrong');

  if (btnModCase) btnModCase.addEventListener('click', () => { modTamperedMsg.value = 'Hello world'; updateMessageAnalysis(); });
  if (btnModExcl) btnModExcl.addEventListener('click', () => { modTamperedMsg.value = 'Hello World!'; updateMessageAnalysis(); });
  if (btnModSpace) btnModSpace.addEventListener('click', () => { modTamperedMsg.value = 'Hello World '; updateMessageAnalysis(); });

  if (btnKeyUpper) btnKeyUpper.addEventListener('click', () => { modTamperedKey.value = 'mysecretKey'; updateKeyAnalysis(); });
  if (btnKeyAppend) btnKeyAppend.addEventListener('click', () => { modTamperedKey.value = 'mysecretkey123'; updateKeyAnalysis(); });
  if (btnKeyWrong) btnKeyWrong.addEventListener('click', () => { modTamperedKey.value = 'wrongkey'; updateKeyAnalysis(); });

  // =========================================================================
  // 8. Preset Test Cases
  // =========================================================================

  if (loadPreset1) {
    loadPreset1.addEventListener('click', async () => {
      if (activeSimulationMode === 'encryptMac') {
        pipeMessage.value = 'Hello World';
        pipeKey.value = 'mysecretkey';
        pipeHash.value = 'SHA-256';
        await handlePipeEncrypt();
        setChannelTamper('clean');
        await handlePipeVerifyAndDecrypt();
      } else {
        genMessage.value = 'Hello World';
        genKey.value = 'mysecretkey';
        genAlgorithm.value = 'SHA-256';
        await handleGenerateHmac();
        verMessage.value = 'Hello World';
        verKey.value = 'mysecretkey';
        verHmac.value = generatedHmacDisplay.textContent.trim();
        await handleVerifyHmac();
      }
    });
  }

  if (loadPreset2) {
    loadPreset2.addEventListener('click', async () => {
      if (activeSimulationMode === 'encryptMac') {
        pipeMessage.value = 'Hello World';
        pipeKey.value = 'mysecretkey';
        pipeHash.value = 'SHA-256';
        await handlePipeEncrypt();
        setChannelTamper('tamper_ct');
        await handlePipeVerifyAndDecrypt();
      } else {
        genMessage.value = 'Hello World';
        genKey.value = 'mysecretkey';
        genAlgorithm.value = 'SHA-256';
        await handleGenerateHmac();
        verMessage.value = 'Hello World!';
        verKey.value = 'mysecretkey';
        verHmac.value = generatedHmacDisplay.textContent.trim();
        await handleVerifyHmac();

        btnTabModMsg.click();
        modOrigMsg.value = 'Hello World';
        modTamperedMsg.value = 'Hello World!';
        updateMessageAnalysis();
      }
    });
  }

  if (loadPreset3) {
    loadPreset3.addEventListener('click', async () => {
      if (activeSimulationMode === 'encryptMac') {
        pipeMessage.value = 'Hello World';
        pipeKey.value = 'mysecretkey';
        pipeHash.value = 'SHA-256';
        await handlePipeEncrypt();
        setChannelTamper('tamper_key');
        await handlePipeVerifyAndDecrypt();
      } else {
        genMessage.value = 'Hello World';
        genKey.value = 'mysecretkey';
        genAlgorithm.value = 'SHA-256';
        await handleGenerateHmac();
        verMessage.value = 'Hello World';
        verKey.value = 'mysecretKey';
        verHmac.value = generatedHmacDisplay.textContent.trim();
        await handleVerifyHmac();

        btnTabModKey.click();
        modOrigKey.value = 'mysecretkey';
        modTamperedKey.value = 'mysecretKey';
        updateKeyAnalysis();
      }
    });
  }

  if (loadPreset4) {
    loadPreset4.addEventListener('click', async () => {
      if (activeSimulationMode === 'encryptMac') {
        pipeMessage.value = 'Hello World';
        pipeKey.value = 'mysecretkey';
        pipeHash.value = 'SHA-256';
        await handlePipeEncrypt();
        setChannelTamper('tamper_hmac');
        await handlePipeVerifyAndDecrypt();
      } else {
        genMessage.value = 'Hello World';
        genKey.value = 'mysecretkey';
        genAlgorithm.value = 'SHA-256';
        await handleGenerateHmac();
        verMessage.value = 'Hello World';
        verKey.value = 'mysecretkey';
        const realHmac = generatedHmacDisplay.textContent.trim();
        verHmac.value = 'ffff' + realHmac.substring(4);
        await handleVerifyHmac();
      }
    });
  }

  if (loadPresetReset) {
    loadPresetReset.addEventListener('click', () => {
      // Reset Pipeline
      pipeMessage.value = 'Hello World';
      pipeKey.value = 'mysecretkey';
      pipeRxCiphertext.value = '';
      pipeRxIv.value = '';
      pipeRxKey.value = 'mysecretkey';
      pipeRxHmac.value = '';
      setChannelTamper('clean');
      resetPipeReceiverOutput();
      pipeCiphertextDisplay.innerHTML = '<span class="hex-placeholder">Click "Encrypt & Generate HMAC" to produce ciphertext...</span>';
      pipeIvDisplay.textContent = '-';
      pipeHmacDisplay.textContent = '-';
      pipeCtLen.textContent = '0';
      pipeHmacLen.textContent = '64';

      // Reset Standard Mode
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
  }

  // =========================================================================
  // 9. Interactive Quiz Logic
  // =========================================================================

  const quizAnswers = {
    q1: { correct: 'B', explanation: 'HMAC primarily provides message authentication and integrity verification using a symmetric secret key.' },
    q2: { correct: 'B', explanation: 'HMAC requires a plaintext message and a shared secret key.' },
    q3: { correct: 'B', explanation: 'Any change in the message alters the recalculated HMAC, causing verification to fail.' },
    q4: { correct: 'C', explanation: 'HMAC-SHA-256 is the standard default algorithm used throughout this lab.' },
    q5: { correct: 'B', explanation: 'If the secret key does not match the key used to generate the HMAC, verification fails.' },
    q6: { correct: 'C', explanation: 'Naive concatenation Hash(Key || Message) suffers from Length Extension Attacks; HMAC prevents this with its nested inner/outer hash structure.' }
  };

  if (quizForm) {
    quizForm.addEventListener('submit', (e) => {
      e.preventDefault();
      let score = 0;
      const total = Object.keys(quizAnswers).length;

      for (let qKey in quizAnswers) {
        const qNum = qKey.replace('q', '');
        const card = document.querySelector(`.quiz-question-card[data-q="${qNum}"]`);
        const selected = document.querySelector(`input[name="${qKey}"]:checked`);
        const feedback = document.getElementById(`feedbackQ${qNum}`);
        if (!card || !feedback) continue;

        const options = card.querySelectorAll('.quiz-option');
        options.forEach(opt => opt.classList.remove('correct', 'incorrect'));

        if (!selected) {
          feedback.className = 'quiz-feedback show-incorrect';
          feedback.textContent = 'Please select an answer for this question.';
          continue;
        }

        const val = selected.value;
        const isCorrect = (val === quizAnswers[qKey].correct);

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

      quizSummaryBox.style.display = 'block';
      quizScoreText.textContent = `${score} / ${total}`;

      const pct = (score / total) * 100;
      if (pct === 100) {
        quizScoreMessage.innerHTML = '<span style="color:#7ee787;">Outstanding! You have mastered HMAC principles, authenticated encryption, and integrity verification.</span>';
      } else if (pct >= 60) {
        quizScoreMessage.innerHTML = '<span style="color:#60a5fa;">Good job! Review the Theory tab to clear up any missed concepts.</span>';
      } else {
        quizScoreMessage.innerHTML = '<span style="color:#fcd34d;">Keep practicing! Explore the Modification Analysis and Full Pipeline to see HMAC in action.</span>';
      }

      quizSummaryBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  }

  if (btnResetQuiz) {
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
  }

  // =========================================================================
  // 10. Tab Navigation
  // =========================================================================

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

      if (targetTab === 'simulation') {
        updateMessageAnalysis();
        updateKeyAnalysis();
      }
    });
  });

  // =========================================================================
  // 11. Initial Page Load
  // =========================================================================

  window.addEventListener('DOMContentLoaded', async () => {
    // Run initial Encrypt-then-MAC pipeline with Decryption
    try {
      await handlePipeEncrypt();
      await handlePipeVerifyAndDecrypt();
    } catch (e) {
      console.error('Initial pipeline run error:', e);
    }

    // Run initial standard HMAC generation
    try {
      await handleGenerateHmac();
      await updateMessageAnalysis();
      await updateKeyAnalysis();
    } catch (e) {
      console.error('Initial HMAC run error:', e);
    }
  });

})();
