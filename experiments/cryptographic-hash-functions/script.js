/**
 * Hashing Functions Simulator - MD5 & SHA-1 Interactive Engine
 * Provides authentic binary conversion, padding, block representation,
 * and mathematical MD5/SHA-1 hashing with visual step animation.
 */

(function () {
  'use strict';

  // UTF-8 Helper
  function getUtf8Bytes(str) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    const result = [];

    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      const charBytes = encoder.encode(char);
      for (let b = 0; b < charBytes.length; b++) {
        const byteVal = charBytes[b];
        let displayChar = char;
        if (char === ' ') displayChar = '(space)';
        else if (char === '\t') displayChar = '(tab)';
        else if (char === '\n') displayChar = '(newline)';
        if (b > 0) displayChar = '..';

        result.push({
          char: displayChar,
          dec: byteVal,
          bin: byteVal.toString(2).padStart(8, '0')
        });
      }
    }
    return { bytes, byteList: result };
  }

  // MD5 Algorithm with Intermediate State Extraction
  function computeMD5(bytes) {
    const bitLength = bytes.length * 8;

    let paddingLength = (56 - ((bytes.length + 1) % 64)) % 64;
    if (paddingLength < 0) paddingLength += 64;

    const totalLength = bytes.length + 1 + paddingLength + 8;
    const padded = new Uint8Array(totalLength);
    padded.set(bytes, 0);
    padded[bytes.length] = 0x80;

    const view = new DataView(padded.buffer);
    view.setUint32(totalLength - 8, bitLength >>> 0, true);
    view.setUint32(totalLength - 4, Math.floor(bitLength / 0x100000000), true);

    // Format first 16 bytes for display
    let hexList = [];
    for (let i = 0; i < Math.min(16, padded.length); i++) {
      hexList.push(padded[i].toString(16).padStart(2, '0').toUpperCase());
    }
    const paddedHexStr = hexList.join(' ') + ' ...';

    // Extract first 3 words in little-endian format
    const M0 = view.getUint32(0, true).toString(16).padStart(8, '0').toUpperCase();
    const M1 = view.getUint32(4, true).toString(16).padStart(8, '0').toUpperCase();
    const M2 = view.getUint32(8, true).toString(16).padStart(8, '0').toUpperCase();

    // MD5 Constants and Shifts
    const S = [
      7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
      5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
      4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
      6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    ];

    const K = new Uint32Array(64);
    for (let i = 0; i < 64; i++) {
      K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
    }

    let A = 0x67452301 >>> 0;
    let B = 0xEFCDAB89 >>> 0;
    let C = 0x98BADCFE >>> 0;
    let D = 0x10325476 >>> 0;

    let intA = 0, intB = 0, intC = 0, intD = 0;
    const numBlocks = padded.length / 64;

    for (let b = 0; b < numBlocks; b++) {
      const blockWords = new Uint32Array(16);
      for (let i = 0; i < 16; i++) {
        blockWords[i] = view.getUint32(b * 64 + i * 4, true);
      }

      let a = A, bReg = B, c = C, d = D;

      for (let i = 0; i < 64; i++) {
        let f, g;
        if (i < 16) {
          f = (bReg & c) | ((~bReg) & d);
          g = i;
        } else if (i < 32) {
          f = (d & bReg) | ((~d) & c);
          g = (5 * i + 1) % 16;
        } else if (i < 48) {
          f = bReg ^ c ^ d;
          g = (3 * i + 5) % 16;
        } else {
          f = c ^ (bReg | (~d));
          g = (7 * i) % 16;
        }

        let temp = d;
        d = c;
        c = bReg;
        let sum = (a + f + K[i] + blockWords[g]) >>> 0;
        let rot = ((sum << S[i]) | (sum >>> (32 - S[i]))) >>> 0;
        bReg = (bReg + rot) >>> 0;
        a = temp;
      }

      A = (A + a) >>> 0;
      B = (B + bReg) >>> 0;
      C = (C + c) >>> 0;
      D = (D + d) >>> 0;

      if (b === 0 || b === numBlocks - 1) {
        intA = A;
        intB = B;
        intC = C;
        intD = D;
      }
    }

    function toLittleEndianHex(val) {
      let s = '';
      for (let i = 0; i < 4; i++) {
        s += ((val >>> (i * 8)) & 0xff).toString(16).padStart(2, '0');
      }
      return s;
    }

    const hash = toLittleEndianHex(A) + toLittleEndianHex(B) + toLittleEndianHex(C) + toLittleEndianHex(D);

    return {
      paddedHex: paddedHexStr,
      words: [`M[0] = 0x${M0}`, `M[1] = 0x${M1}`, `M[2] = 0x${M2}`],
      state: {
        A: `0x${intA.toString(16).padStart(8, '0').toUpperCase()}`,
        B: `0x${intB.toString(16).padStart(8, '0').toUpperCase()}`,
        C: `0x${intC.toString(16).padStart(8, '0').toUpperCase()}`,
        D: `0x${intD.toString(16).padStart(8, '0').toUpperCase()}`
      },
      hash
    };
  }

  // SHA-1 Algorithm with Intermediate State Extraction
  function computeSHA1(bytes) {
    const bitLength = bytes.length * 8;

    let paddingLength = (56 - ((bytes.length + 1) % 64)) % 64;
    if (paddingLength < 0) paddingLength += 64;

    const totalLength = bytes.length + 1 + paddingLength + 8;
    const padded = new Uint8Array(totalLength);
    padded.set(bytes, 0);
    padded[bytes.length] = 0x80;

    const view = new DataView(padded.buffer);
    view.setUint32(totalLength - 8, Math.floor(bitLength / 0x100000000), false);
    view.setUint32(totalLength - 4, bitLength >>> 0, false);

    let hexList = [];
    for (let i = 0; i < Math.min(16, padded.length); i++) {
      hexList.push(padded[i].toString(16).padStart(2, '0').toUpperCase());
    }
    const paddedHexStr = hexList.join(' ') + ' ...';

    // Extract first 3 words in big-endian format
    const W0 = view.getUint32(0, false).toString(16).padStart(8, '0').toUpperCase();
    const W1 = view.getUint32(4, false).toString(16).padStart(8, '0').toUpperCase();
    const W2 = view.getUint32(8, false).toString(16).padStart(8, '0').toUpperCase();

    let H0 = 0x67452301 >>> 0;
    let H1 = 0xEFCDAB89 >>> 0;
    let H2 = 0x98BADCFE >>> 0;
    let H3 = 0x10325476 >>> 0;
    let H4 = 0xC3D2E1F0 >>> 0;

    let intH = {};
    const numBlocks = padded.length / 64;

    for (let b = 0; b < numBlocks; b++) {
      const W = new Uint32Array(80);
      for (let t = 0; t < 16; t++) {
        W[t] = view.getUint32(b * 64 + t * 4, false);
      }
      for (let t = 16; t < 80; t++) {
        let x = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
        W[t] = ((x << 1) | (x >>> 31)) >>> 0;
      }

      let a = H0, bReg = H1, c = H2, d = H3, e = H4;

      for (let t = 0; t < 80; t++) {
        let f, k;
        if (t < 20) {
          f = (bReg & c) | ((~bReg) & d);
          k = 0x5A827999;
        } else if (t < 40) {
          f = bReg ^ c ^ d;
          k = 0x6ED9EBA1;
        } else if (t < 60) {
          f = (bReg & c) | (bReg & d) | (c & d);
          k = 0x8F1BBCDC;
        } else {
          f = bReg ^ c ^ d;
          k = 0xCA62C1D6;
        }

        let aRot = ((a << 5) | (a >>> 27)) >>> 0;
        let temp = (aRot + f + e + k + W[t]) >>> 0;
        e = d;
        d = c;
        c = ((bReg << 30) | (bReg >>> 2)) >>> 0;
        bReg = a;
        a = temp;
      }

      H0 = (H0 + a) >>> 0;
      H1 = (H1 + bReg) >>> 0;
      H2 = (H2 + c) >>> 0;
      H3 = (H3 + d) >>> 0;
      H4 = (H4 + e) >>> 0;

      if (b === 0 || b === numBlocks - 1) {
        intH = {
          H0: `0x${H0.toString(16).padStart(8, '0').toUpperCase()}`,
          H1: `0x${H1.toString(16).padStart(8, '0').toUpperCase()}`,
          H2: `0x${H2.toString(16).padStart(8, '0').toUpperCase()}`,
          H3: `0x${H3.toString(16).padStart(8, '0').toUpperCase()}`,
          H4: `0x${H4.toString(16).padStart(8, '0').toUpperCase()}`
        };
      }
    }

    function toBigEndianHex(val) {
      return val.toString(16).padStart(8, '0');
    }

    const hash = toBigEndianHex(H0) + toBigEndianHex(H1) + toBigEndianHex(H2) + toBigEndianHex(H3) + toBigEndianHex(H4);

    return {
      paddedHex: paddedHexStr,
      words: [`W[0] = 0x${W0}`, `W[1] = 0x${W1}`, `W[2] = 0x${W2}`],
      state: intH,
      hash
    };
  }

  // Render Binary Conversion Table
  function renderBinaryTable(tableEl, byteList) {
    if (!tableEl) return;
    if (!byteList || byteList.length === 0) {
      tableEl.innerHTML = `
        <table class="sim-binary-table">
          <tbody>
            <tr class="sim-row-char"><th>Character</th><td>(empty)</td></tr>
            <tr class="sim-row-dec"><th>Decimal</th><td>0</td></tr>
            <tr class="sim-row-bin"><th>Binary</th><td>00000000</td></tr>
          </tbody>
        </table>`;
      return;
    }

    let charTh = '<th>Character</th>';
    let decTh = '<th>Decimal</th>';
    let binTh = '<th>Binary</th>';

    let charTds = '';
    let decTds = '';
    let binTds = '';

    byteList.forEach(item => {
      charTds += `<td>${item.char}</td>`;
      decTds += `<td>${item.dec}</td>`;
      binTds += `<td>${item.bin}</td>`;
    });

    tableEl.innerHTML = `
      <table class="sim-binary-table">
        <tbody>
          <tr class="sim-row-char">${charTh}${charTds}</tr>
          <tr class="sim-row-dec">${decTh}${decTds}</tr>
          <tr class="sim-row-bin">${binTh}${binTds}</tr>
        </tbody>
      </table>`;
  }

  let isInitialized = false;

  function initSimulator() {
    const inputEl = document.getElementById('simInputMessage');
    const btnReset = document.getElementById('simBtnReset');
    const metaChars = document.getElementById('simMetaChars');
    const metaBytes = document.getElementById('simMetaBytes');

    // Toolbar & Fast Output Controls
    const btnQuickHashToggle = document.getElementById('simBtnQuickHashToggle');
    const quickOutputPanel = document.getElementById('simQuickOutputPanel');
    const quickMd5Hash = document.getElementById('simQuickMd5Hash');
    const quickSha1Hash = document.getElementById('simQuickSha1Hash');

    const btnRunStage1 = document.getElementById('simBtnRunStage1');
    const btnRunStage2 = document.getElementById('simBtnRunStage2');
    const btnRunStage3 = document.getElementById('simBtnRunStage3');
    const btnRunAll = document.getElementById('simBtnRunAll');
    const btnResetSteps = document.getElementById('simBtnResetSteps');

    // In-Stage Trigger Buttons
    const md5BtnStage1 = document.getElementById('simMd5BtnStage1');
    const md5BtnStage2 = document.getElementById('simMd5BtnStage2');
    const md5BtnStage3 = document.getElementById('simMd5BtnStage3');
    const sha1BtnStage1 = document.getElementById('simSha1BtnStage1');
    const sha1BtnStage2 = document.getElementById('simSha1BtnStage2');
    const sha1BtnStage3 = document.getElementById('simSha1BtnStage3');

    // Stage Cards & Placeholders
    const md5Stage1Card = document.getElementById('simMd5Stage1Card');
    const md5Stage2Card = document.getElementById('simMd5Stage2Card');
    const md5Stage3Card = document.getElementById('simMd5Stage3Card');
    const sha1Stage1Card = document.getElementById('simSha1Stage1Card');
    const sha1Stage2Card = document.getElementById('simSha1Stage2Card');
    const sha1Stage3Card = document.getElementById('simSha1Stage3Card');

    const md5Stage1Placeholder = document.getElementById('simMd5Stage1Placeholder');
    const md5Stage2Placeholder = document.getElementById('simMd5Stage2Placeholder');
    const md5Stage3Placeholder = document.getElementById('simMd5Stage3Placeholder');
    const sha1Stage1Placeholder = document.getElementById('simSha1Stage1Placeholder');
    const sha1Stage2Placeholder = document.getElementById('simSha1Stage2Placeholder');
    const sha1Stage3Placeholder = document.getElementById('simSha1Stage3Placeholder');

    // Stage Content Containers
    const md5BinaryTable = document.getElementById('simMd5BinaryTable');
    const md5Stage2Content = document.getElementById('simMd5Stage2Content');
    const md5Stage3Content = document.getElementById('simMd5Stage3Content');
    const sha1BinaryTable = document.getElementById('simSha1BinaryTable');
    const sha1Stage2Content = document.getElementById('simSha1Stage2Content');
    const sha1Stage3Content = document.getElementById('simSha1Stage3Content');

    // Data Value Output Spans
    const md5PaddedHex = document.getElementById('simMd5PaddedHex');
    const md5BlockWords = document.getElementById('simMd5BlockWords');
    const md5StateVars = document.getElementById('simMd5StateVars');
    const md5FinalHash = document.getElementById('simMd5FinalHash');

    const sha1PaddedHex = document.getElementById('simSha1PaddedHex');
    const sha1BlockWords = document.getElementById('simSha1BlockWords');
    const sha1StateVars = document.getElementById('simSha1StateVars');
    const sha1FinalHash = document.getElementById('simSha1FinalHash');

    const compMd5Hash = document.getElementById('simCompMd5Hash');
    const compSha1Hash = document.getElementById('simCompSha1Hash');

    if (!inputEl) return;

    let executedStage = 0; // 0: reset/unexecuted, 1: stage 1, 2: stage 2, 3: stage 3

    function recalculateData(resetStageOnChange = false) {
      const text = inputEl.value;
      const { bytes, byteList } = getUtf8Bytes(text);

      if (metaChars) metaChars.textContent = text.length;
      if (metaBytes) metaBytes.textContent = bytes.length;

      const md5Data = computeMD5(bytes);
      const sha1Data = computeSHA1(bytes);

      // Instant Fast Output updates unconditionally for quick direct hash view
      if (quickMd5Hash) quickMd5Hash.textContent = md5Data.hash;
      if (quickSha1Hash) quickSha1Hash.textContent = sha1Data.hash;

      if (resetStageOnChange) {
        executedStage = 0;
      }

      // Prepare DOM contents for each stage
      renderBinaryTable(md5BinaryTable, byteList);
      renderBinaryTable(sha1BinaryTable, byteList);

      if (md5PaddedHex) md5PaddedHex.textContent = md5Data.paddedHex;
      if (md5BlockWords) md5BlockWords.innerHTML = md5Data.words.join('<br>') + '<br>...';
      if (md5StateVars) {
        md5StateVars.innerHTML = `A = ${md5Data.state.A}<br>B = ${md5Data.state.B}<br>C = ${md5Data.state.C}<br>D = ${md5Data.state.D}`;
      }
      if (md5FinalHash) md5FinalHash.textContent = md5Data.hash;

      if (sha1PaddedHex) sha1PaddedHex.textContent = sha1Data.paddedHex;
      if (sha1BlockWords) sha1BlockWords.innerHTML = sha1Data.words.join('<br>') + '<br>...';
      if (sha1StateVars) {
        sha1StateVars.innerHTML = `H0 = ${sha1Data.state.H0}<br>H1 = ${sha1Data.state.H1}<br>H2 = ${sha1Data.state.H2}<br>H3 = ${sha1Data.state.H3}<br>H4 = ${sha1Data.state.H4}`;
      }
      if (sha1FinalHash) sha1FinalHash.textContent = sha1Data.hash;

      // Update UI visibility and step button states according to executedStage
      updateStageUI(md5Data.hash, sha1Data.hash);
    }

    function updateStageUI(md5HashVal, sha1HashVal) {
      // Stage 1 Visibility & Buttons
      if (executedStage >= 1) {
        if (md5Stage1Placeholder) md5Stage1Placeholder.style.display = 'none';
        if (sha1Stage1Placeholder) sha1Stage1Placeholder.style.display = 'none';
        if (md5BinaryTable) md5BinaryTable.classList.remove('hidden-step');
        if (sha1BinaryTable) sha1BinaryTable.classList.remove('hidden-step');
        if (md5Stage1Card) md5Stage1Card.classList.add('stage-active');
        if (sha1Stage1Card) sha1Stage1Card.classList.add('stage-active');

        setButtonCompleted(btnRunStage1, '✓ Step 1 Completed');
        setButtonCompleted(md5BtnStage1, '✓ Stage 1 Complete (Binary Converted)');
        setButtonCompleted(sha1BtnStage1, '✓ Stage 1 Complete (Binary Converted)');

        if (btnRunStage2) btnRunStage2.disabled = false;
        if (md5BtnStage2) md5BtnStage2.disabled = false;
        if (sha1BtnStage2) sha1BtnStage2.disabled = false;
      } else {
        if (md5Stage1Placeholder) md5Stage1Placeholder.style.display = 'flex';
        if (sha1Stage1Placeholder) sha1Stage1Placeholder.style.display = 'flex';
        if (md5BinaryTable) md5BinaryTable.classList.add('hidden-step');
        if (sha1BinaryTable) sha1BinaryTable.classList.add('hidden-step');
        if (md5Stage1Card) md5Stage1Card.classList.remove('stage-active');
        if (sha1Stage1Card) sha1Stage1Card.classList.remove('stage-active');

        resetButton(btnRunStage1, 'Step 1: Convert to Binary');
        resetButton(md5BtnStage1, '▶ Execute Stage 1: Convert to Binary');
        resetButton(sha1BtnStage1, '▶ Execute Stage 1: Convert to Binary');

        if (btnRunStage2) btnRunStage2.disabled = true;
        if (md5BtnStage2) md5BtnStage2.disabled = true;
        if (sha1BtnStage2) sha1BtnStage2.disabled = true;
      }

      // Stage 2 Visibility & Buttons
      if (executedStage >= 2) {
        if (md5Stage2Placeholder) md5Stage2Placeholder.style.display = 'none';
        if (sha1Stage2Placeholder) sha1Stage2Placeholder.style.display = 'none';
        if (md5Stage2Content) md5Stage2Content.classList.remove('hidden-step');
        if (sha1Stage2Content) sha1Stage2Content.classList.remove('hidden-step');
        if (md5Stage2Card) md5Stage2Card.classList.add('stage-active');
        if (sha1Stage2Card) sha1Stage2Card.classList.add('stage-active');

        setButtonCompleted(btnRunStage2, '✓ Step 2 Completed');
        setButtonCompleted(md5BtnStage2, '✓ Stage 2 Complete (Padded & Processed)');
        setButtonCompleted(sha1BtnStage2, '✓ Stage 2 Complete (Padded & Processed)');

        if (btnRunStage3) btnRunStage3.disabled = false;
        if (md5BtnStage3) md5BtnStage3.disabled = false;
        if (sha1BtnStage3) sha1BtnStage3.disabled = false;
      } else {
        if (md5Stage2Placeholder) md5Stage2Placeholder.style.display = 'flex';
        if (sha1Stage2Placeholder) sha1Stage2Placeholder.style.display = 'flex';
        if (md5Stage2Content) md5Stage2Content.classList.add('hidden-step');
        if (sha1Stage2Content) sha1Stage2Content.classList.add('hidden-step');
        if (md5Stage2Card) md5Stage2Card.classList.remove('stage-active');
        if (sha1Stage2Card) sha1Stage2Card.classList.remove('stage-active');

        resetButton(btnRunStage2, 'Step 2: Process Data');
        resetButton(md5BtnStage2, '▶ Execute Stage 2: Process Message & Rounds');
        resetButton(sha1BtnStage2, '▶ Execute Stage 2: Process Message & Rounds');

        if (btnRunStage3) btnRunStage3.disabled = true;
        if (md5BtnStage3) md5BtnStage3.disabled = true;
        if (sha1BtnStage3) sha1BtnStage3.disabled = true;
      }

      // Stage 3 Visibility & Buttons
      if (executedStage >= 3) {
        if (md5Stage3Placeholder) md5Stage3Placeholder.style.display = 'none';
        if (sha1Stage3Placeholder) sha1Stage3Placeholder.style.display = 'none';
        if (md5Stage3Content) md5Stage3Content.classList.remove('hidden-step');
        if (sha1Stage3Content) sha1Stage3Content.classList.remove('hidden-step');
        if (md5Stage3Card) md5Stage3Card.classList.add('stage-active');
        if (sha1Stage3Card) sha1Stage3Card.classList.add('stage-active');

        setButtonCompleted(btnRunStage3, '✓ Step 3 Completed');
        setButtonCompleted(md5BtnStage3, '✓ Stage 3 Complete (Final Hash Calculated)');
        setButtonCompleted(sha1BtnStage3, '✓ Stage 3 Complete (Final Hash Calculated)');

        if (compMd5Hash) compMd5Hash.textContent = md5HashVal;
        if (compSha1Hash) compSha1Hash.textContent = sha1HashVal;
      } else {
        if (md5Stage3Placeholder) md5Stage3Placeholder.style.display = 'flex';
        if (sha1Stage3Placeholder) sha1Stage3Placeholder.style.display = 'flex';
        if (md5Stage3Content) md5Stage3Content.classList.add('hidden-step');
        if (sha1Stage3Content) sha1Stage3Content.classList.add('hidden-step');
        if (md5Stage3Card) md5Stage3Card.classList.remove('stage-active');
        if (sha1Stage3Card) sha1Stage3Card.classList.remove('stage-active');

        resetButton(btnRunStage3, 'Step 3: Calculate Hash');
        resetButton(md5BtnStage3, '▶ Execute Stage 3: Calculate Final MD5 Hash');
        resetButton(sha1BtnStage3, '▶ Execute Stage 3: Calculate Final SHA-1 Hash');

        if (compMd5Hash) compMd5Hash.textContent = '... (Execute Stage 3)';
        if (compSha1Hash) compSha1Hash.textContent = '... (Execute Stage 3)';
      }
    }

    function setButtonCompleted(btn, text) {
      if (!btn) return;
      btn.textContent = text;
      btn.classList.add('completed');
    }

    function resetButton(btn, defaultText) {
      if (!btn) return;
      btn.textContent = defaultText;
      btn.classList.remove('completed');
    }

    function executeStep(stageNum) {
      executedStage = Math.max(executedStage, stageNum);
      recalculateData(false);
    }

    if (!isInitialized) {
      isInitialized = true;

      // Real-time input synchronization (resets process steps on typing so final hash is not pre-shown)
      inputEl.addEventListener('input', () => recalculateData(true));
      inputEl.addEventListener('keyup', () => recalculateData(true));
      inputEl.addEventListener('change', () => recalculateData(true));
      inputEl.addEventListener('paste', () => setTimeout(() => recalculateData(true), 10));

      // Quick Hash Toggle
      if (btnQuickHashToggle) {
        btnQuickHashToggle.addEventListener('click', () => {
          if (quickOutputPanel) {
            quickOutputPanel.classList.toggle('visible');
            const isVisible = quickOutputPanel.classList.contains('visible');
            btnQuickHashToggle.classList.toggle('active', isVisible);
            btnQuickHashToggle.innerHTML = isVisible 
              ? 'Hide Instant Output' 
              : 'Instant Fast Output';
          }
        });
      }

      // Step Buttons (Toolbar & In-Stage)
      const stage1Btns = [btnRunStage1, md5BtnStage1, sha1BtnStage1];
      stage1Btns.forEach(btn => {
        if (btn) btn.addEventListener('click', () => executeStep(1));
      });

      const stage2Btns = [btnRunStage2, md5BtnStage2, sha1BtnStage2];
      stage2Btns.forEach(btn => {
        if (btn) btn.addEventListener('click', () => executeStep(2));
      });

      const stage3Btns = [btnRunStage3, md5BtnStage3, sha1BtnStage3];
      stage3Btns.forEach(btn => {
        if (btn) btn.addEventListener('click', () => executeStep(3));
      });

      // Execute All Steps (Animated sequence)
      if (btnRunAll) {
        btnRunAll.addEventListener('click', () => {
          btnRunAll.disabled = true;
          btnRunAll.textContent = 'Executing...';
          executedStage = 0;
          recalculateData(false);

          setTimeout(() => {
            executeStep(1);
          }, 400);

          setTimeout(() => {
            executeStep(2);
          }, 1100);

          setTimeout(() => {
            executeStep(3);
            btnRunAll.disabled = false;
            btnRunAll.textContent = '▶ Execute All Steps';
          }, 1800);
        });
      }

      // Reset Process Steps
      if (btnResetSteps) {
        btnResetSteps.addEventListener('click', () => {
          executedStage = 0;
          recalculateData(false);
        });
      }

      // Reset Input Message
      if (btnReset) {
        btnReset.addEventListener('click', () => {
          inputEl.value = 'Hello World';
          executedStage = 0;
          recalculateData(false);
        });
      }

      // Copy buttons
      document.querySelectorAll('.sim-copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const targetId = btn.getAttribute('data-target');
          const targetEl = document.getElementById(targetId);
          if (targetEl && targetEl.textContent && targetEl.textContent !== '...') {
            navigator.clipboard.writeText(targetEl.textContent.trim()).then(() => {
              const originalContent = btn.innerHTML;
              btn.textContent = 'Copied!';
              setTimeout(() => {
                btn.innerHTML = originalContent;
              }, 1500);
            }).catch(() => {
              const ta = document.createElement('textarea');
              ta.value = targetEl.textContent.trim();
              document.body.appendChild(ta);
              ta.select();
              document.execCommand('copy');
              document.body.removeChild(ta);
              const originalContent = btn.innerHTML;
              btn.textContent = 'Copied!';
              setTimeout(() => {
                btn.innerHTML = originalContent;
              }, 1500);
            });
          }
        });
      });
    }

    // Initial calculation on load
    recalculateData(false);
  }

  // Expose to window so other tabs or inline script can invoke it

  // Expose to window so other tabs or inline script can invoke it
  window.initHashSimulator = initSimulator;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSimulator);
  } else {
    initSimulator();
  }

  // Also listen for tab clicks to re-verify simulation state when student opens the tab
  document.addEventListener('click', (e) => {
    const tabBtn = e.target.closest('.tab-btn');
    if (tabBtn && tabBtn.getAttribute('data-tab') === 'simulation') {
      setTimeout(initSimulator, 10);
    }
  });
})();

// Quiz Logic
function initQuiz() {
  const quizForm = document.getElementById('hashQuizForm');
  if(quizForm && !quizForm.dataset.initialized) {
    quizForm.dataset.initialized = 'true';
    quizForm.addEventListener('submit', function(e) {
      e.preventDefault();
      
      const isConfirmed = confirm("Are you sure you want to submit? Click OK for Yes, Cancel for No.");
      if (!isConfirmed) return;
      
      const correctAnswers = {
        q1: 'b',
        q2: 'a',
        q3: 'b',
        q4: 'b',
        q5: 'c',
        q6: 'c',
        q7: 'b',
        q8: 'a',
        q9: 'c',
        q10: 'b'
      };
      
      let score = 0;
      const formData = new FormData(quizForm);
      
      for (const [question, answer] of Object.entries(correctAnswers)) {
        if (formData.get(question) === answer) {
          score++;
        }
      }
      
      const resultDiv = document.getElementById('quizResult');
      resultDiv.style.display = 'block';
      
      if (score === 10) {
        resultDiv.style.backgroundColor = 'rgba(16, 185, 129, 0.2)';
        resultDiv.style.color = '#6ee7b7';
        resultDiv.style.border = '1px solid #10b981';
      } else if (score >= 7) {
        resultDiv.style.backgroundColor = 'rgba(59, 130, 246, 0.2)';
        resultDiv.style.color = '#93c5fd';
        resultDiv.style.border = '1px solid #3b82f6';
      } else {
        resultDiv.style.backgroundColor = 'rgba(244, 63, 94, 0.2)';
        resultDiv.style.color = '#fda4af';
        resultDiv.style.border = '1px solid #f43f5e';
      }
      
      resultDiv.innerText = "You scored " + score + " out of 10!";
    });
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initQuiz);
} else {
  initQuiz();
}
