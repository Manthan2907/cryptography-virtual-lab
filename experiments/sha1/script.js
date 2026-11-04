/**
 * ============================================================================
 * Cryptography Virtual Laboratory - Experiment 04: SHA-1 Hash Algorithm
 * ============================================================================
 * Department of Computer Engineering - Fr. Conceicao Rodrigues College of Engineering
 * Course: Cryptography & System Security (CSS TH ISE)
 *
 * Collaborative Implementation by Group 4 (group-sha1):
 * - Member 1: Swar (10713)         -- UI Architecture, RFC 3174 Preprocessing & Padding Inspector
 * - Member 2: Tanush Chavan (10710) -- SHA-1 Core Compression Engine & Message Schedule Expansion
 * - Member 3: Aaron Deniz (10719)   -- Interactive Simulation, Rounds Breakdown & Step-by-Step Explorer
 * - Member 4: Asher (10715)         -- Sensitivity Analysis, Strict Avalanche Criterion (SAC),
 *                                      160-Bit Visual Heatmap Grid Diagram & Assessment Quiz
 * ============================================================================
 */

"use strict";

(function () {
  /* ============================================================================
     1. CONSTANTS & MATHEMATICAL SPECIFICATIONS (FIPS PUB 180-1 / RFC 3174)
     ============================================================================ */

  // Standard Initial Hash Values (IV constants)
  const H_INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

  // Per-Stage Additive Constants K_t (Derived from 2^30 * sqrt(2, 3, 5, 10))
  const K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

  // Logical Function Stage Names
  const F_NAMES = [
    "Ch (Conditional)",
    "Parity (Bitwise XOR)",
    "Maj (Majority)",
    "Parity (Bitwise XOR)"
  ];

  const REG_NAMES = ["Register A", "Register B", "Register C", "Register D", "Register E"];

  /* ============================================================================
     2. MEMBER 2 (TANUSH CHAVAN): SHA-1 CORE ALGORITHMIC PRIMITIVES
     ============================================================================ */

  /**
   * Unsigned 32-bit left circular rotation (ROTL^n)
   */
  function rotl(x, n) {
    return ((x << n) | (x >>> (32 - n))) >>> 0;
  }

  /**
   * Formats a 32-bit unsigned integer to an 8-character lowercase hexadecimal string
   */
  function hex8(n) {
    return ("00000000" + (n >>> 0).toString(16)).slice(-8);
  }

  /**
   * Formats an 8-bit byte to a 2-character lowercase hexadecimal string
   */
  function hex2(n) {
    return ("0" + (n & 0xff).toString(16)).slice(-2);
  }

  /**
   * Encodes a JavaScript string to an array of UTF-8 byte integers
   */
  function textToBytes(str) {
    return Array.from(new TextEncoder().encode(str));
  }

  /**
   * Evaluates the non-linear auxiliary function for round t
   * Stage 1 (0..19):  Ch(b,c,d)  = (b AND c) OR ((NOT b) AND d)
   * Stage 2 (20..39): Parity    = b XOR c XOR d
   * Stage 3 (40..59): Maj(b,c,d) = (b AND c) OR (b AND d) OR (c AND d)
   * Stage 4 (60..79): Parity    = b XOR c XOR d
   */
  function roundFunction(t, b, c, d) {
    if (t < 20) {
      return ((b & c) | (~b & d)) >>> 0;
    }
    if (t < 40 || t >= 60) {
      return (b ^ c ^ d) >>> 0;
    }
    return ((b & c) | (b & d) | (c & d)) >>> 0;
  }

  /* ============================================================================
     3. MEMBER 1 (SWAR): RFC 3174 PREPROCESSING, PADDING & SCHEDULE EXPANSION
     ============================================================================ */

  /**
   * Applies RFC 3174 / FIPS 180-1 padding:
   * 1. Append byte 0x80 ('1' bit followed by seven '0' bits)
   * 2. Append zero bytes until length is congruent to 56 mod 64 (448 mod 512)
   * 3. Append original length in bits as a 64-bit big-endian integer
   */
  function padMessage(bytes) {
    const len = bytes.length;
    let zeros = (55 - len) % 64;
    if (zeros < 0) {
      zeros += 64;
    }

    const padded = bytes.slice();
    padded.push(0x80);
    for (let i = 0; i < zeros; i++) {
      padded.push(0x00);
    }

    const bitLen = len * 8;
    const high = Math.floor(bitLen / 4294967296) >>> 0;
    const low = (bitLen & 0xffffffff) >>> 0;

    const lenBytes = [
      (high >>> 24) & 0xff,
      (high >>> 16) & 0xff,
      (high >>> 8) & 0xff,
      high & 0xff,
      (low >>> 24) & 0xff,
      (low >>> 16) & 0xff,
      (low >>> 8) & 0xff,
      low & 0xff
    ];

    for (let j = 0; j < 8; j++) {
      padded.push(lenBytes[j]);
    }

    return {
      padded: padded,
      msgLen: len,
      zeros: zeros,
      bitLen: bitLen,
      totalBlocks: padded.length / 64
    };
  }

  /**
   * Expands a 512-bit block into eighty 32-bit words W[0..79]
   * W[0..15] come directly from the 512-bit block (big-endian)
   * W[16..79] = ROTL^1( W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16] )
   */
  function expandSchedule(blockBytes, offset) {
    const w = new Array(80);
    for (let t = 0; t < 16; t++) {
      const p = offset + t * 4;
      w[t] =
        (((blockBytes[p] << 24) >>> 0) |
          (blockBytes[p + 1] << 16) |
          (blockBytes[p + 2] << 8) |
          blockBytes[p + 3]) >>>
        0;
    }
    for (let u = 16; u < 80; u++) {
      w[u] = rotl(w[u - 3] ^ w[u - 8] ^ w[u - 14] ^ w[u - 16], 1);
    }
    return w;
  }

  /* ============================================================================
     4. MEMBER 3 (AARON DENIZ): 80-ROUND COMPRESSION PIPELINE & INTERMEDIATES
     ============================================================================ */

  /**
   * Executes full SHA-1 computation and logs intermediate state transitions
   * for the interactive step explorer, schedule tables, and register displays.
   */
  function computeSha1(message, saltToken = "") {
    message = typeof message === "string" ? message : (message ? String(message) : "");
    const effectiveMessage = saltToken ? message + saltToken : message;
    const rawBytes = textToBytes(effectiveMessage);
    const pad = padMessage(rawBytes);
    let h = H_INIT.slice();
    const blocks = [];

    for (let off = 0; off < pad.padded.length; off += 64) {
      const w = expandSchedule(pad.padded, off);
      let a = h[0];
      let b = h[1];
      let c = h[2];
      let d = h[3];
      let e = h[4];

      const steps = [];
      const roundEnds = [];

      for (let t = 0; t < 80; t++) {
        const stage = Math.floor(t / 20);
        const f = roundFunction(t, b, c, d);
        const k = K[stage];
        const temp = (rotl(a, 5) + f + e + k + w[t]) >>> 0;
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;

        steps.push({
          t: t,
          stage: stage,
          f: f,
          k: k,
          w: w[t],
          regs: [a, b, c, d, e]
        });

        if (t % 20 === 19) {
          roundEnds.push([a, b, c, d, e]);
        }
      }

      // Merkle–Damgård feed-forward accumulation
      h = [
        (h[0] + a) >>> 0,
        (h[1] + b) >>> 0,
        (h[2] + c) >>> 0,
        (h[3] + d) >>> 0,
        (h[4] + e) >>> 0
      ];

      blocks.push({
        w: w,
        steps: steps,
        roundEnds: roundEnds,
        chain: h.slice()
      });
    }

    const digest = h.map(hex8).join("");

    return {
      digest: digest,
      pad: pad,
      blocks: blocks,
      bits: rawBytes.length * 8,
      charCount: message.length,
      regA: hex8(h[0]),
      regB: hex8(h[1]),
      regC: hex8(h[2]),
      regD: hex8(h[3]),
      regE: hex8(h[4]),
      saltUsed: saltToken
    };
  }

  /* ============================================================================
     5. MEMBER 4 (ASHER): SENSITIVITY ANALYSIS & 160-BIT HEATMAP ENGINE
     ============================================================================ */

  /**
   * Converts a 40-character hexadecimal SHA-1 hash to a 160-character binary string
   */
  function hexToBinary160(hexStr) {
    let bin = "";
    for (let i = 0; i < hexStr.length; i++) {
      bin += parseInt(hexStr.charAt(i), 16).toString(2).padStart(4, "0");
    }
    return bin;
  }

  /**
   * Computes Hamming distance and bitwise difference vector between two SHA-1 hashes
   */
  function compareDigests160(hashA, hashB) {
    const binA = hexToBinary160(hashA);
    const binB = hexToBinary160(hashB);
    let changedBits = 0;
    const bitDifferences = new Array(160);

    for (let i = 0; i < 160; i++) {
      const isDiff = binA[i] !== binB[i];
      if (isDiff) {
        changedBits++;
      }
      bitDifferences[i] = {
        bitIndex: i,
        bitA: binA[i],
        bitB: binB[i],
        isFlipped: isDiff,
        regIndex: Math.floor(i / 32),
        bitInReg: 31 - (i % 32)
      };
    }

    let hexCharsChanged = 0;
    const hexDiffMarks = [];
    for (let j = 0; j < 40; j++) {
      const isHexDiff = hashA.charAt(j) !== hashB.charAt(j);
      if (isHexDiff) {
        hexCharsChanged++;
      }
      hexDiffMarks.push(isHexDiff);
    }

    return {
      changedBits: changedBits,
      totalBits: 160,
      percentage: (changedBits / 160) * 100,
      hexCharsChanged: hexCharsChanged,
      bitDifferences: bitDifferences,
      hexDiffMarks: hexDiffMarks
    };
  }

  /* ============================================================================
     6. DOM ELEMENTS & USER INTERFACE WIREUP
     ============================================================================ */

  const el = id => document.getElementById(id);

  // Main Hash Generator Elements
  const sha1Input = el("sha1Input");
  const charCount = el("charCount");
  const bitCount = el("bitCount");
  const enableSaltToggle = el("enableSaltToggle");
  const saltBadgeToken = el("saltBadgeToken");
  const btnGenerateHash = el("btnGenerateHash");
  const btnClearInput = el("btnClearInput");
  const hashOutput = el("hashOutput");
  const hashLength = el("hashLength");
  const btnCopyHash = el("btnCopyHash");
  const selfCheckTerminal = el("selfCheckTerminal");

  // Diagnostics & Registers
  const statCharCount = el("statCharCount");
  const statOrigBits = el("statOrigBits");
  const statPaddedBytes = el("statPaddedBytes");
  const statBlockCount = el("statBlockCount");
  const regA = el("regA");
  const regB = el("regB");
  const regC = el("regC");
  const regD = el("regD");
  const regE = el("regE");
  const regHexConcat = el("regHexConcat");

  // Padding Inspector
  const padInputText = el("padInputText");
  const btnInspectPad = el("btnInspectPad");
  const padSummaryBox = el("padSummaryBox");
  const padByteStream = el("padByteStream");

  // Message Schedule & Rounds
  const schedBlockSelect = el("schedBlockSelect");
  const schedTableBody = el("schedTableBody");
  const roundsTableBody = el("roundsTableBody");
  const stepBlockSelect = el("stepBlockSelect");
  const stepRangeInput = el("stepRangeInput");
  const stepLabel = el("stepLabel");
  const stepInfoBox = el("stepInfoBox");

  // Avalanche & Heatmap
  const avMsg1 = el("avMsg1");
  const avMsg2 = el("avMsg2");
  const avHash1 = el("avHash1");
  const avHash2 = el("avHash2");
  const btnAnalyzeAvalanche = el("btnAnalyzeAvalanche");
  const btnAvFlipBit = el("btnAvFlipBit");
  const btnAvToggleCase = el("btnAvToggleCase");
  const btnAvAppendChar = el("btnAvAppendChar");
  const btnAvToggleChar = el("btnAvToggleChar");
  const btnAvCopyMsg = el("btnAvCopyMsg");
  const avBitsFlipped = el("avBitsFlipped");
  const avPercent = el("avPercent");
  const avHexFlipped = el("avHexFlipped");
  const avQuality = el("avQuality");
  const avHexDiffDisplay = el("avHexDiffDisplay");
  const bitMatrixContainer = el("bitMatrixContainer");
  const avObservationBox = el("avObservationBox");

  // Quiz
  const quizForm = el("quizForm");
  const btnSubmitQuiz = el("btnSubmitQuiz");
  const btnRetryQuiz = el("btnRetryQuiz");
  const quizScoreBanner = el("quizScoreBanner");

  let currentHashResult = null;
  let dynamicSaltToken = "";

  /* ============================================================================
     7. RENDERING FUNCTIONS
     ============================================================================ */

  /**
   * Runs NIST FIPS 180-1 known-answer self-tests on startup
   */
  function runSelfCheck() {
    const vectors = [
      { msg: "abc", exp: "a9993e364706816aba3e25717850c26c9cd0d89d" },
      { msg: "", exp: "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
      {
        msg: "The quick brown fox jumps over the lazy dog",
        exp: "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
      }
    ];

    let output = "=== NIST FIPS 180-1 Known-Answer Self-Check ===\n";
    let allPassed = true;

    vectors.forEach((v, idx) => {
      const got = computeSha1(v.msg).digest;
      const pass = got === v.exp;
      if (!pass) allPassed = false;
      const badge = pass ? "[PASS]" : "[FAIL]";
      output += `${badge} Test ${idx + 1}: SHA1("${v.msg}")\n`;
      output += `       Expected: ${v.exp}\n`;
      output += `       Computed: ${got}\n`;
    });

    output += allPassed
      ? "\nStatus: All test vectors verified against NIST standard."
      : "\nStatus: Self-check discrepancy detected.";

    if (selfCheckTerminal) {
      selfCheckTerminal.textContent = output;
    }
  }

  /**
   * Updates block selection dropdowns when block count changes
   */
  function syncBlockSelects(totalBlocks) {
    if (!schedBlockSelect || !stepBlockSelect) return;
    const currentSched = parseInt(schedBlockSelect.value, 10) || 0;
    const currentStep = parseInt(stepBlockSelect.value, 10) || 0;

    let options = "";
    for (let i = 0; i < totalBlocks; i++) {
      options += `<option value="${i}">Block ${i + 1} of ${totalBlocks}</option>`;
    }

    schedBlockSelect.innerHTML = options;
    stepBlockSelect.innerHTML = options;

    schedBlockSelect.value = String(Math.min(currentSched, totalBlocks - 1));
    stepBlockSelect.value = String(Math.min(currentStep, totalBlocks - 1));
  }

  /**
   * Renders primary hash generation results & diagnostic register values
   */
  function renderHashOutput(res) {
    if (!res) return;
    currentHashResult = res;

    hashOutput.textContent = res.digest;
    hashLength.textContent = res.digest.length;

    statCharCount.textContent = `${res.charCount} characters`;
    statOrigBits.textContent = `${res.bits} bits`;
    statPaddedBytes.textContent = `${res.pad.padded.length} bytes`;
    statBlockCount.textContent = `${res.blocks.length} block(s)`;

    regA.textContent = res.regA;
    regB.textContent = res.regB;
    regC.textContent = res.regC;
    regD.textContent = res.regD;
    regE.textContent = res.regE;
    regHexConcat.textContent = res.regA + res.regB + res.regC + res.regD + res.regE;

    syncBlockSelects(res.blocks.length);
    renderScheduleTable();
    renderRoundsTable();
    renderStepInfo();
  }

  /**
   * Renders the RFC 3174 Padding Inspector view
   */
  function renderPaddingInspector(text) {
    const bytes = textToBytes(text);
    const pad = padMessage(bytes);

    padSummaryBox.textContent =
      `Original message length (L): ${pad.msgLen} bytes (${pad.bitLen} bits)\n` +
      `+ Mandatory start byte: 0x80 (1 byte = 8 bits)\n` +
      `+ Zero-fill padding (k): ${pad.zeros} bytes (${pad.zeros * 8} zero bits)\n` +
      `+ 64-bit Big-Endian length descriptor: 8 bytes (0x${(pad.bitLen).toString(16).padStart(16, "0")})\n` +
      `= Total padded length: ${pad.padded.length} bytes (${pad.padded.length * 8} bits) = ` +
      `${pad.totalBlocks} block(s) of 512 bits`;

    let html = "";
    for (let i = 0; i < pad.padded.length; i++) {
      let badgeClass = "badge-msg";
      let roleDesc = "Original Message";

      if (i === pad.msgLen) {
        badgeClass = "badge-one";
        roleDesc = "Start Byte (0x80)";
      } else if (i > pad.msgLen && i < pad.msgLen + 1 + pad.zeros) {
        badgeClass = "badge-zero";
        roleDesc = "Zero Fill";
      } else if (i >= pad.msgLen + 1 + pad.zeros) {
        badgeClass = "badge-len";
        roleDesc = "64-bit Length";
      }

      html += `<span class="byte-badge ${badgeClass}" title="Byte #${i}: 0x${hex2(pad.padded[i])} (${roleDesc})">${hex2(pad.padded[i])}</span>`;
    }
    padByteStream.innerHTML = html;
  }

  /**
   * Renders 80-word message schedule for the currently selected block
   */
  function renderScheduleTable() {
    if (!currentHashResult || !schedTableBody) return;
    const blockIdx = parseInt(schedBlockSelect.value, 10) || 0;
    const block = currentHashResult.blocks[blockIdx];
    if (!block) return;

    let html = "";
    for (let t = 0; t < 40; t++) {
      const src1 =
        t < 16
          ? "Block word M[" + t + "]"
          : "ROTL1(W" + (t - 3) + " ^ W" + (t - 8) + " ^ W" + (t - 14) + " ^ W" + (t - 16) + ")";
      const src2 =
        t + 40 < 16
          ? "Block word M[" + (t + 40) + "]"
          : "ROTL1(W" + (t + 37) + " ^ W" + (t + 32) + " ^ W" + (t + 26) + " ^ W" + (t + 24) + ")";

      html += `<tr>
        <td><strong>W[${t}]</strong></td>
        <td><code>${hex8(block.w[t])}</code></td>
        <td style="font-size: 11.5px; color: #b0a59f;">${src1}</td>
        <td><strong>W[${t + 40}]</strong></td>
        <td><code>${hex8(block.w[t + 40])}</code></td>
        <td style="font-size: 11.5px; color: #b0a59f;">${src2}</td>
      </tr>`;
    }
    schedTableBody.innerHTML = html;
  }

  /**
   * Renders registers A, B, C, D, E at the end of each round and after chaining
   */
  function renderRoundsTable() {
    if (!currentHashResult || !roundsTableBody) return;
    let html = "";

    currentHashResult.blocks.forEach((blk, bi) => {
      blk.roundEnds.forEach((regs, ri) => {
        html += `<tr>
          <td><strong>Block ${bi + 1} &middot; Stage ${ri + 1} (${F_NAMES[ri]})</strong></td>
          <td><code>${hex8(regs[0])}</code></td>
          <td><code>${hex8(regs[1])}</code></td>
          <td><code>${hex8(regs[2])}</code></td>
          <td><code>${hex8(regs[3])}</code></td>
          <td><code>${hex8(regs[4])}</code></td>
        </tr>`;
      });
      html += `<tr style="background: rgba(76, 140, 232, 0.12); font-weight: bold;">
        <td><strong>Block ${bi + 1} &middot; Merkle&ndash;Damg&aring;rd Chaining</strong></td>
        <td><code>${hex8(blk.chain[0])}</code></td>
        <td><code>${hex8(blk.chain[1])}</code></td>
        <td><code>${hex8(blk.chain[2])}</code></td>
        <td><code>${hex8(blk.chain[3])}</code></td>
        <td><code>${hex8(blk.chain[4])}</code></td>
      </tr>`;
    });
    roundsTableBody.innerHTML = html;
  }

  /**
   * Updates step information in the Rounds Step Explorer
   */
  function renderStepInfo() {
    if (!currentHashResult || !stepInfoBox) return;
    const blockIdx = parseInt(stepBlockSelect.value, 10) || 0;
    const stepIdx = parseInt(stepRangeInput.value, 10) || 0;
    stepLabel.textContent = String(stepIdx);

    const blk = currentHashResult.blocks[blockIdx];
    if (!blk || !blk.steps[stepIdx]) return;

    const s = blk.steps[stepIdx];
    const stage = s.stage;

    stepInfoBox.textContent =
      `Block ${blockIdx + 1} / Step t = ${s.t} (Stage ${stage + 1}: ${F_NAMES[stage]})\n` +
      `Auxiliary Function f(B,C,D) = 0x${hex8(s.f)}\n` +
      `Additive Constant  K_t       = 0x${hex8(s.k)}\n` +
      `Message Schedule   W[${s.t}]` + (s.t < 10 ? "  " : " ") + `= 0x${hex8(s.w)}\n` +
      `Register State Transformations:\n` +
      `  A = 0x${hex8(s.regs[0])}    B = 0x${hex8(s.regs[1])}    C = 0x${hex8(s.regs[2])}\n` +
      `  D = 0x${hex8(s.regs[3])}    E = 0x${hex8(s.regs[4])}`;
  }

  /**
   * Renders the 160-Bit Visual Heatmap Grid Diagram & Avalanche Metrics
   */
  function renderAvalancheComparison() {
    const msg1 = avMsg1.value;
    const msg2 = avMsg2.value;

    const res1 = computeSha1(msg1);
    const res2 = computeSha1(msg2);

    avHash1.textContent = res1.digest;
    avHash2.textContent = res2.digest;

    const cmp = compareDigests160(res1.digest, res2.digest);

    avBitsFlipped.textContent = `${cmp.changedBits} / 160`;
    avPercent.textContent = `${cmp.percentage.toFixed(2)}%`;
    avHexFlipped.textContent = `${cmp.hexCharsChanged} / 40`;

    // Quality Badge
    let qualityText = "Awaiting";
    let qualityColor = "#2ed573";
    if (msg1 === msg2) {
      qualityText = "Identical Inputs";
      qualityColor = "#79aeff";
    } else if (cmp.changedBits >= 64 && cmp.changedBits <= 96) {
      qualityText = "Optimal (~50% SAC)";
      qualityColor = "#2ed573";
    } else {
      qualityText = "Single-Sample Variance";
      qualityColor = "#f5a623";
    }
    avQuality.textContent = qualityText;
    avQuality.style.color = qualityColor;

    // Hex Diff Display with inline highlighted spans
    let diffHtml = "";
    for (let c = 0; c < 40; c++) {
      if (cmp.hexDiffMarks[c]) {
        diffHtml += `<span class="diff-char" title="Index ${c}: ${res1.digest[c]} &ne; ${res2.digest[c]}">${res2.digest[c]}</span>`;
      } else {
        diffHtml += res2.digest[c];
      }
    }
    avHexDiffDisplay.innerHTML = diffHtml;

    // Render 160-Bit Heatmap Matrix (5 Registers x 32 Bits)
    let matrixHtml = "";
    const regLetters = ["A", "B", "C", "D", "E"];

    for (let r = 0; r < 5; r++) {
      matrixHtml += `<div class="matrix-reg-row">`;
      matrixHtml += `<span class="matrix-reg-label">Reg ${regLetters[r]} (32b):</span>`;
      matrixHtml += `<div class="matrix-reg-bits">`;

      for (let b = 0; b < 32; b++) {
        const bitIdx = r * 32 + b;
        const bitData = cmp.bitDifferences[bitIdx];
        const cellClass = bitData.isFlipped ? "bit-flipped" : "bit-same";
        const symbol = bitData.isFlipped ? "1" : "0";

        matrixHtml += `<div class="bit-cell ${cellClass}" title="Bit #${bitIdx} [Register ${regLetters[r]}, Bit ${31 - b}]: ${bitData.bitA} &rarr; ${bitData.bitB} (${bitData.isFlipped ? "Flipped" : "Unchanged"})">${symbol}</div>`;
      }

      matrixHtml += `</div></div>`;
    }
    bitMatrixContainer.innerHTML = matrixHtml;

    // Observation summary note
    if (msg1 === msg2) {
      avObservationBox.textContent =
        "Observation: Messages are identical, so digests match exactly with 0 bits flipped. Introduce a mutation above to observe diffusion.";
    } else if (cmp.changedBits >= 64 && cmp.changedBits <= 96) {
      avObservationBox.textContent =
        `Observation: Strict Avalanche Criterion strongly observed! ${cmp.changedBits} out of 160 bits flipped (${cmp.percentage.toFixed(2)}%), aligning closely with the ideal 50% diffusion benchmark across registers A through E.`;
    } else {
      avObservationBox.textContent =
        `Observation: ${cmp.changedBits} bits flipped (${cmp.percentage.toFixed(2)}%). In cryptographic hash functions, single sample variance is normal, but the expected value over large samples converges to exactly 50% (80 bits).`;
    }
  }

  /* ============================================================
     8. EVENT LISTENERS & CONTROLS BINDING
     ============================================================ */

  function bindEvents() {
    // Input counter updates
    sha1Input.addEventListener("input", () => {
      const len = sha1Input.value.length;
      charCount.textContent = `Characters: ${len}`;
      bitCount.textContent = `Original Length: ${len * 8} bits`;
      if (!enableSaltToggle.checked) {
        renderHashOutput(computeSha1(sha1Input.value));
      }
    });

    // Salt / Nonce Toggle
    enableSaltToggle.addEventListener("change", () => {
      if (enableSaltToggle.checked) {
        dynamicSaltToken = `_nonce_${Date.now().toString(36)}`;
        saltBadgeToken.textContent = `Salt: ${dynamicSaltToken}`;
        saltBadgeToken.style.color = "#79aeff";
      } else {
        dynamicSaltToken = "";
        saltBadgeToken.textContent = "Deterministic Mode";
        saltBadgeToken.style.color = "#8c827a";
      }
      renderHashOutput(computeSha1(sha1Input.value, dynamicSaltToken));
    });

    // Preset buttons
    document.querySelectorAll(".preset-btn[data-sample]").forEach(btn => {
      btn.addEventListener("click", () => {
        sha1Input.value = btn.getAttribute("data-sample");
        const len = sha1Input.value.length;
        charCount.textContent = `Characters: ${len}`;
        bitCount.textContent = `Original Length: ${len * 8} bits`;
        renderHashOutput(computeSha1(sha1Input.value, dynamicSaltToken));
      });
    });

    // Generate & Clear Buttons
    btnGenerateHash.addEventListener("click", () => {
      if (enableSaltToggle.checked) {
        dynamicSaltToken = `_nonce_${Date.now().toString(36)}`;
        saltBadgeToken.textContent = `Salt: ${dynamicSaltToken}`;
      }
      renderHashOutput(computeSha1(sha1Input.value, dynamicSaltToken));
    });

    btnClearInput.addEventListener("click", () => {
      sha1Input.value = "";
      charCount.textContent = "Characters: 0";
      bitCount.textContent = "Original Length: 0 bits";
      renderHashOutput(computeSha1("", dynamicSaltToken));
    });

    // Copy Hash Button
    btnCopyHash.addEventListener("click", () => {
      const text = hashOutput.textContent.trim();
      if (!text) return;
      navigator.clipboard.writeText(text).then(() => {
        const originalText = btnCopyHash.textContent;
        btnCopyHash.textContent = "Copied!";
        btnCopyHash.style.background = "#2ed573";
        setTimeout(() => {
          btnCopyHash.textContent = originalText;
          btnCopyHash.style.background = "";
        }, 1500);
      });
    });

    // Simulation Subtab Switcher
    const simSubtabBtns = document.querySelectorAll(".sim-subtab-btn");
    simSubtabBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        simSubtabBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");

        const targetView = btn.getAttribute("data-sim-view");
        document.querySelectorAll(".sim-panel").forEach(panel => {
          panel.classList.toggle("active", panel.id === `sim-view-${targetView}`);
        });

        // Trigger view-specific re-renders
        if (targetView === "padding") {
          renderPaddingInspector(padInputText.value);
        } else if (targetView === "avalanche") {
          renderAvalancheComparison();
        }
      });
    });

    // Padding Inspector Button
    btnInspectPad.addEventListener("click", () => {
      renderPaddingInspector(padInputText.value);
    });

    // Block & Step Selectors
    schedBlockSelect.addEventListener("change", renderScheduleTable);
    stepBlockSelect.addEventListener("change", renderStepInfo);
    stepRangeInput.addEventListener("input", renderStepInfo);

    // Avalanche Mutation Presets
    btnAnalyzeAvalanche.addEventListener("click", renderAvalancheComparison);
    avMsg1.addEventListener("input", renderAvalancheComparison);
    avMsg2.addEventListener("input", renderAvalancheComparison);

    btnAvFlipBit.addEventListener("click", () => {
      const chars = Array.from(avMsg1.value);
      if (chars.length === 0) {
        avMsg2.value = "\u0001";
      } else {
        const lastIdx = chars.length - 1;
        chars[lastIdx] = String.fromCodePoint(chars[lastIdx].codePointAt(0) ^ 1);
        avMsg2.value = chars.join("");
      }
      renderAvalancheComparison();
    });

    btnAvToggleCase.addEventListener("click", () => {
      const str = avMsg1.value;
      avMsg2.value = str === str.toLowerCase() ? str.toUpperCase() : str.toLowerCase();
      renderAvalancheComparison();
    });

    btnAvAppendChar.addEventListener("click", () => {
      avMsg2.value = avMsg1.value + ".";
      renderAvalancheComparison();
    });

    btnAvToggleChar.addEventListener("click", () => {
      const str = avMsg1.value;
      if (!str) {
        avMsg2.value = "A";
      } else {
        const last = str.slice(-1);
        const next = last === "z" ? "a" : last === "Z" ? "A" : String.fromCharCode(last.charCodeAt(0) + 1);
        avMsg2.value = str.slice(0, -1) + next;
      }
      renderAvalancheComparison();
    });

    btnAvCopyMsg.addEventListener("click", () => {
      avMsg2.value = avMsg1.value;
      renderAvalancheComparison();
    });

    // Steppers Logic
    initSteppers();

    // Quiz Submission & Reset Logic
    initQuiz();
  }

  /**
   * Interactive Procedure Steppers
   */
  function initSteppers() {
    const stepper = el("sha1-stepper");
    if (!stepper) return;

    stepper.querySelectorAll(".stepper-header").forEach(header => {
      header.addEventListener("click", () => {
        const item = header.closest(".stepper-item");
        const body = el(header.getAttribute("aria-controls"));
        if (!body) return;

        const isOpen = item.classList.contains("open");
        if (isOpen) {
          item.classList.remove("open");
          header.setAttribute("aria-expanded", "false");
          body.hidden = true;
        } else {
          item.classList.add("open");
          header.setAttribute("aria-expanded", "true");
          body.hidden = false;
        }
      });
    });

    stepper.querySelectorAll("[data-step-next]").forEach(btn => {
      btn.addEventListener("click", () => {
        const currentItem = btn.closest(".stepper-item");
        const allItems = [...stepper.querySelectorAll(".stepper-item")];
        const currentIndex = allItems.indexOf(currentItem);

        currentItem.classList.add("done");
        currentItem.classList.remove("open");
        const currentHeader = currentItem.querySelector(".stepper-header");
        if (currentHeader) currentHeader.setAttribute("aria-expanded", "false");
        const currentBody = el(currentHeader.getAttribute("aria-controls"));
        if (currentBody) currentBody.hidden = true;

        if (currentIndex + 1 < allItems.length) {
          const nextItem = allItems[currentIndex + 1];
          nextItem.classList.add("open");
          const nextHeader = nextItem.querySelector(".stepper-header");
          if (nextHeader) nextHeader.setAttribute("aria-expanded", "true");
          const nextBody = el(nextHeader.getAttribute("aria-controls"));
          if (nextBody) nextBody.hidden = false;
          nextItem.scrollIntoView({ behavior: "smooth", block: "nearest" });
        }
      });
    });
  }

  /**
   * Assessment Quiz Evaluator
   */
  function initQuiz() {
    if (!quizForm || !btnSubmitQuiz) return;

    btnSubmitQuiz.addEventListener("click", () => {
      let score = 0;
      const cards = quizForm.querySelectorAll(".quiz-card");

      cards.forEach(card => {
        const qNum = card.getAttribute("data-q");
        const correctVal = card.getAttribute("data-correct");
        const selected = card.querySelector(`input[name="q${qNum}"]:checked`);
        const explanation = el(`exp-q${qNum}`);

        const labels = card.querySelectorAll(".quiz-option-label");
        labels.forEach(label => {
          const input = label.querySelector("input");
          label.classList.remove("correct", "incorrect");

          if (input.value === correctVal) {
            label.classList.add("correct");
          }
          if (input.checked && input.value !== correctVal) {
            label.classList.add("incorrect");
          }
        });

        if (selected && selected.value === correctVal) {
          score++;
        }

        if (explanation) {
          explanation.classList.add("visible");
        }
      });

      const percentage = (score / cards.length) * 100;
      quizScoreBanner.textContent = `Assessment Score: ${score} / ${cards.length} (${percentage.toFixed(0)}%)`;
      quizScoreBanner.classList.add("visible");
      btnRetryQuiz.style.display = "inline-block";
      quizScoreBanner.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });

    btnRetryQuiz.addEventListener("click", () => {
      quizForm.reset();
      quizForm.querySelectorAll(".quiz-option-label").forEach(l => l.classList.remove("correct", "incorrect"));
      quizForm.querySelectorAll(".quiz-explanation").forEach(e => e.classList.remove("visible"));
      quizScoreBanner.classList.remove("visible");
      btnRetryQuiz.style.display = "none";
    });
  }

  /* ============================================================
     9. INITIALIZATION
     ============================================================ */

  runSelfCheck();
  bindEvents();
  if (sha1Input) {
    renderHashOutput(computeSha1(sha1Input.value || "abc"));
  }
  if (padInputText) {
    renderPaddingInspector(padInputText.value || "abc");
  }
  if (avMsg1 && avMsg2) {
    renderAvalancheComparison();
  }
})();
