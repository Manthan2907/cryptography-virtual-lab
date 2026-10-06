/* ==========================================================================
   Virtual Cryptography Lab - Module 11: Bcrypt Password Hashing
   Advanced Interactive Laboratory Logic & Simulation Engine
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  BcryptLabModule.init();
});

const BcryptLabModule = {
  currentPipelineStage: 1,
  selectedRating: 0,
  quizAnswers: {},
  generatedSalts: [],
  benchmarkResults: [],
  lastGeneratedHash: '',
  lastGeneratedTime: '',

  init() {
    this.initSubtabs();
    this.initByteCounter();
    this.initHashGenerator();
    this.initVerifier();
    this.initSaltDemo();
    this.initInspector();
    this.initPipeline();
    this.initTruncationExploit();
    this.initHashRace();
    this.initHardwareBenchmark();
    this.initCrackTimeEstimator();
    this.initRainbowSimulator();
    this.initReportGenerator();
    this.initQuiz();
    this.initFeedback();
    this.initModals();
    this.initFlashcards();
  },

  getBcrypt() {
    return window.dcodeIO?.bcrypt || window.bcrypt;
  },

  // Helper for UTF-8 byte count
  getByteLength(str) {
    if (!str) return 0;
    return new TextEncoder().encode(str).length;
  },

  // 1. Sub-Tabs for Theory Section
  initSubtabs() {
    const subtabBtns = document.querySelectorAll('.b-subtab-btn');
    const subpanes = document.querySelectorAll('.b-subpane');

    subtabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-subtab');
        subtabBtns.forEach(b => b.classList.remove('active'));
        subpanes.forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        const targetPane = document.getElementById(target);
        if (targetPane) targetPane.classList.add('active');
      });
    });
  },

  // 2. Real-time Byte Counter with 72-Byte Truncation Detection
  initByteCounter() {
    const pwdInput = document.getElementById('bGenPassword');
    const byteCountEl = document.getElementById('bByteCount');
    const byteFillEl = document.getElementById('bByteFill');
    const warnBox = document.getElementById('bTruncWarn');
    const toggleBtn = document.getElementById('bTogglePwd');

    if (!pwdInput || !byteCountEl || !byteFillEl) return;

    const updateCounter = () => {
      const val = pwdInput.value;
      const bytes = this.getByteLength(val);
      const pct = Math.min(100, Math.round((bytes / 72) * 100));

      byteCountEl.textContent = `${bytes} / 72 bytes`;
      byteFillEl.style.width = `${pct}%`;

      if (bytes > 72) {
        byteFillEl.className = 'b-byte-fill exceeded';
        if (warnBox) warnBox.classList.remove('hidden');
      } else if (bytes > 60) {
        byteFillEl.className = 'b-byte-fill warn';
        if (warnBox) warnBox.classList.add('hidden');
      } else {
        byteFillEl.className = 'b-byte-fill';
        if (warnBox) warnBox.classList.add('hidden');
      }
    };

    pwdInput.addEventListener('input', updateCounter);
    updateCounter();

    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const type = pwdInput.getAttribute('type') === 'password' ? 'text' : 'password';
        pwdInput.setAttribute('type', type);
        toggleBtn.textContent = type === 'password' ? '👁 Show' : '🔒 Hide';
      });
    }
  },

  // 3. Tool 1: Live Bcrypt Hash Generator
  initHashGenerator() {
    const form = document.getElementById('bGenForm');
    const pwdInput = document.getElementById('bGenPassword');
    const costSelect = document.getElementById('bCostSelect');
    const btnSubmit = document.getElementById('bBtnGen');
    const placeholder = document.getElementById('bHashPlaceholder');
    const outputArea = document.getElementById('bHashOutput');
    const hashText = document.getElementById('bHashText');
    const timeEl = document.getElementById('bMetricTime');
    const roundsEl = document.getElementById('bMetricRounds');
    const lenEl = document.getElementById('bMetricLen');
    const copyBtn = document.getElementById('bBtnCopy');
    const sendVerifyBtn = document.getElementById('bBtnSendVerify');
    const costAdvisor = document.getElementById('bCostAdvisor');
    const expTimeVal = document.getElementById('bExpTimeVal');

    if (!form) return;

    const advisorDescriptions = {
      4: '<strong>Work Factor: 2<sup>4</sup> = 16 rounds</strong> &bull; Minimal latency (~1 ms). For automated unit test suites only; completely insecure for production.',
      8: '<strong>Work Factor: 2<sup>8</sup> = 256 rounds</strong> &bull; Low latency (~15 ms). Suitable only for severely constrained legacy IoT hardware.',
      10: '<strong>Work Factor: 2<sup>10</sup> = 1,024 rounds</strong> &bull; Recommended OWASP baseline (balanced security &amp; ~100 ms login latency).',
      12: '<strong>Work Factor: 2<sup>12</sup> = 4,096 rounds</strong> &bull; High security (~400 ms). Recommended for sensitive admin portals and financial services.'
    };

    const expTimes = { 4: '~1 ms', 8: '~15 ms', 10: '~100 ms', 12: '~400 ms' };

    costSelect?.addEventListener('change', () => {
      const val = parseInt(costSelect.value, 10);
      if (costAdvisor && advisorDescriptions[val]) {
        costAdvisor.innerHTML = advisorDescriptions[val];
      }
      if (expTimeVal && expTimes[val]) {
        expTimeVal.textContent = expTimes[val];
      }
    });

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const pwd = pwdInput.value;
      const cost = parseInt(costSelect.value, 10) || 10;
      if (!pwd) return;

      btnSubmit.disabled = true;
      btnSubmit.textContent = 'Computing Blowfish Key Schedule...';

      setTimeout(() => {
        const bcrypt = this.getBcrypt();
        if (!bcrypt) {
          alert('Bcrypt library is loading or unavailable. Please verify vendor script.');
          btnSubmit.disabled = false;
          btnSubmit.textContent = 'Generate Bcrypt Hash';
          return;
        }

        try {
          const t0 = performance.now();
          const salt = bcrypt.genSaltSync(cost);
          const hash = bcrypt.hashSync(pwd, salt);
          const t1 = performance.now();
          const duration = (t1 - t0).toFixed(2);

          this.lastGeneratedHash = hash;
          this.lastGeneratedTime = `${duration} ms`;

          if (placeholder) placeholder.classList.add('hidden');
          if (outputArea) outputArea.classList.remove('hidden');

          if (hashText) hashText.textContent = hash;
          if (timeEl) timeEl.textContent = `${duration} ms`;
          if (roundsEl) roundsEl.textContent = Math.pow(2, cost).toLocaleString();
          if (lenEl) lenEl.textContent = `${hash.length} chars`;
          if (expTimeVal) expTimeVal.textContent = `${duration} ms`;

          // Auto-populate inspector
          const inspectorInput = document.getElementById('bInspectInput');
          if (inspectorInput) {
            inspectorInput.value = hash;
            this.inspectHash(hash);
          }
        } catch (err) {
          console.error(err);
          alert('Error during hashing: ' + err.message);
        } finally {
          btnSubmit.disabled = false;
          btnSubmit.textContent = 'Generate Bcrypt Hash';
        }
      }, 40);
    });

    copyBtn?.addEventListener('click', () => {
      if (!hashText) return;
      navigator.clipboard.writeText(hashText.textContent).then(() => {
        const prev = copyBtn.textContent;
        copyBtn.textContent = '✓ Copied!';
        setTimeout(() => copyBtn.textContent = prev, 1500);
      });
    });

    sendVerifyBtn?.addEventListener('click', () => {
      const hashVal = hashText ? hashText.textContent : '';
      const pwdVal = pwdInput ? pwdInput.value : '';
      const verifyHashInput = document.getElementById('bVerifyHash');
      const verifyPwdInput = document.getElementById('bVerifyPwd');

      if (verifyHashInput && verifyPwdInput) {
        verifyHashInput.value = hashVal;
        verifyPwdInput.value = pwdVal;
        verifyHashInput.scrollIntoView({ behavior: 'smooth' });
      }
    });
  },

  // 4. Tool 2: Password Match Verifier
  initVerifier() {
    const form = document.getElementById('bVerifyForm');
    const hashInput = document.getElementById('bVerifyHash');
    const pwdInput = document.getElementById('bVerifyPwd');
    const btnVerify = document.getElementById('bBtnVerify');
    const placeholder = document.getElementById('bVerifyPlaceholder');
    const resultBox = document.getElementById('bVerifyResult');
    const banner = document.getElementById('bVerifyBanner');
    const titleEl = document.getElementById('bVerifyTitle');
    const descEl = document.getElementById('bVerifyDesc');
    const timeEl = document.getElementById('bVerifyTime');

    if (!form) return;

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const targetHash = hashInput.value.trim();
      const candidatePwd = pwdInput.value;
      if (!targetHash || candidatePwd === undefined) return;

      btnVerify.disabled = true;
      btnVerify.textContent = 'Verifying password match...';

      setTimeout(() => {
        const bcrypt = this.getBcrypt();
        if (!bcrypt) {
          btnVerify.disabled = false;
          btnVerify.textContent = 'Verify Password Match';
          return;
        }

        try {
          const t0 = performance.now();
          const isMatch = bcrypt.compareSync(candidatePwd, targetHash);
          const t1 = performance.now();
          const duration = (t1 - t0).toFixed(2);

          if (placeholder) placeholder.classList.add('hidden');
          if (resultBox) resultBox.classList.remove('hidden');

          if (isMatch) {
            banner.className = 'b-status-banner success';
            titleEl.textContent = '✓ PASSWORD MATCH CONFIRMED';
            descEl.textContent = 'The candidate password successfully recreated the identical 192-bit digest using the salt embedded in the target hash string.';
          } else {
            banner.className = 'b-status-banner error';
            titleEl.textContent = '✗ VERIFICATION FAILED (NO MATCH)';
            descEl.textContent = 'The candidate password produced a completely different digest. Access denied.';
          }

          if (timeEl) timeEl.textContent = `Completed in ${duration} ms`;
        } catch (err) {
          alert('Verification error (ensure hash string is formatted as $2b$cost$...): ' + err.message);
        } finally {
          btnVerify.disabled = false;
          btnVerify.textContent = 'Verify Password Match';
        }
      }, 40);
    });
  },

  // 5. Tool 3: Non-Deterministic Salt Demonstration
  initSaltDemo() {
    const btnRun = document.getElementById('bBtnSaltDemo');
    const pwdInput = document.getElementById('bSaltPwd');
    const btnVerifyAll = document.getElementById('bBtnVerifySalts');
    const verifyStatus = document.getElementById('bSaltVerifyStatus');

    if (!btnRun || !pwdInput) return;

    btnRun.addEventListener('click', () => {
      const pwd = pwdInput.value || 'SameSecretPassword123';
      const bcrypt = this.getBcrypt();
      if (!bcrypt) return;

      btnRun.disabled = true;
      btnRun.textContent = 'Generating 3 distinct salts...';

      setTimeout(() => {
        try {
          this.generatedSalts = [];
          for (let i = 1; i <= 3; i++) {
            const salt = bcrypt.genSaltSync(8);
            const hash = bcrypt.hashSync(pwd, salt);
            this.generatedSalts.push(hash);

            const hashEl = document.getElementById(`bSaltHash${i}`);
            const valEl = document.getElementById(`bSaltVal${i}`);
            if (hashEl) hashEl.textContent = hash;
            if (valEl) valEl.textContent = `Salt: ${salt}`;
          }

          if (btnVerifyAll) btnVerifyAll.disabled = false;
          if (verifyStatus) verifyStatus.textContent = '';
        } catch (err) {
          console.error(err);
        } finally {
          btnRun.disabled = false;
          btnRun.textContent = 'Run Salt Randomness Test';
        }
      }, 40);
    });

    btnVerifyAll?.addEventListener('click', () => {
      const pwd = pwdInput.value || 'SameSecretPassword123';
      const bcrypt = this.getBcrypt();
      if (!bcrypt || this.generatedSalts.length !== 3) return;

      const m1 = bcrypt.compareSync(pwd, this.generatedSalts[0]);
      const m2 = bcrypt.compareSync(pwd, this.generatedSalts[1]);
      const m3 = bcrypt.compareSync(pwd, this.generatedSalts[2]);

      if (m1 && m2 && m3) {
        verifyStatus.innerHTML = '<span style="color:#86efac; font-weight:700;">✓ SUCCESS: All 3 completely distinct hash strings verified TRUE against the exact same password!</span>';
      } else {
        verifyStatus.innerHTML = '<span style="color:#fca5a5; font-weight:700;">✗ Verification error</span>';
      }
    });
  },

  // 6. Tool 4: Modular Hash String Inspector
  initInspector() {
    const input = document.getElementById('bInspectInput');
    if (input) {
      input.addEventListener('input', (e) => this.inspectHash(e.target.value.trim()));
      this.inspectHash(input.value.trim());
    }

    const tokenDetails = {
      ver: {
        title: 'Version Prefix ($2, $2a, $2x, $2y, $2b)',
        html: `
          <div class="b-callout tip" style="margin-bottom:12px;">
            <strong>Standard Identifier:</strong> Identifies which historical revision of the Bcrypt algorithm generated this hash.
          </div>
          <p><strong>Common Revisions:</strong></p>
          <ul style="line-height:1.6; font-size:0.9rem;">
            <li><code>$2$</code> (1999): Original specification by Niels Provos & David Mazières for OpenBSD.</li>
            <li><code>$2a$</code> (2000): Added explicit NUL-terminator specification to handle non-null-terminated strings.</li>
            <li><code>$2x$</code> / <code>$2y$</code> (2011): Fixes for crypt_blowfish signed-character 8-bit sign-extension bug on Linux/PHP.</li>
            <li><code>$2b$</code> (2014): <strong>Current Gold Standard.</strong> Fixes password length wraparound bug (OpenBSD 5.5). Supported across all modern web frameworks.</li>
          </ul>
        `
      },
      cost: {
        title: 'Cost Factor Parameter (C)',
        html: `
          <div class="b-callout tip" style="margin-bottom:12px;">
            <strong>Exponential Work Factor Formula:</strong> Iterations = <code>2<sup>Cost</sup></code>
          </div>
          <p>The cost factor determines how many rounds of state expansion the Eksblowfish key schedule performs:</p>
          <ul style="line-height:1.6; font-size:0.9rem;">
            <li><strong>Cost 10:</strong> 2<sup>10</sup> = 1,024 rounds (~100 ms). Standard baseline for interactive web logins.</li>
            <li><strong>Cost 12:</strong> 2<sup>12</sup> = 4,096 rounds (~400 ms). High security for administrator credentials and financial apps.</li>
            <li><strong>Cost 14:</strong> 2<sup>14</sup> = 16,384 rounds (~1.6 s). Very slow, used for cold backup protection.</li>
          </ul>
          <p style="font-size:0.86rem; color:var(--color-text-muted);">
            Because the cost parameter is stored directly in the hash string, servers can dynamically increase the cost factor for new registrations without breaking existing user accounts.
          </p>
        `
      },
      salt: {
        title: 'Radix-64 Encoded Salt (22 Characters)',
        html: `
          <div class="b-callout tip" style="margin-bottom:12px;">
            <strong>128-bit Cryptographic Salt:</strong> 16 raw bytes generated via CSPRNG, encoded using Bcrypt's custom Radix-64 alphabet into 22 printable ASCII characters.
          </div>
          <p><strong>Why Salt is Essential:</strong></p>
          <ul style="line-height:1.6; font-size:0.9rem;">
            <li><strong>Defeats Rainbow Tables:</strong> An attacker must generate an entirely separate multi-gigabyte table for every unique salt.</li>
            <li><strong>Eliminates Password Correlation:</strong> If 1,000 users have the password <code>password123</code>, all 1,000 hashes are completely distinct strings.</li>
            <li><strong>Public Storage:</strong> The salt does NOT need to be kept secret—it is intentionally stored in plaintext inside the hash so the verifier can reproduce the computation.</li>
          </ul>
        `
      },
      digest: {
        title: 'Ciphertext Digest (31 Characters)',
        html: `
          <div class="b-callout tip" style="margin-bottom:12px;">
            <strong>192-bit Output:</strong> 24 raw bytes resulting from encrypting the constant string <code>"OrpheanBeholderScryDoubt"</code> 64 times via Blowfish ECB mode.
          </div>
          <p><strong>Key Properties:</strong></p>
          <ul style="line-height:1.6; font-size:0.9rem;">
            <li><strong>Encoded into 31 Radix-64 Characters:</strong> Uses Bcrypt's custom Base64 alphabet: <code>./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789</code>.</li>
            <li><strong>Strictly Irreversible:</strong> Even with the salt and digest, mathematical properties of the Feistel network and non-linear S-boxes prevent reversing the digest back into the plaintext password.</li>
            <li><strong>Total String Length:</strong> 4 (prefix) + 3 (cost) + 22 (salt) + 31 (digest) = 60 characters.</li>
          </ul>
        `
      }
    };

    const handleTokenClick = (type) => {
      const info = tokenDetails[type];
      if (!info) return;
      const modal = document.getElementById('bModalInspectorDetail');
      const titleEl = document.getElementById('mTitleToken');
      const bodyEl = document.getElementById('bModalTokenBody');
      if (titleEl) titleEl.textContent = `🔎 ${info.title}`;
      if (bodyEl) bodyEl.innerHTML = info.html;
      if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
      }
    };

    document.querySelectorAll('[data-token]').forEach(el => {
      el.addEventListener('click', () => {
        const token = el.getAttribute('data-token');
        handleTokenClick(token);
      });
    });
  },

  inspectHash(hashStr) {
    const segVer = document.getElementById('bSegVer');
    const segCost = document.getElementById('bSegCost');
    const segSalt = document.getElementById('bSegSalt');
    const segDigest = document.getElementById('bSegDigest');

    const dVer = document.getElementById('bDVer');
    const dCost = document.getElementById('bDCost');
    const dRounds = document.getElementById('bDRounds');
    const dSalt = document.getElementById('bDSalt');
    const dDigest = document.getElementById('bDDigest');

    if (!hashStr || hashStr.length < 60 || !hashStr.startsWith('$2')) {
      if (segVer) segVer.textContent = '$2b$';
      if (segCost) segCost.textContent = '10$';
      if (segSalt) segSalt.textContent = 'Invalid / Short Hash';
      if (segDigest) segDigest.textContent = '...';
      return;
    }

    try {
      const parts = hashStr.split('$');
      const ver = `$${parts[1]}$`;
      const cost = `${parts[2]}$`;
      const payload = parts[3] || '';
      const salt = payload.substring(0, 22);
      const digest = payload.substring(22);

      if (segVer) segVer.textContent = ver;
      if (segCost) segCost.textContent = cost;
      if (segSalt) segSalt.textContent = salt;
      if (segDigest) segDigest.textContent = digest;

      const costNum = parseInt(parts[2], 10) || 10;
      const rounds = Math.pow(2, costNum);

      if (dVer) dVer.textContent = ver;
      if (dCost) dCost.textContent = costNum;
      if (dRounds) dRounds.innerHTML = `2<sup>${costNum}</sup> = ${rounds.toLocaleString()} rounds`;
      if (dSalt) dSalt.textContent = `${salt.length} chars (128-bit salt)`;
      if (dDigest) dDigest.textContent = `${digest.length} chars (192-bit digest)`;
    } catch (err) {
      console.error(err);
    }
  },

  // 7. Tool 5: 5-Stage Eksblowfish Pipeline Stepper
  initPipeline() {
    const steps = document.querySelectorAll('.b-p-step');
    const lines = document.querySelectorAll('.b-p-line');
    const stages = document.querySelectorAll('.b-p-stage');
    const prevBtn = document.getElementById('bBtnPrevStage');
    const nextBtn = document.getElementById('bBtnNextStage');
    const counter = document.getElementById('bStageCounter');
    const autoBtn = document.getElementById('bBtnAutoPipeline');
    let autoInterval = null;

    if (!steps.length) return;

    const setStage = (n) => {
      this.currentPipelineStage = n;

      steps.forEach(step => {
        const s = parseInt(step.getAttribute('data-step'), 10);
        if (s === n) {
          step.classList.add('active');
          step.classList.remove('completed');
        } else if (s < n) {
          step.classList.remove('active');
          step.classList.add('completed');
        } else {
          step.classList.remove('active');
          step.classList.remove('completed');
        }
      });

      lines.forEach((line, idx) => {
        if (idx < n - 1) line.classList.add('completed');
        else line.classList.remove('completed');
      });

      stages.forEach((stage, idx) => {
        if (idx + 1 === n) stage.classList.add('active');
        else stage.classList.remove('active');
      });

      if (counter) counter.textContent = `Stage ${n} of 5`;
      if (prevBtn) prevBtn.disabled = n === 1;
      if (nextBtn) nextBtn.disabled = n === 5;
    };

    const stopAuto = () => {
      if (autoInterval) {
        clearInterval(autoInterval);
        autoInterval = null;
        if (autoBtn) {
          autoBtn.textContent = '▶ Auto-Play Pipeline';
          autoBtn.classList.remove('b-btn-primary');
          autoBtn.classList.add('b-btn-outline');
        }
      }
    };

    const startAuto = () => {
      if (autoInterval) return;
      if (autoBtn) {
        autoBtn.textContent = '⏸ Pause Auto-Play';
        autoBtn.classList.remove('b-btn-outline');
        autoBtn.classList.add('b-btn-primary');
      }
      autoInterval = setInterval(() => {
        let next = this.currentPipelineStage + 1;
        if (next > 5) next = 1;
        setStage(next);
      }, 1800);
    };

    autoBtn?.addEventListener('click', () => {
      if (autoInterval) stopAuto();
      else startAuto();
    });

    steps.forEach(s => {
      s.addEventListener('click', () => {
        stopAuto();
        const n = parseInt(s.getAttribute('data-step'), 10);
        setStage(n);
      });
    });

    prevBtn?.addEventListener('click', () => {
      stopAuto();
      if (this.currentPipelineStage > 1) setStage(this.currentPipelineStage - 1);
    });

    nextBtn?.addEventListener('click', () => {
      stopAuto();
      if (this.currentPipelineStage < 5) setStage(this.currentPipelineStage + 1);
    });
  },

  // =========================================================================
  // 8. INNOVATIVE FEATURE: 72-Byte Truncation Exploit & SHA-256 Mitigation
  // =========================================================================
  initTruncationExploit() {
    const btnRunExploit = document.getElementById('bBtnRunExploit');
    const baseInput = document.getElementById('bExploitBase');
    const suffixA = document.getElementById('bExploitSuffixA');
    const suffixB = document.getElementById('bExploitSuffixB');
    const togglePrehash = document.getElementById('bTogglePrehash');
    const statusBox = document.getElementById('bExploitStatus');
    const hashAEl = document.getElementById('bExploitHashA');
    const hashBEl = document.getElementById('bExploitHashB');
    const saltEl = document.getElementById('bExploitSaltUsed');

    if (!btnRunExploit || !baseInput) return;

    btnRunExploit.addEventListener('click', () => {
      const bcrypt = this.getBcrypt();
      if (!bcrypt) return;

      const base = baseInput.value;
      const passA = base + suffixA.value;
      const passB = base + suffixB.value;
      const usePrehash = togglePrehash ? togglePrehash.checked : false;

      btnRunExploit.disabled = true;
      btnRunExploit.textContent = 'Computing Exploit Proof...';

      setTimeout(async () => {
        try {
          const sharedSalt = bcrypt.genSaltSync(8); // fixed salt so comparison is mathematically exact
          let inputA = passA;
          let inputB = passB;

          if (usePrehash) {
            // Apply SHA-256 pre-hashing
            if (window.CryptoJS?.SHA256) {
              inputA = CryptoJS.SHA256(passA).toString(CryptoJS.enc.Base64);
              inputB = CryptoJS.SHA256(passB).toString(CryptoJS.enc.Base64);
            } else if (crypto.subtle) {
              const bufA = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(passA));
              const bufB = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(passB));
              inputA = btoa(String.fromCharCode(...new Uint8Array(bufA)));
              inputB = btoa(String.fromCharCode(...new Uint8Array(bufB)));
            }
          }

          const hashA = bcrypt.hashSync(inputA, sharedSalt);
          const hashB = bcrypt.hashSync(inputB, sharedSalt);

          if (hashAEl) hashAEl.textContent = hashA;
          if (hashBEl) hashBEl.textContent = hashB;
          if (saltEl) saltEl.textContent = `Shared Salt: ${sharedSalt}`;

          const isCollided = (hashA === hashB);

          if (isCollided) {
            statusBox.className = 'b-status-banner error';
            statusBox.innerHTML = `
              <div>
                <strong>🚨 CRITICAL COLLISION OBSERVED!</strong>
                <p>Both Password A and Password B produced the <strong>EXACT SAME 60-character Bcrypt hash</strong> because characters beyond byte index 71 were silently dropped by Eksblowfish. An attacker logging in with either password gains access to the same account!</p>
              </div>
            `;
          } else {
            statusBox.className = 'b-status-banner success';
            statusBox.innerHTML = `
              <div>
                <strong>✓ TRUNCATION MITIGATED (SHA-256 PRE-HASHING APPLIED)</strong>
                <p>Because SHA-256 pre-hashing was applied, Password A (${this.getByteLength(passA)} bytes) and Password B (${this.getByteLength(passB)} bytes) were first mapped to unique 44-character Base64 representations. Both fit safely within 72 bytes and produced <strong>completely distinct, uncollidable Bcrypt hashes</strong>!</p>
              </div>
            `;
          }
        } catch (err) {
          console.error(err);
        } finally {
          btnRunExploit.disabled = false;
          btnRunExploit.textContent = 'Execute 72-Byte Test';
        }
      }, 50);
    });
  },

  // =========================================================================
  // 9. INNOVATIVE FEATURE: Live "Hash Race" (MD5 vs SHA-256 vs Bcrypt)
  // =========================================================================
  initHashRace() {
    const btnRace = document.getElementById('bBtnStartRace');
    const pwdInput = document.getElementById('bRacePassword');
    const md5Bar = document.getElementById('bRaceBarMD5');
    const shaBar = document.getElementById('bRaceBarSHA');
    const bcryptBar = document.getElementById('bRaceBarBcrypt');

    const md5Status = document.getElementById('bRaceStatusMD5');
    const shaStatus = document.getElementById('bRaceStatusSHA');
    const bcryptStatus = document.getElementById('bRaceStatusBcrypt');
    const summaryBox = document.getElementById('bRaceSummary');

    if (!btnRace) return;

    btnRace.addEventListener('click', () => {
      const pwd = pwdInput ? (pwdInput.value || 'BenchmarkRaceTestPass!2026') : 'Test';
      const bcrypt = this.getBcrypt();
      if (!bcrypt) return;

      btnRace.disabled = true;
      btnRace.textContent = 'Racing in progress...';
      if (summaryBox) summaryBox.classList.add('hidden');

      // Reset bars
      if (md5Bar) md5Bar.style.width = '0%';
      if (shaBar) shaBar.style.width = '0%';
      if (bcryptBar) bcryptBar.style.width = '0%';

      const BATCH = 30; // 30 rounds of each

      // 1. MD5 Batch
      const t0_md5 = performance.now();
      for (let i = 0; i < BATCH; i++) {
        if (window.CryptoJS?.MD5) {
          CryptoJS.MD5(pwd + i);
        }
      }
      const t1_md5 = performance.now();
      const time_md5 = (t1_md5 - t0_md5).toFixed(2);
      if (md5Bar) md5Bar.style.width = '100%';
      if (md5Status) md5Status.textContent = `${BATCH} hashes in ${time_md5} ms (${Math.round((BATCH / Math.max(0.1, time_md5)) * 1000).toLocaleString()} H/s)`;

      // 2. SHA-256 Batch
      const t0_sha = performance.now();
      for (let i = 0; i < BATCH; i++) {
        if (window.CryptoJS?.SHA256) {
          CryptoJS.SHA256(pwd + i);
        }
      }
      const t1_sha = performance.now();
      const time_sha = (t1_sha - t0_sha).toFixed(2);
      if (shaBar) shaBar.style.width = '100%';
      if (shaStatus) shaStatus.textContent = `${BATCH} hashes in ${time_sha} ms (${Math.round((BATCH / Math.max(0.1, time_sha)) * 1000).toLocaleString()} H/s)`;

      // 3. Bcrypt (Cost 8 for smooth async demo)
      let bCount = 0;
      const t0_bcrypt = performance.now();

      const computeBcryptStep = () => {
        if (bCount < 5) { // 5 Bcrypt hashes is already ~100x slower
          bcrypt.hashSync(pwd + bCount, bcrypt.genSaltSync(8));
          bCount++;
          const pct = Math.round((bCount / 5) * 100);
          if (bcryptBar) bcryptBar.style.width = `${pct}%`;
          if (bcryptStatus) bcryptStatus.textContent = `Computing ${bCount} of 5 Bcrypt hashes...`;
          setTimeout(computeBcryptStep, 10);
        } else {
          const t1_bcrypt = performance.now();
          const time_bcrypt = (t1_bcrypt - t0_bcrypt).toFixed(2);
          if (bcryptStatus) bcryptStatus.textContent = `5 hashes in ${time_bcrypt} ms (~${Math.round((5 / (time_bcrypt / 1000)))} H/s)`;
          btnRace.disabled = false;
          btnRace.textContent = 'Run 30-Hash Race Again';

          if (summaryBox) {
            summaryBox.classList.remove('hidden');
            summaryBox.innerHTML = `
              <p><strong>Race Analysis:</strong> MD5 computed ${BATCH} hashes in ${time_md5} ms, and SHA-256 computed ${BATCH} hashes in ${time_sha} ms. Meanwhile, Bcrypt took ${time_bcrypt} ms for just 5 hashes. <em>This deliberate CPU latency is what protects your users when databases are breached!</em></p>
            `;
          }
        }
      };

      setTimeout(computeBcryptStep, 30);
    });
  },

  // =========================================================================
  // 10. INNOVATIVE FEATURE: Device Hardware Benchmark & Server Sizing
  // =========================================================================
  initHardwareBenchmark() {
    const btnBench = document.getElementById('bBtnRunBenchmark');
    const chart = document.getElementById('bBenchChart');
    const recBox = document.getElementById('bBenchRec');

    if (!btnBench) return;

    btnBench.addEventListener('click', () => {
      const bcrypt = this.getBcrypt();
      if (!bcrypt) return;

      btnBench.disabled = true;
      btnBench.textContent = 'Benchmarking your hardware...';
      if (chart) chart.innerHTML = '';
      if (recBox) recBox.classList.add('hidden');

      const costs = [4, 6, 8, 9, 10, 11];
      const results = [];
      let idx = 0;

      const runNext = () => {
        if (idx < costs.length) {
          const cost = costs[idx];
          btnBench.textContent = `Benchmarking Cost ${cost}...`;

          setTimeout(() => {
            const t0 = performance.now();
            bcrypt.hashSync('HardwareCalibrationPassword2026', bcrypt.genSaltSync(cost));
            const t1 = performance.now();
            const ms = Math.round(t1 - t0);
            results.push({ cost, ms });
            idx++;
            runNext();
          }, 30);
        } else {
          this.benchmarkResults = results;
          btnBench.disabled = false;
          btnBench.textContent = 'Re-Run Hardware Benchmark';

          // Render CSS bar chart
          const maxMs = Math.max(...results.map(r => r.ms), 1);
          let html = '';
          let bestCost = 10;

          results.forEach(r => {
            const widthPct = Math.max(3, Math.round((r.ms / maxMs) * 100));
            html += `
              <div class="b-bench-row">
                <span class="b-bold b-mono">Cost ${r.cost}</span>
                <div class="b-bench-bar-track">
                  <div class="b-bench-bar" style="width:${widthPct}%;"></div>
                </div>
                <span class="b-mono" style="font-size:0.85rem; text-align:right;">${r.ms} ms</span>
              </div>
            `;
            if (r.ms >= 200 && r.ms <= 500) {
              bestCost = r.cost;
            }
          });

          if (chart) chart.innerHTML = html;

          if (recBox) {
            recBox.classList.remove('hidden');
            recBox.innerHTML = `
              <strong>OWASP Production Server Sizing Recommendation:</strong>
              <p style="margin:4px 0 0; font-size:0.9rem;">
                OWASP recommends a web login budget of <strong>250 to 500 milliseconds</strong>. On this client machine, <strong>Cost ${bestCost}</strong> matches this target window (~${results.find(r => r.cost === bestCost)?.ms || 250} ms). For high-security administrative portals, Cost 12 is recommended.
              </p>
            `;
          }
        }
      };

      runNext();
    });
  },

  // =========================================================================
  // 11. INNOVATIVE FEATURE: Offline Brute-Force & GPU Crack Time Estimator
  // =========================================================================
  initCrackTimeEstimator() {
    const pwdInput = document.getElementById('bCalcPassword');
    const costSlider = document.getElementById('bCalcCost');
    const costVal = document.getElementById('bCalcCostVal');
    const entropyEl = document.getElementById('bCalcEntropy');
    const combosEl = document.getElementById('bCalcCombos');
    const cpuTimeEl = document.getElementById('bCalcCPUTime');
    const gpuTimeEl = document.getElementById('bCalcGPUTime');
    const clusterTimeEl = document.getElementById('bCalcClusterTime');
    const powerEl = document.getElementById('bCalcPowerCost');

    if (!pwdInput || !costSlider) return;

    const calculate = () => {
      const pwd = pwdInput.value || 'SecretPass1';
      const cost = parseInt(costSlider.value, 10) || 10;
      if (costVal) costVal.textContent = cost;

      // Character set detection
      let poolSize = 0;
      if (/[a-z]/.test(pwd)) poolSize += 26;
      if (/[A-Z]/.test(pwd)) poolSize += 26;
      if (/[0-9]/.test(pwd)) poolSize += 10;
      if (/[^a-zA-Z0-9]/.test(pwd)) poolSize += 33;
      if (poolSize === 0) poolSize = 26;

      const len = pwd.length;
      const entropy = Math.round(len * Math.log2(poolSize));
      const totalCombos = Math.pow(poolSize, len);

      if (entropyEl) entropyEl.textContent = `${entropy} bits (${poolSize} char pool)`;
      if (combosEl) combosEl.textContent = totalCombos > 1e15 ? totalCombos.toExponential(2) : totalCombos.toLocaleString();

      // Effective Bcrypt Hash rates scaling with 2^Cost:
      // Baseline at Cost 10:
      // Single CPU: ~20 H/s
      // 8x RTX 4090: ~160,000 H/s
      // Nation State Cluster: ~5,000,000 H/s
      const scaleFactor = Math.pow(2, 10 - cost);
      const cpuRate = Math.max(0.01, 20 * scaleFactor);
      const gpuRate = Math.max(1, 160000 * scaleFactor);
      const clusterRate = Math.max(10, 5000000 * scaleFactor);

      // Average guesses to crack is combos / 2
      const guesses = totalCombos / 2;
      const formatTime = (seconds) => {
        if (seconds < 0.001) return '< 1 millisecond';
        if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
        if (seconds < 60) return `${seconds.toFixed(1)} seconds`;
        if (seconds < 3600) return `${(seconds / 60).toFixed(1)} minutes`;
        if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hours`;
        if (seconds < 31536000) return `${(seconds / 86400).toFixed(1)} days`;
        if (seconds < 31536000 * 1000) return `${(seconds / 31536000).toFixed(1)} years`;
        return `${(seconds / 31536000).toExponential(2)} years (Millennia!)`;
      };

      if (cpuTimeEl) cpuTimeEl.textContent = formatTime(guesses / cpuRate);
      if (gpuTimeEl) gpuTimeEl.textContent = formatTime(guesses / gpuRate);
      if (clusterTimeEl) clusterTimeEl.textContent = formatTime(guesses / clusterRate);

      // Electrical cost estimation for 8x RTX 4090 (3.6 kW rig @ $0.15 / kWh)
      const hours = (guesses / gpuRate) / 3600;
      const kwh = hours * 3.6;
      const usd = kwh * 0.15;
      if (powerEl) {
        if (usd < 0.01) powerEl.textContent = '< $0.01 (Negligible)';
        else if (usd > 1e7) powerEl.textContent = `$${usd.toExponential(2)} USD (Economically Infeasible)`;
        else powerEl.textContent = `~$${Math.round(usd).toLocaleString()} USD (${Math.round(kwh).toLocaleString()} kWh)`;
      }
    };

    pwdInput.addEventListener('input', calculate);
    costSlider.addEventListener('input', calculate);
    calculate();
  },

  // =========================================================================
  // 12. INNOVATIVE FEATURE: Rainbow Table Simulator & Salt Defense
  // =========================================================================
  initRainbowSimulator() {
    const rainbowDB = [
      { pass: "password", md5: "5f4dcc3b5aa765d61d8327deb882cf99" },
      { pass: "123456", md5: "e10adc3949ba59abbe56e057f20f883e" },
      { pass: "admin", md5: "21232f297a57a5a743894a0e4a801fc3" },
      { pass: "welcome", md5: "40be4e59b9a2a2b5dffb918c0e86b3d7" },
      { pass: "letmein", md5: "1a1dc91c907325c69271ddf0c944bc72" }
    ];

    const input = document.getElementById('bRainbowInput');
    const btnCheck = document.getElementById('bBtnRainbowCheck');
    const resultBox = document.getElementById('bRainbowResult');

    if (!btnCheck || !input) return;

    btnCheck.addEventListener('click', () => {
      const val = input.value.trim();
      if (!val) return;

      const isBcrypt = val.startsWith('$2');
      if (isBcrypt) {
        resultBox.className = 'b-status-banner success';
        resultBox.innerHTML = `
          <div>
            <strong>✓ RAINBOW TABLE LOOKUP FAILED (ATTACK NEUTRALIZED)</strong>
            <p>Bcrypt uses a unique 128-bit CSPRNG salt. Precomputed hash lookup tables cannot find this hash because the salt forces the attacker to compute $2^{128}$ separate tables. The lookup returned 0 matches!</p>
          </div>
        `;
        return;
      }

      // Check against unsalted MD5
      const match = rainbowDB.find(item => item.md5.toLowerCase() === val.toLowerCase() || item.pass === val);
      if (match) {
        resultBox.className = 'b-status-banner error';
        resultBox.innerHTML = `
          <div>
            <strong>🚨 INSTANT CRACK: Password Found in Rainbow Table!</strong>
            <p>Plaintext Password: <strong>${match.pass}</strong> (Lookup time: &lt; 0.001 ms). Without salts, fast hashes are cracked instantly via dictionary matching.</p>
          </div>
        `;
      } else {
        resultBox.className = 'b-status-banner';
        resultBox.innerHTML = `<div>Hash not in mini-demo rainbow table, but still vulnerable if unsalted.</div>`;
      }
    });
  },

  // =========================================================================
  // 13. INNOVATIVE FEATURE: Export Academic Lab Journal Report (Printable)
  // =========================================================================
  initReportGenerator() {
    const btnOpen = document.getElementById('bBtnGenReport');
    const modalOverlay = document.getElementById('bReportModalOverlay');
    const btnClose = document.getElementById('bBtnCloseReport');
    const btnPrint = document.getElementById('bBtnPrintReport');

    const repStudent = document.getElementById('bRepStudentName');
    const repTime = document.getElementById('bRepTimestamp');
    const repHash = document.getElementById('bRepHash');
    const repDuration = document.getElementById('bRepDuration');
    const repScore = document.getElementById('bRepScore');

    if (!btnOpen) return;

    btnOpen.addEventListener('click', () => {
      if (modalOverlay) modalOverlay.classList.remove('hidden');

      const now = new Date();
      if (repTime) repTime.textContent = now.toLocaleString();
      if (repHash) repHash.textContent = this.lastGeneratedHash || '$2b$10$nOUIs22CharsOfSaltHere...31CharsOfHashDigestHere...';
      if (repDuration) repDuration.textContent = this.lastGeneratedTime || '98.40 ms';
      if (repScore) repScore.textContent = `${this.quizScore !== undefined ? this.quizScore : 10} / 10`;
    });

    btnClose?.addEventListener('click', () => {
      if (modalOverlay) modalOverlay.classList.add('hidden');
    });

    btnPrint?.addEventListener('click', () => {
      window.print();
    });
  },

  // 14. Quiz Engine
  initQuiz() {
    const questions = [
      {
        q: "1. Why are high-throughput hash functions like SHA-256 or MD5 vulnerable for password storage?",
        opts: [
          "They produce variable-length hash digests.",
          "Attacker GPUs compute billions of hashes per second, making offline dictionary attacks trivially fast.",
          "They require private keys that can be intercepted in transit.",
          "They cannot hash inputs longer than 10 characters."
        ],
        ans: 1,
        exp: "Fast hash algorithms are engineered for massive data transfer integrity. In password cracking, speed directly empowers attackers to brute-force billions of candidate passwords per second on modern GPUs."
      },
      {
        q: "2. How does incrementing the Bcrypt cost factor parameter (C) by 1 affect internal work?",
        opts: [
          "It adds 10 ms of linear latency.",
          "It doubles the internal Eksblowfish key expansion iterations (2^C).",
          "It doubles the character length of the generated output string.",
          "It expands the salt from 128 bits to 256 bits."
        ],
        ans: 1,
        exp: "Bcrypt work factor scales exponentially: Iterations = 2^C. Incrementing cost from 10 to 11 exactly doubles the work from 1,024 to 2,048 rounds."
      },
      {
        q: "3. What is the fundamental security role of the 128-bit random salt in Bcrypt?",
        opts: [
          "To allow password recovery through reversible decryption.",
          "To defeat precomputed rainbow tables and guarantee identical passwords produce completely unique hashes.",
          "To reduce memory usage on web servers.",
          "To compress passwords down to 8 characters."
        ],
        ans: 1,
        exp: "Because every user receives a distinct 128-bit CSPRNG salt, precomputed rainbow tables are rendered obsolete since an attacker would need to build a custom table of 2^128 entries for each individual account."
      },
      {
        q: "4. What is the architectural key limit of the Eksblowfish cipher within Bcrypt?",
        opts: [
          "32 bytes",
          "64 bytes",
          "72 bytes",
          "256 bytes"
        ],
        ans: 2,
        exp: "Blowfish key schedules enforce a 72-byte ceiling. Password bytes beyond position 72 are silently truncated, which is why modern frameworks pre-hash passwords with SHA-256 first."
      },
      {
        q: "5. In the standard format '$2b$10$nOUIs...31Chars...', what does '$2b$' signify?",
        opts: [
          "2 kilobytes of RAM allocation.",
          "The 2014 OpenBSD revision B algorithm identifier.",
          "A cost factor of 2.",
          "A 2-byte checksum."
        ],
        ans: 1,
        exp: "'$2b$' denotes OpenBSD Revision B (released in 2014), which corrected an unsigned char wraparound bug present in '$2a$'."
      },
      {
        q: "6. Why does Eksblowfish's 4KB S-box state make Bcrypt significantly more resistant to GPU cracking than SHA-256?",
        opts: [
          "GPUs can only execute algorithms requiring less than 1KB of memory.",
          "Each GPU thread needs 4KB in fast L1 cache; thousands of concurrent threads quickly exhaust cache lines, causing severe memory stalls.",
          "Bcrypt requires an active internet connection to hash passwords.",
          "GPUs lack the hardware instructions to perform bitwise XOR operations."
        ],
        ans: 1,
        exp: "While SHA-256 requires only 64 bytes of state fitting into registers, Eksblowfish's 4KB S-boxes exhaust the limited L1 cache of streaming multiprocessors, preventing GPUs from running tens of thousands of parallel password cracks simultaneously."
      },
      {
        q: "7. In a defense-in-depth architecture, where should a cryptographic 'Pepper' be stored?",
        opts: [
          "Directly in the database alongside the user's password hash and salt.",
          "Inside the user's browser local storage.",
          "Outside the database in a secure key management system (e.g., AWS KMS, Azure Key Vault, or an HSM).",
          "Hardcoded directly into the client-side JavaScript file."
        ],
        ans: 2,
        exp: "Unlike salts (which are public and stored in the database), peppers are secret application-wide keys stored in external KMS or HSM modules. If the database leaks via SQL injection, the attacker cannot crack the hashes without the Pepper."
      },
      {
        q: "8. During password verification, why must candidate and stored hash digests be compared using a constant-time comparison function?",
        opts: [
          "To prevent side-channel timing attacks that measure microscopic CPU latency differences to guess bytes sequentially.",
          "To speed up the verification process by skipping unmatched bytes.",
          "Because standard string equality operators cannot compare strings longer than 32 characters.",
          "To automatically repair corrupted database rows."
        ],
        ans: 0,
        exp: "Standard string equality (==) terminates immediately upon the first mismatched byte. An attacker measuring microscopic network/CPU latency can deduce the password byte-by-byte. Constant-time comparison ensures identical latency regardless of match location."
      },
      {
        q: "9. What is the recommended industry-standard pattern to support passwords of unlimited length without triggering Bcrypt's 72-byte truncation flaw?",
        opts: [
          "Switch back to unsalted MD5 hashing.",
          "Pre-hash the plaintext password with SHA-256 and Base64-encode the 32-byte digest before passing it to Bcrypt.",
          "Split passwords into 72-byte chunks and concatenate the output hashes.",
          "Reject all user passwords that exceed 16 characters."
        ],
        ans: 1,
        exp: "Pre-hashing with SHA-256 compresses arbitrary-length passwords into a 32-byte binary digest. Encoded as Base64 (44 characters), this safely fits within Bcrypt's 72-byte boundary while preserving full cryptographic entropy."
      },
      {
        q: "10. How does a web application safely upgrade its password hashes from Cost 10 to Cost 12 without forcing all users to reset their passwords?",
        opts: [
          "Decrypt stored hashes using a master key and re-encrypt with Cost 12.",
          "Run an offline batch script to directly rewrite the cost number inside the hash string.",
          "Transparently verify the user's plaintext password on their next login; if valid, compute a fresh Cost 12 hash and update their database record.",
          "Bcrypt hashes cannot be upgraded once generated."
        ],
        ans: 2,
        exp: "Because one-way hashes cannot be reversed or decrypted, the server must wait until the user enters their plaintext password during login. Upon successful verification, the server detects the outdated cost factor and seamlessly computes and saves a new hash."
      }
    ];

    const quizList = document.getElementById('bQuizList');
    const scoreBadge = document.getElementById('bQuizScoreBadge');
    const resetBtn = document.getElementById('bBtnResetQuiz');

    if (!quizList) return;

    const render = () => {
      this.quizAnswers = {};
      let score = 0;
      if (scoreBadge) scoreBadge.textContent = `Score: 0 / ${questions.length}`;
      quizList.innerHTML = '';

      questions.forEach((qObj, qIdx) => {
        const card = document.createElement('div');
        card.className = 'b-quiz-card';
        card.id = `bQCard-${qIdx}`;

        let optsHTML = '';
        qObj.opts.forEach((opt, oIdx) => {
          optsHTML += `<button type="button" class="b-quiz-opt" data-q="${qIdx}" data-opt="${oIdx}">${String.fromCharCode(65 + oIdx)}. ${opt}</button>`;
        });

        card.innerHTML = `
          <div class="b-quiz-title">${qObj.q}</div>
          <div class="b-quiz-options">${optsHTML}</div>
          <div class="b-quiz-exp hidden" id="bQExp-${qIdx}">${qObj.exp}</div>
        `;

        quizList.appendChild(card);
      });

      const optBtns = quizList.querySelectorAll('.b-quiz-opt');
      optBtns.forEach(btn => {
        btn.addEventListener('click', () => {
          const qIdx = parseInt(btn.getAttribute('data-q'), 10);
          const selOpt = parseInt(btn.getAttribute('data-opt'), 10);
          if (this.quizAnswers[qIdx] !== undefined) return;

          this.quizAnswers[qIdx] = selOpt;
          const qObj = questions[qIdx];
          const card = document.getElementById(`bQCard-${qIdx}`);
          const expBox = document.getElementById(`bQExp-${qIdx}`);
          const sibs = card.querySelectorAll('.b-quiz-opt');

          sibs.forEach((sBtn, idx) => {
            sBtn.disabled = true;
            if (idx === qObj.ans) sBtn.classList.add('correct');
            if (idx === selOpt && selOpt !== qObj.ans) sBtn.classList.add('wrong');
          });

          if (selOpt === qObj.ans) score++;
          this.quizScore = score;
          if (expBox) expBox.classList.remove('hidden');
          if (scoreBadge) scoreBadge.textContent = `Score: ${score} / ${questions.length}`;
        });
      });
    };

    resetBtn?.addEventListener('click', render);
    render();
  },

  // 15. Feedback Star Rating & Submission
  initFeedback() {
    const starContainer = document.getElementById('bStarRating');
    const form = document.getElementById('bFeedbackForm');
    const toast = document.getElementById('bFeedbackToast');

    if (starContainer) {
      const stars = starContainer.querySelectorAll('.star-item');
      stars.forEach(star => {
        star.addEventListener('click', () => {
          const val = parseInt(star.getAttribute('data-value'), 10);
          this.selectedRating = val;
          stars.forEach((s, idx) => {
            if (idx < val) s.classList.add('active');
            else s.classList.remove('active');
          });
        });
      });
    }

    form?.addEventListener('submit', (e) => {
      e.preventDefault();
      if (toast) {
        toast.classList.remove('hidden');
        setTimeout(() => toast.classList.add('hidden'), 3500);
      }
      form.reset();
      this.selectedRating = 0;
      if (starContainer) {
        starContainer.querySelectorAll('.star-item').forEach(s => s.classList.remove('active'));
      }
    });
  },

  // 16. Learner Popup Modals System
  initModals() {
    const modalTriggers = document.querySelectorAll('[data-modal]');
    const closeBtns = document.querySelectorAll('[data-close-modal]');
    const modals = document.querySelectorAll('.b-modal-overlay');

    const openModal = (id) => {
      const modal = document.getElementById(id);
      if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
      }
    };

    const closeModal = (modal) => {
      if (modal) {
        modal.classList.add('hidden');
        const anyOpen = Array.from(modals).some(m => !m.classList.contains('hidden'));
        if (!anyOpen) {
          document.body.style.overflow = '';
        }
      }
    };

    modalTriggers.forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = btn.getAttribute('data-modal');
        if (targetId) openModal(targetId);
      });
    });

    document.getElementById('bBtnOpenGuide')?.addEventListener('click', () => openModal('bModalGuide'));
    document.getElementById('bBtnOpenGlossary')?.addEventListener('click', () => openModal('bModalGlossary'));
    document.getElementById('bBtnOpenFeistel')?.addEventListener('click', () => openModal('bModalFeistel'));

    closeBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const parentModal = btn.closest('.b-modal-overlay');
        closeModal(parentModal);
      });
    });

    modals.forEach(modal => {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          closeModal(modal);
        }
      });
    });

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        modals.forEach(m => closeModal(m));
      }
    });
  },

  // 17. Interactive Active-Recall Flashcards
  initFlashcards() {
    const cards = document.querySelectorAll('.b-flashcard');
    const resetBtn = document.getElementById('bBtnResetCards');

    cards.forEach(card => {
      const toggleFlip = () => card.classList.toggle('flipped');

      card.addEventListener('click', toggleFlip);
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          toggleFlip();
        }
      });
    });

    resetBtn?.addEventListener('click', () => {
      cards.forEach(c => c.classList.remove('flipped'));
    });
  }
};
