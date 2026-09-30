/* ==========================================================================
   Virtual Cryptography Lab - Module 11: Bcrypt Password Hashing
   Experiment Logic & Interactive Widgets
   Client-Side Execution using Bundled bcrypt.min.js
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  BcryptLabModule.init();
});

const BcryptLabModule = {
  currentPipelineStage: 1,
  selectedRating: 0,
  quizAnswers: {},
  generatedSalts: [],

  init() {
    this.initSubtabs();
    this.initByteCounter();
    this.initHashGenerator();
    this.initVerifier();
    this.initSaltDemo();
    this.initInspector();
    this.initPipeline();
    this.initQuiz();
    this.initFeedback();
  },

  getBcrypt() {
    return window.dcodeIO?.bcrypt || window.bcrypt;
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
      const bytes = new TextEncoder().encode(val).length;
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

  // 3. Tool A: Live Bcrypt Hash Generator
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

    if (!form) return;

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

          if (placeholder) placeholder.classList.add('hidden');
          if (outputArea) outputArea.classList.remove('hidden');

          if (hashText) hashText.textContent = hash;
          if (timeEl) timeEl.textContent = `${duration} ms`;
          if (roundsEl) roundsEl.textContent = Math.pow(2, cost).toLocaleString();
          if (lenEl) lenEl.textContent = `${hash.length} chars`;

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

  // 4. Tool B: Password Match Verifier
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

  // 5. Tool C: Non-Deterministic Salt Demonstration
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

  // 6. Tool D: Modular Hash String Inspector
  initInspector() {
    const input = document.getElementById('bInspectInput');
    if (input) {
      input.addEventListener('input', (e) => this.inspectHash(e.target.value.trim()));
      this.inspectHash(input.value.trim());
    }
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

  // 7. Tool E: 5-Stage Eksblowfish Pipeline Stepper
  initPipeline() {
    const steps = document.querySelectorAll('.b-p-step');
    const lines = document.querySelectorAll('.b-p-line');
    const stages = document.querySelectorAll('.b-p-stage');
    const prevBtn = document.getElementById('bBtnPrevStage');
    const nextBtn = document.getElementById('bBtnNextStage');
    const counter = document.getElementById('bStageCounter');

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

    steps.forEach(s => {
      s.addEventListener('click', () => {
        const n = parseInt(s.getAttribute('data-step'), 10);
        setStage(n);
      });
    });

    prevBtn?.addEventListener('click', () => {
      if (this.currentPipelineStage > 1) setStage(this.currentPipelineStage - 1);
    });

    nextBtn?.addEventListener('click', () => {
      if (this.currentPipelineStage < 5) setStage(this.currentPipelineStage + 1);
    });
  },

  // 8. Quiz Engine
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
        exp: "Bcrypt work factor scales exponentially: Iterations = 2^C. Incrementing cost from 10 to 11 doubles the work from 1,024 to 2,048 rounds."
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
          if (expBox) expBox.classList.remove('hidden');
          if (scoreBadge) scoreBadge.textContent = `Score: ${score} / ${questions.length}`;
        });
      });
    };

    resetBtn?.addEventListener('click', render);
    render();
  },

  // 9. Feedback Star Rating & Submission
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
  }
};
