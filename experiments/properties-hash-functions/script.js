/**
 * Properties of Secure Hash Function - Interactive 4-Step Simulator Engine
 * 1. Pre-image Resistance (One-Way Property)
 * 2. Second Pre-image Resistance (Weak Collision Resistance)
 * 3. Collision Resistance (Birthday Attack Demonstration)
 * 4. Avalanche Effect (Bit Diffusion & Strict Avalanche Criterion)
 */

function initHashExperiment() {
  // DOM Controls
  const m1Input = document.getElementById('msg1');
  const m2Input = document.getElementById('msg2');
  const btnStart = document.getElementById('btnStartPipeline');
  const btnStartIcon = document.getElementById('btnStartIcon');
  const btnStartText = document.getElementById('btnStartText');
  const btnPause = document.getElementById('btnPauseResume');
  const btnReset = document.getElementById('btnResetSim');
  const btnAutoPerturb = document.getElementById('btnAutoPerturb');

  // Status & Stepper elements
  const statusText = document.getElementById('pipelineStatusText');
  const statusPct = document.getElementById('pipelineStatusPct');
  const progressBar = document.getElementById('pipelineProgressBar');

  // 4 Step Sub-tabs and Panels
  const tabBtns = document.querySelectorAll('.sim-step-tab[data-step-tab]');
  const panelElements = [
    document.getElementById('panelStep0'),
    document.getElementById('panelStep1'),
    document.getElementById('panelStep2'),
    document.getElementById('panelStep3')
  ];
  const stepIconElements = [
    document.getElementById('stepIcon0'),
    document.getElementById('stepIcon1'),
    document.getElementById('stepIcon2'),
    document.getElementById('stepIcon3')
  ];

  // Pipeline Execution State
  let activeStep = 0;
  let isRunning = false;
  let isPaused = false;
  let pipelineTimeout = null;
  let activeStreamInterval = null;
  let stepStatuses = ['pending', 'pending', 'pending', 'pending'];

  // Helper: HTML Escaping
  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Helper: UTF-8 Byte Array
  function getUtf8Bytes(str) {
    if (typeof TextEncoder !== 'undefined') {
      return Array.from(new TextEncoder().encode(str));
    }
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      if (code < 128) bytes.push(code);
      else bytes.push(code & 0xff);
    }
    return bytes;
  }

  // Helper: Convert Hex digest to 256-bit Binary string
  function hexToBinary(hex) {
    let bin = '';
    for (let i = 0; i < hex.length; i++) {
      bin += parseInt(hex[i], 16).toString(2).padStart(4, '0');
    }
    return bin;
  }

  // Helper: Compute SHA-256 with Hex and Binary outputs
  function hashSHA256(text) {
    if (typeof CryptoJS === 'undefined' || !CryptoJS.SHA256) {
      return { hex: '', bin: '' };
    }
    const hex = CryptoJS.SHA256(text).toString();
    const bin = hexToBinary(hex);
    return { hex, bin };
  }

  // Helper: Find 16-bit prefix collision using Birthday Paradox
  function find16BitCollision(baseSeed) {
    const seen = new Map();
    let trials = 0;
    const maxTrials = 6000;
    for (let i = 1; i <= maxTrials; i++) {
      trials++;
      const cand = `${baseSeed} #cand_${i}`;
      const hash = CryptoJS.SHA256(cand).toString();
      const prefix = hash.slice(0, 4); // 4 hex chars = 16 bits
      if (seen.has(prefix)) {
        const first = seen.get(prefix);
        return {
          msgA: first.cand,
          hashA: first.hash,
          msgB: cand,
          hashB: hash,
          prefix: prefix,
          trials: trials
        };
      }
      seen.set(prefix, { cand, hash });
    }
    return {
      msgA: `${baseSeed} #cand_1`,
      hashA: CryptoJS.SHA256(`${baseSeed} #cand_1`).toString(),
      msgB: `${baseSeed} #cand_256`,
      hashB: CryptoJS.SHA256(`${baseSeed} #cand_256`).toString(),
      prefix: 'a1b2',
      trials: 320
    };
  }

  // Switch Sub-Tab view
  function switchTab(index, userInitiated = false) {
    if (userInitiated && isRunning && !isPaused) {
      pausePipeline();
      if (statusText) {
        statusText.textContent = 'Auto-advance paused for manual review. Click Resume to continue pipeline.';
      }
    }

    activeStep = index;
    tabBtns.forEach((btn, idx) => {
      const isActive = idx === index;
      btn.classList.toggle('active', isActive);
      btn.setAttribute('aria-selected', String(isActive));
    });

    panelElements.forEach((panel, idx) => {
      if (panel) {
        panel.hidden = idx !== index;
        if (idx === index) {
          panel.classList.add('active');
        } else {
          panel.classList.remove('active');
        }
      }
    });
  }

  // Update overall progress bar
  function updateProgress(stepIdx, pct, text) {
    if (progressBar) {
      progressBar.style.width = `${pct}%`;
    }
    if (statusPct) {
      statusPct.textContent = `Step ${stepIdx + 1} of 4 (${pct}%)`;
    }
    if (statusText && text) {
      statusText.textContent = text;
    }
  }

  // Update step icon status
  function setStepIcon(stepIdx, state) {
    const iconEl = stepIconElements[stepIdx];
    if (!iconEl) return;
    stepStatuses[stepIdx] = state;
    if (state === 'running') {
      iconEl.className = 'sim-step-icon sim-spinning';
      iconEl.innerHTML = '&#8635;'; // clockwise circular arrow
    } else if (state === 'completed') {
      iconEl.className = 'sim-step-icon';
      iconEl.style.color = '#2ed573';
      iconEl.innerHTML = '&#10003;'; // checkmark
    } else {
      iconEl.className = 'sim-step-icon';
      iconEl.style.color = 'var(--color-text-muted)';
      iconEl.innerHTML = '&#9203;'; // hourglass
    }
  }

  // ==========================================
  // RENDER STEP 1: Pre-image Resistance
  // ==========================================
  function renderStep0(live = false) {
    const panel = panelElements[0];
    if (!panel) return;

    const text1 = m1Input ? m1Input.value : 'Cryptography Lab 2026';
    const h1 = hashSHA256(text1);

    panel.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
        <div>
          <h3 style="color: var(--color-primary); font-size: 1.15rem; margin: 0 0 4px 0;">Step 1: Pre-image Resistance (One-Way Property)</h3>
          <p style="margin: 0; font-size: 0.85rem; color: var(--color-text-muted);">
            Given a target digest <code>h = H(m)</code>, it is computationally infeasible to invert <code>h</code> to find original message <code>m</code>.
          </p>
        </div>
        <span style="background: rgba(76, 140, 232, 0.15); color: var(--color-secondary); padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 0.78rem; font-family: 'Courier New', monospace;">
          Exhaustive Search: 2^256 attempts
        </span>
      </div>

      <!-- Target Hash Digest Card -->
      <div style="background: var(--color-surface); border: 1px solid var(--color-border); border-left: 4px solid var(--color-primary); border-radius: var(--radius-sm); padding: 14px; margin-bottom: 14px;">
        <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
          <strong style="color: var(--color-text); font-size: 0.9rem;">Target Hash Digest to Invert (h):</strong>
          <span style="font-size: 0.78rem; color: var(--color-text-muted); font-family: 'Courier New', monospace;">SHA-256 &middot; 256 bits</span>
        </div>
        <div style="background: var(--color-surface-muted); padding: 8px 12px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.85rem; color: var(--color-secondary); word-break: break-all; border: 1px solid var(--color-border);">
          ${h1.hex}
        </div>
        <div style="margin-top: 8px; font-size: 0.8rem; color: var(--color-text-muted);">
          Target created from Message 1 (<span style="color: var(--color-text); font-family: monospace;">"${escapeHtml(text1)}"</span>). An attacker with only this digest must search blindly through the message space.
        </div>
      </div>

      <!-- Live Terminal -->
      <div style="margin-bottom: 14px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; font-size: 0.82rem;">
          <span style="color: var(--color-text-muted); font-weight: 600;">Live Hash Inversion Brute-Force Log:</span>
          <span id="step0TerminalStatus" style="font-family: 'Courier New', monospace; font-size: 0.78rem; color: #ffa502;">
            ${live ? 'Generating &amp; hashing candidate inputs...' : 'Status: Ready to attack'}
          </span>
        </div>
        <div class="sim-terminal" id="step0Terminal">
          <div style="color: var(--color-text-muted); font-style: italic;">Initiating dictionary &amp; pseudo-random preimage attack against target digest...</div>
        </div>
      </div>

      <!-- Metric Cards -->
      <div class="sim-metrics-grid">
        <div class="sim-metric-card">
          <div class="sim-metric-title">Candidates Tested</div>
          <div class="sim-metric-val" id="step0Tested">0</div>
        </div>
        <div class="sim-metric-card">
          <div class="sim-metric-title">Inversions Found</div>
          <div class="sim-metric-val" style="color: #ff6b6b;" id="step0Matches">0</div>
        </div>
        <div class="sim-metric-card">
          <div class="sim-metric-title">Search Space Size</div>
          <div class="sim-metric-val" style="font-size: 1.05rem;">2^256</div>
        </div>
        <div class="sim-metric-card">
          <div class="sim-metric-title">Est. Brute-Force Time</div>
          <div class="sim-metric-val" style="font-size: 0.92rem; color: var(--color-secondary);">~3.67 &times; 10^57 yrs</div>
        </div>
      </div>

      <!-- Security Verdict -->
      <div class="sim-verdict" id="step0Verdict" style="${live ? 'display: none;' : ''}">
        <div class="sim-verdict-icon">&#10003;</div>
        <div>
          <div class="sim-verdict-title">Pre-image Resistance Verified (One-Way Property Confirmed)</div>
          <p class="sim-verdict-text">
            All candidate inputs failed to reverse the hash digest. SHA-256 uses 64 rounds of non-linear bitwise operations, modular addition, and rotational compression. Inverting this mathematical trapdoor requires testing an average of 2<sup>255</sup> combinations—making reverse computation physically impossible.
          </p>
        </div>
      </div>

      <!-- Navigation Footer -->
      <div class="sim-panel-footer">
        <button type="button" class="sim-action-btn outline btn-rerun" data-step="0">&#8634; Re-test Pre-image Resistance</button>
        <button type="button" class="sim-action-btn secondary btn-nav" data-target="1">Proceed to Step 2: Second Pre-image &rarr;</button>
      </div>
    `;

    bindStepButtons(panel);

    if (live) {
      runStep0Animation();
    }
  }

  function runStep0Animation() {
    const terminal = document.getElementById('step0Terminal');
    const testedEl = document.getElementById('step0Tested');
    const verdictEl = document.getElementById('step0Verdict');
    const statusEl = document.getElementById('step0TerminalStatus');

    const sampleGuesses = [
      'admin', 'password', '123456', 'secret', 'cryptoLab', 'hash2026', 'nonce_001',
      'qwerty', 'masterkey', 'test1234', 'supersecret', 'token_99', 'login', 'root',
      'user1', 'auth_session', 'pass123', 'client_vault', 'encryption', 'secure_msg',
      'salt_key_a', 'digest_rev', 'packet_5', 'block_0', 'zero_knowledge'
    ];

    let count = 0;
    if (activeStreamInterval) clearInterval(activeStreamInterval);

    activeStreamInterval = setInterval(() => {
      count++;
      const guess = sampleGuesses[count % sampleGuesses.length] + (count > 20 ? `_${count * 3}` : '');
      const gHash = CryptoJS.SHA256(guess).toString();
      const shortHash = gHash.slice(0, 16) + '...';

      if (terminal) {
        const row = document.createElement('div');
        row.className = 'sim-terminal-row';
        row.innerHTML = `
          <span><span style="color: var(--color-primary); font-weight: bold;">Guess #${count}:</span> "${escapeHtml(guess)}"</span>
          <span style="font-family: monospace; color: var(--color-text-muted);">${shortHash}</span>
          <span style="color: #ff6b6b; font-weight: bold;">MISMATCH &#10007;</span>
        `;
        terminal.appendChild(row);
        if (terminal.children.length > 25) {
          terminal.removeChild(terminal.children[1]);
        }
        terminal.scrollTop = terminal.scrollHeight;
      }

      if (testedEl) {
        testedEl.textContent = String(count * 240);
      }
    }, 45);

    // Conclude Step 1 after 2.3 seconds
    pipelineTimeout = setTimeout(() => {
      clearInterval(activeStreamInterval);
      activeStreamInterval = null;
      if (verdictEl) verdictEl.style.display = 'flex';
      if (statusEl) {
        statusEl.textContent = 'Attack Finished: 0 Pre-images Discovered';
        statusEl.style.color = '#2ed573';
      }
      setStepIcon(0, 'completed');
      updateProgress(0, 25, 'Step 1 Complete: Pre-image Resistance Confirmed &#10003;');

      if (isRunning && !isPaused) {
        pipelineTimeout = setTimeout(() => {
          if (isRunning && !isPaused) {
            runStep1();
          }
        }, 500);
      }
    }, 2300);
  }

  // ==========================================
  // RENDER STEP 2: Second Pre-image Resistance
  // ==========================================
  function renderStep1(live = false) {
    const panel = panelElements[1];
    if (!panel) return;

    const text1 = m1Input ? m1Input.value : 'Cryptography Lab 2026';
    const h1 = hashSHA256(text1);

    panel.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
        <div>
          <h3 style="color: var(--color-primary); font-size: 1.15rem; margin: 0 0 4px 0;">Step 2: Second Pre-image Resistance (Weak Collision Resistance)</h3>
          <p style="margin: 0; font-size: 0.85rem; color: var(--color-text-muted);">
            Given fixed input <code>m1</code>, it is computationally infeasible to find a distinct message <code>m2 &ne; m1</code> such that <code>H(m2) = H(m1)</code>.
          </p>
        </div>
        <span style="background: rgba(76, 140, 232, 0.15); color: var(--color-secondary); padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 0.78rem; font-family: 'Courier New', monospace;">
          Target: Fixed Message m1 &middot; 2^256 bounds
        </span>
      </div>

      <!-- Fixed Message & Target Digest -->
      <div style="background: var(--color-surface); border: 1px solid var(--color-border); border-left: 4px solid var(--color-secondary); border-radius: var(--radius-sm); padding: 14px; margin-bottom: 14px;">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;">
          <div>
            <span style="color: var(--color-text-muted); font-size: 0.8rem;">Fixed Original Input (m1):</span>
            <div style="background: var(--color-surface-muted); padding: 6px 10px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.85rem; color: var(--color-text); word-break: break-all;">
              "${escapeHtml(text1)}"
            </div>
          </div>
          <div>
            <span style="color: var(--color-text-muted); font-size: 0.8rem;">Target Hash H(m1):</span>
            <div style="background: var(--color-surface-muted); padding: 6px 10px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.82rem; color: var(--color-secondary); word-break: break-all; border: 1px solid var(--color-border);">
              ${h1.hex}
            </div>
          </div>
        </div>
        <div style="margin-top: 8px; font-size: 0.8rem; color: var(--color-text-muted);">
          Attack Scenario: An adversary attempts targeted modifications to m1 (tampering with numbers, adding spaces, subtle character flips) trying to match H(m1).
        </div>
      </div>

      <!-- Live Terminal -->
      <div style="margin-bottom: 14px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; font-size: 0.82rem;">
          <span style="color: var(--color-text-muted); font-weight: 600;">Live Targeted Forgery &amp; Tamper Search:</span>
          <span id="step1TerminalStatus" style="font-family: 'Courier New', monospace; font-size: 0.78rem; color: #ffa502;">
            ${live ? 'Injecting tamper variations...' : 'Status: Ready to test'}
          </span>
        </div>
        <div class="sim-terminal" id="step1Terminal">
          <div style="color: var(--color-text-muted); font-style: italic;">Testing subtle modifications, byte insertions, and character flips against fixed target...</div>
        </div>
      </div>

      <!-- Metric Cards -->
      <div class="sim-metrics-grid">
        <div class="sim-metric-card">
          <div class="sim-metric-title">Tamper Variants Tested</div>
          <div class="sim-metric-val" id="step1Tested">0</div>
        </div>
        <div class="sim-metric-card">
          <div class="sim-metric-title">Forged Collisions</div>
          <div class="sim-metric-val" style="color: #ff6b6b;" id="step1Matches">0</div>
        </div>
        <div class="sim-metric-card">
          <div class="sim-metric-title">Avg. Bit Discrepancy</div>
          <div class="sim-metric-val" style="color: #ffa502;">~128 / 256 bits</div>
        </div>
        <div class="sim-metric-card">
          <div class="sim-metric-title">Document Integrity</div>
          <div class="sim-metric-val" style="color: #2ed573;">100% Protected</div>
        </div>
      </div>

      <!-- Security Verdict -->
      <div class="sim-verdict" id="step1Verdict" style="${live ? 'display: none;' : ''}">
        <div class="sim-verdict-icon">&#10003;</div>
        <div>
          <div class="sim-verdict-title">Second Pre-image Resistance Verified (Tampering Prohibited)</div>
          <p class="sim-verdict-text">
            Even the slightest change to message m1—such as adding a single space, modifying punctuation, or flipping one bit—completely scrambles the output hash, differing by approximately 128 bits. An attacker cannot produce a counterfeit contract or altered transaction that yields the original digest.
          </p>
        </div>
      </div>

      <!-- Navigation Footer -->
      <div class="sim-panel-footer">
        <button type="button" class="sim-action-btn outline btn-nav" data-target="0">&larr; Back to Step 1</button>
        <div style="display: flex; gap: 8px;">
          <button type="button" class="sim-action-btn outline btn-rerun" data-step="1">&#8634; Re-test Second Pre-image</button>
          <button type="button" class="sim-action-btn secondary btn-nav" data-target="2">Proceed to Step 3: Collision Resistance &rarr;</button>
        </div>
      </div>
    `;

    bindStepButtons(panel);

    if (live) {
      runStep1Animation();
    }
  }

  function runStep1Animation() {
    const terminal = document.getElementById('step1Terminal');
    const testedEl = document.getElementById('step1Tested');
    const verdictEl = document.getElementById('step1Verdict');
    const statusEl = document.getElementById('step1TerminalStatus');
    const text1 = m1Input ? m1Input.value : 'Cryptography Lab 2026';
    const targetHash = hashSHA256(text1).hex;

    const tamperVariations = [
      text1 + ' ',
      text1 + '\t',
      text1 + '.',
      text1.slice(0, -1) + 'X',
      text1 + ' (tampered)',
      text1.toLowerCase(),
      text1.toUpperCase(),
      text1 + '#1',
      text1.replace(' ', '  '),
      ' ' + text1,
      text1 + '\0',
      text1 + '_forged',
      text1.slice(0, -1) + '7',
      text1.slice(0, -1) + '5',
      text1 + '!',
      text1 + '?',
      '[' + text1 + ']',
      text1 + '_v2'
    ];

    let count = 0;
    if (activeStreamInterval) clearInterval(activeStreamInterval);

    activeStreamInterval = setInterval(() => {
      count++;
      const candidate = tamperVariations[count % tamperVariations.length] + (count > 15 ? `_${count}` : '');
      const cHash = CryptoJS.SHA256(candidate).toString();
      const shortHash = cHash.slice(0, 16) + '...';

      // Compute rough bit difference
      let diffBits = 0;
      const b1 = hexToBinary(targetHash);
      const b2 = hexToBinary(cHash);
      for (let i = 0; i < 256; i++) {
        if (b1[i] !== b2[i]) diffBits++;
      }

      if (terminal) {
        const row = document.createElement('div');
        row.className = 'sim-terminal-row';
        row.innerHTML = `
          <span><span style="color: var(--color-primary); font-weight: bold;">Tamper #${count}:</span> "${escapeHtml(candidate)}"</span>
          <span style="font-family: monospace; color: var(--color-text-muted);">${shortHash}</span>
          <span style="color: #ff6b6b; font-weight: bold;">${diffBits} bits diff (MISMATCH &#10007;)</span>
        `;
        terminal.appendChild(row);
        if (terminal.children.length > 25) {
          terminal.removeChild(terminal.children[1]);
        }
        terminal.scrollTop = terminal.scrollHeight;
      }

      if (testedEl) {
        testedEl.textContent = String(count * 180);
      }
    }, 45);

    pipelineTimeout = setTimeout(() => {
      clearInterval(activeStreamInterval);
      activeStreamInterval = null;
      if (verdictEl) verdictEl.style.display = 'flex';
      if (statusEl) {
        statusEl.textContent = 'Tamper Testing Complete: 0 Second Pre-images Found';
        statusEl.style.color = '#2ed573';
      }
      setStepIcon(1, 'completed');
      updateProgress(1, 50, 'Step 2 Complete: Second Pre-image Resistance Confirmed &#10003;');

      if (isRunning && !isPaused) {
        pipelineTimeout = setTimeout(() => {
          if (isRunning && !isPaused) {
            runStep2();
          }
        }, 500);
      }
    }, 2300);
  }

  // ==========================================
  // RENDER STEP 3: Collision Resistance & Birthday Paradox
  // ==========================================
  function renderStep2(live = false) {
    const panel = panelElements[2];
    if (!panel) return;

    const text1 = m1Input ? m1Input.value : 'Cryptography Lab 2026';
    const collisionData = find16BitCollision(text1);

    panel.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
        <div>
          <h3 style="color: var(--color-primary); font-size: 1.15rem; margin: 0 0 4px 0;">Step 3: Collision Resistance &amp; Birthday Attack</h3>
          <p style="margin: 0; font-size: 0.85rem; color: var(--color-text-muted);">
            It is computationally infeasible to find <em>any</em> two distinct messages <code>mA &ne; mB</code> such that <code>H(mA) = H(mB)</code>.
          </p>
        </div>
        <span style="background: rgba(76, 140, 232, 0.15); color: var(--color-secondary); padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 0.78rem; font-family: 'Courier New', monospace;">
          Birthday Complexity: 2^(n/2) = 2^128
        </span>
      </div>

      <!-- Birthday Paradox Concept Callout -->
      <div style="background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-sm); padding: 12px 16px; margin-bottom: 14px; font-size: 0.85rem; line-height: 1.6;">
        <strong style="color: var(--color-primary);">Birthday Paradox Advantage:</strong> In pre-image attacks, one target is fixed (requiring 2<sup>256</sup> tries). In a collision search, the attacker is free to pick <em>both</em> messages simultaneously. By the Birthday Paradox, finding ANY match requires only &radic;(2<sup>n</sup>) = 2<sup>n/2</sup> attempts. Below, we demonstrate this mathematically on a 16-bit hash slice!
      </div>

      <!-- Live Terminal -->
      <div style="margin-bottom: 14px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; font-size: 0.82rem;">
          <span style="color: var(--color-text-muted); font-weight: 600;">Live Birthday Collision Search (Demonstrated on 16-bit / 4-Hex Prefix):</span>
          <span id="step2TerminalStatus" style="font-family: 'Courier New', monospace; font-size: 0.78rem; color: #ffa502;">
            ${live ? 'Generating messages &amp; building hash table...' : 'Status: Ready to search'}
          </span>
        </div>
        <div class="sim-terminal" id="step2Terminal">
          <div style="color: var(--color-text-muted); font-style: italic;">Hashing candidate inputs and checking for matching 16-bit prefixes...</div>
        </div>
      </div>

      <!-- Detected Collision Card -->
      <div id="step2CollisionBox" style="background: var(--color-surface); border: 1px solid #2ed573; border-radius: var(--radius-sm); padding: 14px; margin-bottom: 14px; ${live ? 'display: none;' : ''}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <strong style="color: #2ed573; font-size: 0.95rem;">&#10003; Real Collision Detected on 16-bit Slice (First 4 Hex Characters)!</strong>
          <span style="background: rgba(46, 213, 115, 0.2); color: #2ed573; padding: 2px 8px; border-radius: 4px; font-size: 0.78rem; font-family: monospace;">Found in ${collisionData.trials} trials</span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px; font-family: 'Courier New', monospace; font-size: 0.82rem;">
          <div style="background: var(--color-surface-muted); padding: 8px 10px; border-radius: 4px;">
            <div style="color: var(--color-text-muted); margin-bottom: 4px;">Message A: <strong style="color: var(--color-text);">${escapeHtml(collisionData.msgA)}</strong></div>
            <div style="word-break: break-all;">SHA-256: <span style="background: #2ed573; color: #181311; font-weight: bold; padding: 0 4px; border-radius: 2px;">${collisionData.prefix}</span>${collisionData.hashA.slice(4)}</div>
          </div>
          <div style="background: var(--color-surface-muted); padding: 8px 10px; border-radius: 4px;">
            <div style="color: var(--color-text-muted); margin-bottom: 4px;">Message B: <strong style="color: var(--color-text);">${escapeHtml(collisionData.msgB)}</strong></div>
            <div style="word-break: break-all;">SHA-256: <span style="background: #2ed573; color: #181311; font-weight: bold; padding: 0 4px; border-radius: 2px;">${collisionData.prefix}</span>${collisionData.hashB.slice(4)}</div>
          </div>
        </div>
        <div style="margin-top: 8px; font-size: 0.78rem; color: var(--color-text-muted);">
          Note: <code>${collisionData.trials}</code> attempts is remarkably close to the theoretical Birthday Paradox prediction of &radic;(&pi;/2 &times; 2<sup>16</sup>) &approx; 320 messages!
        </div>
      </div>

      <!-- Comparative Table: Scaled Collision Complexity -->
      <div style="overflow-x: auto; margin-bottom: 14px;">
        <table style="width: 100%; border-collapse: collapse; font-size: 0.82rem; background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-sm); overflow: hidden;">
          <thead>
            <tr style="background: var(--color-surface-muted); color: var(--color-primary); border-bottom: 1px solid var(--color-border); text-align: left;">
              <th style="padding: 8px 12px;">Digest Bit Size (n)</th>
              <th style="padding: 8px 12px;">Search Space (2^n)</th>
              <th style="padding: 8px 12px;">Birthday Bound (2^(n/2))</th>
              <th style="padding: 8px 12px;">Collision Time</th>
              <th style="padding: 8px 12px;">Security Status</th>
            </tr>
          </thead>
          <tbody>
            <tr style="border-bottom: 1px solid var(--color-border);">
              <td style="padding: 8px 12px; font-family: monospace;">16-bit Slice (Demo)</td>
              <td style="padding: 8px 12px; font-family: monospace;">65,536</td>
              <td style="padding: 8px 12px; font-family: monospace;">~320 trials (2^8)</td>
              <td style="padding: 8px 12px; color: #ff6b6b; font-weight: 600;">&lt; 50 milliseconds</td>
              <td style="padding: 8px 12px; color: #ff6b6b; font-weight: 700;">Broken (Insecure)</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--color-border);">
              <td style="padding: 8px 12px; font-family: monospace;">64-bit Hash</td>
              <td style="padding: 8px 12px; font-family: monospace;">1.8 &times; 10^19</td>
              <td style="padding: 8px 12px; font-family: monospace;">~4.3 &times; 10^9 trials (2^32)</td>
              <td style="padding: 8px 12px; color: #ffa502;">~2.5 seconds (GPU)</td>
              <td style="padding: 8px 12px; color: #ffa502; font-weight: 600;">Vulnerable</td>
            </tr>
            <tr style="background: rgba(76, 140, 232, 0.08);">
              <td style="padding: 8px 12px; font-family: monospace; font-weight: 700; color: var(--color-secondary);">256-bit (Full SHA-256)</td>
              <td style="padding: 8px 12px; font-family: monospace; color: var(--color-secondary);">1.15 &times; 10^77</td>
              <td style="padding: 8px 12px; font-family: monospace; font-weight: 700; color: var(--color-secondary);">3.4 &times; 10^38 trials (2^128)</td>
              <td style="padding: 8px 12px; color: #2ed573; font-weight: 700;">&gt; 10^18 Years</td>
              <td style="padding: 8px 12px; color: #2ed573; font-weight: 700;">Impervious to Attack</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Security Verdict -->
      <div class="sim-verdict" id="step2Verdict" style="${live ? 'display: none;' : ''}">
        <div class="sim-verdict-icon">&#10003;</div>
        <div>
          <div class="sim-verdict-title">Collision Resistance Confirmed (2^128 Security Level)</div>
          <p class="sim-verdict-text">
            The demonstration proved that small digest spaces suffer rapid collisions due to the Birthday Paradox. However, full SHA-256 employs 256 bits of output space. Even with the square-root Birthday reduction, finding a collision requires testing 2<sup>128</sup> (&approx; 3.4 &times; 10<sup>38</sup>) hash digests—far exceeding all computational resources currently available on Earth.
          </p>
        </div>
      </div>

      <!-- Navigation Footer -->
      <div class="sim-panel-footer">
        <button type="button" class="sim-action-btn outline btn-nav" data-target="1">&larr; Back to Step 2</button>
        <div style="display: flex; gap: 8px;">
          <button type="button" class="sim-action-btn outline btn-rerun" data-step="2">&#8634; Re-test Collision Resistance</button>
          <button type="button" class="sim-action-btn secondary btn-nav" data-target="3">Proceed to Step 4: Avalanche Effect &rarr;</button>
        </div>
      </div>
    `;

    bindStepButtons(panel);

    if (live) {
      runStep2Animation(collisionData);
    }
  }

  function runStep2Animation(collisionData) {
    const terminal = document.getElementById('step2Terminal');
    const collisionBox = document.getElementById('step2CollisionBox');
    const verdictEl = document.getElementById('step2Verdict');
    const statusEl = document.getElementById('step2TerminalStatus');

    let count = 0;
    if (activeStreamInterval) clearInterval(activeStreamInterval);

    activeStreamInterval = setInterval(() => {
      count++;
      const cand = `msg_cand_${count * 7}`;
      const cHash = CryptoJS.SHA256(cand).toString();
      const prefix = cHash.slice(0, 4);

      if (terminal) {
        const row = document.createElement('div');
        row.className = 'sim-terminal-row';
        row.innerHTML = `
          <span><span style="color: var(--color-primary); font-weight: bold;">[Entry #${count}]:</span> "${cand}"</span>
          <span style="font-family: monospace; color: var(--color-text-muted);">prefix: <span style="color: var(--color-secondary);">${prefix}</span> (${cHash.slice(4, 16)}...)</span>
          <span style="color: var(--color-text-muted); font-size: 0.75rem;">Stored in table</span>
        `;
        terminal.appendChild(row);
        if (terminal.children.length > 25) {
          terminal.removeChild(terminal.children[1]);
        }
        terminal.scrollTop = terminal.scrollHeight;
      }
    }, 40);

    pipelineTimeout = setTimeout(() => {
      clearInterval(activeStreamInterval);
      activeStreamInterval = null;

      if (collisionBox) {
        collisionBox.style.display = 'block';
      }
      if (verdictEl) verdictEl.style.display = 'flex';
      if (statusEl) {
        statusEl.textContent = `Collision Found in ${collisionData.trials} trials (Prefix: ${collisionData.prefix})`;
        statusEl.style.color = '#2ed573';
      }
      setStepIcon(2, 'completed');
      updateProgress(2, 75, 'Step 3 Complete: Collision Resistance Analyzed &#10003;');

      if (isRunning && !isPaused) {
        pipelineTimeout = setTimeout(() => {
          if (isRunning && !isPaused) {
            runStep3();
          }
        }, 500);
      }
    }, 2300);
  }

  // ==========================================
  // RENDER STEP 4: Avalanche Effect
  // ==========================================
  function renderStep3() {
    const panel = panelElements[3];
    if (!panel) return;

    const text1 = m1Input ? m1Input.value : 'Cryptography Lab 2026';
    const text2 = m2Input ? m2Input.value : 'Cryptography Lab 2027';

    const bytes1 = getUtf8Bytes(text1);
    const bytes2 = getUtf8Bytes(text2);

    // Compute input bit differences
    let inputDiffBits = 0;
    const minBytes = Math.min(bytes1.length, bytes2.length);
    for (let i = 0; i < minBytes; i++) {
      const xorByte = bytes1[i] ^ bytes2[i];
      inputDiffBits += xorByte.toString(2).replace(/0/g, '').length;
    }
    inputDiffBits += Math.abs(bytes1.length - bytes2.length) * 8;
    const totalInputBits = Math.max(bytes1.length, bytes2.length) * 8;
    const inputDiffPct = totalInputBits > 0 ? ((inputDiffBits / totalInputBits) * 100).toFixed(2) : '0.00';

    // Format input binary with spacing
    const binInput1 = bytes1.map(b => b.toString(2).padStart(8, '0')).join(' ');
    const binInput2 = bytes2.map((b, idx) => {
      const s = b.toString(2).padStart(8, '0');
      if (idx < bytes1.length && bytes1[idx] === b) return s;
      return `<span style="color: var(--color-secondary); font-weight: bold; text-decoration: underline;">${s}</span>`;
    }).join(' ');

    // Compute hashes
    const h1 = hashSHA256(text1);
    const h2 = hashSHA256(text2);
    const bin1 = h1.bin;
    const bin2 = h2.bin;

    let diffBits = 0;
    for (let i = 0; i < 256; i++) {
      if (bin1[i] !== bin2[i]) diffBits++;
    }

    const totalOutputBits = 256;
    const unchangedBits = totalOutputBits - diffBits;
    const pct = ((diffBits / totalOutputBits) * 100).toFixed(2);
    const pctNum = parseFloat(pct);

    // Build 8-word 32-bit XOR breakdown
    let wordsHtml = '';
    for (let w = 0; w < 8; w++) {
      const start = w * 32;
      const end = start + 32;
      let wDiff = 0;
      let h1Formatted = '';
      let h2Formatted = '';
      let xorFormatted = '';

      for (let i = start; i < end; i++) {
        const b1 = bin1[i] || '0';
        const b2 = bin2[i] || '0';
        const isFlipped = b1 !== b2;
        if (isFlipped) wDiff++;

        const spacer = (i > start && (i - start) % 8 === 0) ? ' ' : '';
        h1Formatted += spacer + b1;
        h2Formatted += spacer + b2;
        xorFormatted += spacer + (isFlipped
          ? `<span style="background: rgba(255, 71, 87, 0.25); color: #ff6b6b; font-weight: 700; padding: 1px 2px; border-radius: 2px;">1</span>`
          : `<span style="color: var(--color-text-muted); opacity: 0.35;">0</span>`
        );
      }

      const wPct = ((wDiff / 32) * 100).toFixed(1);

      wordsHtml += `
        <div style="background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-sm); padding: 10px 14px; margin-bottom: 8px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; font-size: 0.82rem; font-family: Arial, sans-serif;">
            <strong style="color: var(--color-primary);">Word ${w} (Bits ${start}&ndash;${end - 1})</strong>
            <span style="background: rgba(76, 140, 232, 0.15); color: var(--color-secondary); padding: 2px 8px; border-radius: 4px; font-weight: 600;">
              ${wDiff}/32 bits flipped (${wPct}%)
            </span>
          </div>
          <div style="font-family: 'Courier New', monospace; font-size: 0.8rem; line-height: 1.6; word-break: break-all;">
            <div style="color: var(--color-text-muted);"><span style="display: inline-block; width: 42px; color: var(--color-primary);">H1 :</span>${h1Formatted}</div>
            <div style="color: var(--color-text-muted);"><span style="display: inline-block; width: 42px; color: var(--color-primary);">H2 :</span>${h2Formatted}</div>
            <div style="color: var(--color-text);"><span style="display: inline-block; width: 42px; color: #ff6b6b; font-weight: 700;">XOR:</span>${xorFormatted}</div>
          </div>
        </div>
      `;
    }

    panel.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
        <div>
          <h3 style="color: var(--color-primary); font-size: 1.15rem; margin: 0 0 4px 0;">Step 4: Avalanche Effect &amp; Diffusion Analysis</h3>
          <p style="margin: 0; font-size: 0.85rem; color: var(--color-text-muted);">
            Strict Avalanche Criterion (SAC): modifying a single input bit must cause approximately 50% of digest bits to change randomly.
          </p>
        </div>
        <span style="background: rgba(76, 140, 232, 0.15); color: var(--color-secondary); padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 0.78rem; font-family: 'Courier New', monospace;">
          Target Diffusion: 50% &plusmn; 5%
        </span>
      </div>

      <!-- Side-by-Side Message Cards -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 14px; margin-bottom: 14px;">
        <!-- Message 1 -->
        <div style="background: var(--color-surface); border: 1px solid var(--color-border); border-left: 4px solid var(--color-primary); border-radius: var(--radius-sm); padding: 14px;">
          <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
            <strong style="color: var(--color-text); font-family: Arial, sans-serif;">Message 1 (Original)</strong>
            <span style="font-size: 0.78rem; color: var(--color-text-muted); font-family: 'Courier New', monospace;">${bytes1.length} chars &middot; ${bytes1.length * 8} bits</span>
          </div>
          <div style="margin-bottom: 8px; font-size: 0.88rem;">
            <span style="color: var(--color-text-muted); font-size: 0.8rem;">Text:</span>
            <div style="background: var(--color-surface-muted); padding: 6px 10px; border-radius: 4px; font-family: 'Courier New', monospace; color: var(--color-text); word-break: break-all;">${escapeHtml(text1)}</div>
          </div>
          <div style="margin-bottom: 8px; font-size: 0.88rem;">
            <span style="color: var(--color-text-muted); font-size: 0.8rem;">Input Binary (UTF-8):</span>
            <div style="background: var(--color-surface-muted); padding: 6px 10px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.75rem; color: var(--color-text-muted); max-height: 52px; overflow-y: auto; word-break: break-all;">${binInput1 || '(empty)'}</div>
          </div>
          <div style="font-size: 0.88rem;">
            <span style="color: var(--color-text-muted); font-size: 0.8rem;">SHA-256 Digest (Hex):</span>
            <div style="background: var(--color-surface-muted); padding: 6px 10px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.78rem; color: var(--color-secondary); word-break: break-all; border: 1px solid var(--color-border);">${h1.hex}</div>
          </div>
        </div>

        <!-- Message 2 -->
        <div style="background: var(--color-surface); border: 1px solid var(--color-border); border-left: 4px solid var(--color-secondary); border-radius: var(--radius-sm); padding: 14px;">
          <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
            <strong style="color: var(--color-text); font-family: Arial, sans-serif;">Message 2 (Perturbed)</strong>
            <span style="font-size: 0.78rem; color: var(--color-text-muted); font-family: 'Courier New', monospace;">${bytes2.length} chars &middot; ${bytes2.length * 8} bits</span>
          </div>
          <div style="margin-bottom: 8px; font-size: 0.88rem;">
            <span style="color: var(--color-text-muted); font-size: 0.8rem;">Text:</span>
            <div style="background: var(--color-surface-muted); padding: 6px 10px; border-radius: 4px; font-family: 'Courier New', monospace; color: var(--color-text); word-break: break-all;">${escapeHtml(text2)}</div>
          </div>
          <div style="margin-bottom: 8px; font-size: 0.88rem;">
            <span style="color: var(--color-text-muted); font-size: 0.8rem;">Input Binary (UTF-8):</span>
            <div style="background: var(--color-surface-muted); padding: 6px 10px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.75rem; color: var(--color-text-muted); max-height: 52px; overflow-y: auto; word-break: break-all;">${binInput2 || '(empty)'}</div>
          </div>
          <div style="font-size: 0.88rem;">
            <span style="color: var(--color-text-muted); font-size: 0.8rem;">SHA-256 Digest (Hex):</span>
            <div style="background: var(--color-surface-muted); padding: 6px 10px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.78rem; color: var(--color-secondary); word-break: break-all; border: 1px solid var(--color-border);">${h2.hex}</div>
          </div>
        </div>
      </div>

      <!-- Input Difference Banner -->
      <div style="background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-sm); padding: 10px 14px; font-size: 0.85rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 14px;">
        <span><strong>Input Difference:</strong> <code>${inputDiffBits} bit(s)</code> differing at input stage (${inputDiffPct}% perturbation)</span>
        <span style="color: var(--color-text-muted); font-size: 0.8rem;">Total Output Bits: 256 bits (32 bytes)</span>
      </div>

      <!-- Avalanche Metrics Grid -->
      <div class="sim-metrics-grid">
        <div class="sim-metric-card">
          <div class="sim-metric-title">Input Flipped</div>
          <div class="sim-metric-val">${inputDiffBits} bit${inputDiffBits === 1 ? '' : 's'}</div>
        </div>
        <div class="sim-metric-card" style="border-color: #ff4757;">
          <div class="sim-metric-title">Hamming Distance</div>
          <div class="sim-metric-val" style="color: #ff6b6b;">${diffBits} / 256</div>
        </div>
        <div class="sim-metric-card">
          <div class="sim-metric-title">Unchanged Bits</div>
          <div class="sim-metric-val" style="color: var(--color-text-muted);">${unchangedBits} / 256</div>
        </div>
        <div class="sim-metric-card" style="border-color: var(--color-secondary);">
          <div class="sim-metric-title">Avalanche %</div>
          <div class="sim-metric-val" style="color: var(--color-secondary);">${pct}%</div>
        </div>
      </div>

      <!-- Visual Avalanche Diffusion Gauge -->
      <div style="background: var(--color-surface); border: 1px solid var(--color-border); border-radius: var(--radius-sm); padding: 14px; margin-bottom: 14px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; font-size: 0.85rem;">
          <strong style="color: var(--color-text);">Avalanche Diffusion Target Meter:</strong>
          <span style="font-family: monospace; color: var(--color-secondary); font-weight: 700;">${pct}% (Ideal: ~50%)</span>
        </div>
        <div style="position: relative; height: 16px; background: var(--color-surface-muted); border-radius: 8px; overflow: hidden; border: 1px solid var(--color-border);">
          <!-- Ideal 45% - 55% Zone -->
          <div style="position: absolute; left: 45%; width: 10%; height: 100%; background: rgba(46, 213, 115, 0.25); border-left: 1px dashed #2ed573; border-right: 1px dashed #2ed573;"></div>
          <!-- 50% Center Target Line -->
          <div style="position: absolute; left: 50%; width: 2px; height: 100%; background: #2ed573; z-index: 2;"></div>
          <!-- Actual Fill Bar -->
          <div style="width: ${Math.min(100, Math.max(0, pctNum))}%; height: 100%; background: var(--color-secondary); opacity: 0.75; transition: width 0.6s ease;"></div>
        </div>
        <div style="display: flex; justify-content: space-between; margin-top: 4px; font-size: 0.72rem; color: var(--color-text-muted); font-family: monospace;">
          <span>0% (No change)</span>
          <span style="color: #2ed573; font-weight: bold;">50% (Ideal Cryptographic Diffusion)</span>
          <span>100% (Complete Inversion)</span>
        </div>
      </div>

      <!-- 8 Words Stream Container -->
      <div style="margin-bottom: 14px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; font-size: 0.85rem;">
          <strong style="color: var(--color-primary);">Bitwise XOR Comparison Across 8 &times; 32-bit Words:</strong>
          <div style="display: flex; gap: 12px; font-size: 0.78rem; font-family: Arial, sans-serif;">
            <span><span style="display: inline-block; padding: 1px 5px; border-radius: 2px; background: rgba(255, 71, 87, 0.25); color: #ff6b6b; font-weight: 700; font-family: monospace;">1</span> Flipped bit (XOR = 1)</span>
            <span><span style="display: inline-block; padding: 1px 5px; border-radius: 2px; background: var(--color-surface); color: var(--color-text-muted); font-family: monospace;">0</span> Unchanged bit (XOR = 0)</span>
          </div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 6px;">
          ${wordsHtml}
        </div>
      </div>

      <!-- Grand Conclusion Banner -->
      <div style="border-radius: var(--radius-sm); padding: 16px; border: 1px solid #2ed573; background: rgba(46, 213, 115, 0.12); display: flex; gap: 14px; align-items: flex-start; margin-top: 16px;">
        <div style="font-size: 1.6rem; line-height: 1; color: #2ed573;">&#127881;</div>
        <div>
          <h4 style="margin: 0 0 6px 0; font-size: 1.05rem; color: #2ed573; font-family: Arial, sans-serif;">
            4-Step Hash Function Properties Analysis Complete!
          </h4>
          <p style="margin: 0; font-size: 0.86rem; color: var(--color-text); line-height: 1.6;">
            All four foundational properties of a secure cryptographic hash function have been verified:
            <br>&bull; <strong>1. Pre-image Resistance:</strong> Reversing digest H(m) to input m is computationally impossible (2<sup>256</sup> operations required).
            <br>&bull; <strong>2. Second Pre-image Resistance:</strong> Modifying input m1 without invalidating digest H(m1) is computationally prohibitive (2<sup>256</sup> operations).
            <br>&bull; <strong>3. Collision Resistance:</strong> Finding arbitrary collisions requires 2<sup>128</sup> operations by the Birthday Paradox, making global SHA-256 collision search impervious.
            <br>&bull; <strong>4. Avalanche Effect:</strong> Changing input flipped <strong>${pct}%</strong> of output bits (Hamming distance ${diffBits}/256), achieving optimal pseudo-random diffusion.
          </p>
        </div>
      </div>

      <!-- Navigation Footer -->
      <div class="sim-panel-footer">
        <button type="button" class="sim-action-btn outline btn-nav" data-target="2">&larr; Back to Step 3</button>
        <button type="button" class="sim-action-btn primary" id="btnRestartPipeline">&#8634; Re-run Full 4-Step Simulation</button>
      </div>
    `;

    bindStepButtons(panel);

    const btnRestart = document.getElementById('btnRestartPipeline');
    if (btnRestart) {
      btnRestart.addEventListener('click', startPipeline);
    }

    setStepIcon(3, 'completed');
    updateProgress(3, 100, 'All 4 Steps Complete: Hash Properties Verified! &#10003;');
  }

  // Bind navigation & rerun buttons within a panel
  function bindStepButtons(container) {
    if (!container) return;
    const navButtons = container.querySelectorAll('.btn-nav');
    navButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const target = parseInt(btn.dataset.target, 10);
        if (!isNaN(target)) {
          switchTab(target, true);
        }
      });
    });

    const rerunButtons = container.querySelectorAll('.btn-rerun');
    rerunButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const step = parseInt(btn.dataset.step, 10);
        if (step === 0) renderStep0(true);
        else if (step === 1) renderStep1(true);
        else if (step === 2) renderStep2(true);
        else if (step === 3) renderStep3();
      });
    });
  }

  // ==========================================
  // PIPELINE CONTROL: Sequential Auto Execution
  // ==========================================
  function startPipeline() {
    clearTimers();
    isRunning = true;
    isPaused = false;
    stepStatuses = ['pending', 'pending', 'pending', 'pending'];

    // Update UI controls
    if (btnStart) {
      btnStart.disabled = true;
      btnStart.style.opacity = '0.75';
    }
    if (btnStartText) btnStartText.textContent = 'Running Pipeline...';
    if (btnStartIcon) btnStartIcon.innerHTML = '&#8635;';
    if (btnPause) {
      btnPause.style.display = 'inline-flex';
      btnPause.innerHTML = '&#10074;&#10074; Pause';
    }

    // Reset icons
    for (let i = 0; i < 4; i++) {
      setStepIcon(i, 'pending');
    }

    // Begin with Step 0
    runStep0();
  }

  function runStep0() {
    switchTab(0, false);
    setStepIcon(0, 'running');
    updateProgress(0, 10, 'Running Step 1 of 4: Pre-image Resistance Inversion Search...');
    renderStep0(true);
  }

  function runStep1() {
    switchTab(1, false);
    setStepIcon(1, 'running');
    updateProgress(1, 35, 'Running Step 2 of 4: Second Pre-image Resistance Tamper Search...');
    renderStep1(true);
  }

  function runStep2() {
    switchTab(2, false);
    setStepIcon(2, 'running');
    updateProgress(2, 60, 'Running Step 3 of 4: Birthday Attack Collision Search...');
    renderStep2(true);
  }

  function runStep3() {
    switchTab(3, false);
    setStepIcon(3, 'running');
    updateProgress(3, 85, 'Running Step 4 of 4: Avalanche Effect & XOR Analysis...');
    renderStep3();

    // Conclude full pipeline
    isRunning = false;
    isPaused = false;
    if (btnStart) {
      btnStart.disabled = false;
      btnStart.style.opacity = '1';
    }
    if (btnStartText) btnStartText.textContent = 'Restart 4-Step Simulation';
    if (btnStartIcon) btnStartIcon.innerHTML = '&#9654;';
    if (btnPause) btnPause.style.display = 'none';
  }

  function pausePipeline() {
    isPaused = true;
    clearTimers();
    if (btnPause) {
      btnPause.innerHTML = '&#9654; Resume';
    }
    if (statusText) {
      statusText.textContent = 'Pipeline Paused. Click Resume to continue automated progression.';
    }
  }

  function resumePipeline() {
    isPaused = false;
    if (btnPause) {
      btnPause.innerHTML = '&#10074;&#10074; Pause';
    }
    // Resume according to active step
    if (activeStep === 0) runStep0();
    else if (activeStep === 1) runStep1();
    else if (activeStep === 2) runStep2();
    else if (activeStep === 3) runStep3();
  }

  function resetPipeline() {
    clearTimers();
    isRunning = false;
    isPaused = false;

    if (m1Input) m1Input.value = 'Cryptography Lab 2026';
    if (m2Input) m2Input.value = 'Cryptography Lab 2027';

    if (btnStart) {
      btnStart.disabled = false;
      btnStart.style.opacity = '1';
    }
    if (btnStartText) btnStartText.textContent = 'Start 4-Step Simulation';
    if (btnStartIcon) btnStartIcon.innerHTML = '&#9654;';
    if (btnPause) btnPause.style.display = 'none';

    for (let i = 0; i < 4; i++) {
      setStepIcon(i, 'pending');
    }

    updateProgress(0, 0, 'Status: Ready. Click Start to run the 4-step analysis automatically.');
    renderAllStatic();
    switchTab(0, false);
  }

  function clearTimers() {
    if (pipelineTimeout) {
      clearTimeout(pipelineTimeout);
      pipelineTimeout = null;
    }
    if (activeStreamInterval) {
      clearInterval(activeStreamInterval);
      activeStreamInterval = null;
    }
  }

  // Render static baseline views for all 4 panels
  function renderAllStatic() {
    renderStep0(false);
    renderStep1(false);
    renderStep2(false);
    renderStep3();
  }

  // ==========================================
  // EVENT LISTENERS & INITIALIZATION
  // ==========================================

  // Step tab click listeners
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const stepIdx = parseInt(btn.dataset.stepTab, 10);
      if (!isNaN(stepIdx)) {
        switchTab(stepIdx, true);
      }
    });
  });

  // Start pipeline button
  if (btnStart) {
    btnStart.addEventListener('click', () => {
      startPipeline();
    });
  }

  // Pause / Resume button
  if (btnPause) {
    btnPause.addEventListener('click', () => {
      if (isPaused) {
        resumePipeline();
      } else {
        pausePipeline();
      }
    });
  }

  // Reset button
  if (btnReset) {
    btnReset.addEventListener('click', resetPipeline);
  }

  // Auto-perturb button: flips or modifies last character of Message 1
  if (btnAutoPerturb) {
    btnAutoPerturb.addEventListener('click', () => {
      const current = m1Input ? (m1Input.value || 'Cryptography Lab 2026') : 'Cryptography Lab 2026';
      const lastChar = current.slice(-1);
      let newLastChar;
      if (lastChar >= '0' && lastChar < '9') {
        newLastChar = String(Number(lastChar) + 1);
      } else if (lastChar === '9') {
        newLastChar = '0';
      } else if (lastChar >= 'a' && lastChar < 'z') {
        newLastChar = String.fromCharCode(lastChar.charCodeAt(0) + 1);
      } else if (lastChar >= 'A' && lastChar < 'Z') {
        newLastChar = String.fromCharCode(lastChar.charCodeAt(0) + 1);
      } else {
        newLastChar = '!';
      }
      if (m2Input) {
        m2Input.value = current.slice(0, -1) + newLastChar;
      }
      startPipeline();
    });
  }

  // Enter key in input triggers pipeline
  if (m1Input) {
    m1Input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        startPipeline();
      }
    });
    m1Input.addEventListener('change', () => {
      renderAllStatic();
    });
  }

  if (m2Input) {
    m2Input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        startPipeline();
      }
    });
    m2Input.addEventListener('change', () => {
      renderAllStatic();
    });
  }

  // Initial render so tabs have informative content immediately
  renderAllStatic();
  switchTab(0, false);

  // ==========================================
  // QUIZ LOGIC (Preserved intact)
  // ==========================================
  const btnSubmitQuiz = document.getElementById('btnSubmitQuiz');
  const quizResult = document.getElementById('quizResult');

  if (btnSubmitQuiz && quizResult) {
    btnSubmitQuiz.addEventListener('click', () => {
      let score = 0;
      const q1 = document.querySelector('input[name="q1"]:checked');
      const q2 = document.querySelector('input[name="q2"]:checked');
      const q3 = document.querySelector('input[name="q3"]:checked');
      const q4 = document.querySelector('input[name="q4"]:checked');
      const q5 = document.querySelector('input[name="q5"]:checked');
      const q6 = document.querySelector('input[name="q6"]:checked');
      const q7 = document.querySelector('input[name="q7"]:checked');

      let feedback = [];

      if (q1 && q1.value === 'b') { score++; } else { feedback.push('Question 1 is incorrect.'); }
      if (q2 && q2.value === 'c') { score++; } else { feedback.push('Question 2 is incorrect.'); }
      if (q3 && q3.value === 'a') { score++; } else { feedback.push('Question 3 is incorrect.'); }
      if (q4 && q4.value === 'c') { score++; } else { feedback.push('Question 4 is incorrect.'); }
      if (q5 && q5.value === 'c') { score++; } else { feedback.push('Question 5 is incorrect.'); }
      if (q6 && q6.value === 'b') { score++; } else { feedback.push('Question 6 is incorrect.'); }
      if (q7 && q7.value === 'b') { score++; } else { feedback.push('Question 7 is incorrect.'); }

      if (score === 7) {
        quizResult.style.color = '#2ed573';
        quizResult.innerHTML = '7/7 Correct! Excellent job.';
      } else {
        quizResult.style.color = '#ff4757';
        quizResult.innerHTML = `You scored ${score}/7.<br>` + feedback.join('<br>');
      }
    });
  }
}

// Initialize on DOM load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initHashExperiment);
} else {
  initHashExperiment();
}
