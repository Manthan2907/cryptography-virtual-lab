/**
 * Needham-Schroeder Symmetric Key Protocol Virtual Lab Engine
 * IIT Kharagpur Virtual Labs Specification
 * Fully Scoped Namespace: NSLab
 */

const NSLab = (function() {
  'use strict';

  // Protocol State Machine Storage
  const state = {
    aliceId: 'Alice',
    bobId: 'Bob',
    nonceMode: 'auto',
    nonceA: '0x4F92',
    nonceB: '0x8A1C',
    keyA: '0x9A4F8B2C',
    keyB: '0x3C81D5E9',
    sessionKey: '0x7E2A91D4',
    step: 0,
    isInitialized: false
  };

  // Node Positions for Animated Packet (percentages)
  const nodePositions = {
    alice: { x: 15, y: 75 },
    kdc: { x: 50, y: 22 },
    bob: { x: 85, y: 75 }
  };

  // Pretest Questions Data
  const pretestQuestions = [
    {
      id: 'pre_1',
      question: '1. What is the fundamental role of a Key Distribution Center (KDC) in symmetric key cryptography?',
      options: [
        'a: To store public keys of all users in a PKI directory',
        'b: To generate and distribute temporary symmetric session keys between users who share master keys with it',
        'c: To decrypt all end-to-end network communications in real time',
        'd: To convert symmetric keys into asymmetric key pairs'
      ],
      correct: 1,
      explanation: 'Correct! A Key Distribution Center (KDC) acts as a trusted third party holding master keys shared individually with each client. It generates short-lived session keys (K_AB) on demand.'
    },
    {
      id: 'pre_2',
      question: '2. In network security, what is a "Nonce"?',
      options: [
        'a: A permanent master secret key shared between Alice and Bob',
        'b: A random or non-repeating value generated once to guarantee freshness and prevent replay attacks',
        'c: A hash digest of the user password',
        'd: An unencrypted public key certificate'
      ],
      correct: 1,
      explanation: 'Correct! A Nonce ("number used once") ensures that a message or challenge is fresh and has not been replayed by an adversary from a past session.'
    },
    {
      id: 'pre_3',
      question: '3. Why is plaintext identity transmission required in Step 1 (A → S: A, B, N_A)?',
      options: [
        'a: To allow KDC to look up Alice\'s and Bob\'s pre-shared master keys in its database',
        'b: To encrypt Alice\'s master key using Bob\'s ID',
        'c: To bypass KDC authentication rules',
        'd: To generate a public key certificate for Bob'
      ],
      correct: 0,
      explanation: 'Correct! KDC must know who is making the request (Alice) and who she wants to talk to (Bob) so it can select the correct master keys K_A and K_B to build the response and ticket.'
    },
    {
      id: 'pre_4',
      question: '4. In symmetric key establishment, what is a "Ticket"?',
      options: [
        'a: An unencrypted text file containing user login details',
        'b: An encrypted structure intended for Bob containing session key K_AB and Alice\'s ID, encrypted with Bob\'s master key K_B',
        'c: A digital signature created with Alice\'s private key',
        'd: A token sent to KDC to invalidate old keys'
      ],
      correct: 1,
      explanation: 'Correct! The ticket {K_AB, A}_KB allows Alice to pass Bob\'s portion of the session credentials without Alice being able to read or tamper with Bob\'s master key.'
    }
  ];

  // Posttest Questions Data
  const posttestQuestions = [
    {
      id: 'post_1',
      question: '1. What security property does Alice verify when she decrypts {N_A, Bob, K_AB, Ticket}_KA in Step 2?',
      options: [
        'a: That Bob has already received the session key',
        'b: That the response is fresh and directly answers her Step 1 request because it contains her nonce N_A',
        'c: That KDC has deleted its copy of master key K_A',
        'd: That K_AB is an asymmetric key pair'
      ],
      correct: 1,
      explanation: 'Correct! Including N_A inside the ciphertext encrypted under K_A proves to Alice that KDC received her recent request and generated a fresh response.'
    },
    {
      id: 'post_2',
      question: '2. Why does Bob send challenge {N_B}_KAB in Step 4 instead of assuming Step 3 completes authentication?',
      options: [
        'a: To prove that the sender of the ticket actually possesses the session key K_AB',
        'b: To request KDC to issue a new ticket',
        'c: To decrypt Alice\'s master key K_A',
        'd: To calculate a hash digest of N_A'
      ],
      correct: 0,
      explanation: 'Correct! Anyone could eavesdrop and forward an encrypted ticket. Step 4 challenges the sender to prove knowledge of key K_AB.'
    },
    {
      id: 'post_3',
      question: '3. In Step 5, Alice responds with {N_B - 1}_KAB. Why is the function (N_B - 1) performed on the nonce?',
      options: [
        'a: To prevent reflection attacks where an adversary echoes back the exact same challenge ciphertext without knowing K_AB',
        'b: To compress the session key for faster network transit',
        'c: To notify KDC that the handshake finished',
        'd: To reset Bob\'s master key'
      ],
      correct: 0,
      explanation: 'Correct! Performing a known operation (such as subtracting 1) proves that Alice decrypted N_B, modified it, and re-encrypted it, proving active key possession.'
    },
    {
      id: 'post_4',
      question: '4. What is the major vulnerability of the original 1978 Needham-Schroeder symmetric protocol identified by Denning and Sacco (1981)?',
      options: [
        'a: Master keys are sent in plaintext',
        'b: Step 3\'s ticket {K_AB, A}_KB lacks a timestamp or Bob-nonce, enabling replay of an old compromised ticket to Bob',
        'c: Nonces are restricted to 8 bits',
        'd: KDC cannot support more than two clients'
      ],
      correct: 1,
      explanation: 'Correct! The Denning-Sacco vulnerability showed that if an old session key K_AB is compromised, an attacker can replay {K_AB, A}_KB to Bob, who cannot verify ticket freshness without a timestamp.'
    }
  ];

  // DOM Caching
  let els = {};

  // Utility: Generate 16-bit Random Hex Nonce (e.g. 0x4F92)
  function generateHexNonce() {
    const val = Math.floor(Math.random() * 65536);
    return '0x' + val.toString(16).toUpperCase().padStart(4, '0');
  }

  // Utility: Generate 32-bit Hex Session Key (e.g. 0x7E2A91D4)
  function generateHexKey() {
    const val = Math.floor(Math.random() * 4294967295);
    return '0x' + val.toString(16).toUpperCase().padStart(8, '0');
  }

  // Initialize Laboratory Module
  function init() {
    cacheDOM();
    bindEvents();
    renderQuiz('pretestQuestionsContainer', pretestQuestions, 'btnPretestSubmit', 'btnPretestReset', 'pretestScore');
    renderQuiz('posttestQuestionsContainer', posttestQuestions, 'btnPosttestSubmit', 'btnPosttestReset', 'posttestScore');
    updateUI();
  }

  function cacheDOM() {
    els = {
      // Sidebar Navigation Links
      navLinks: document.querySelectorAll('.vlab-nav-link'),
      tabPanels: document.querySelectorAll('.vlab-tab-panel'),

      // Simulation Controls
      selectAlice: document.getElementById('selectAlice'),
      selectBob: document.getElementById('selectBob'),
      selectNonceMode: document.getElementById('selectNonceMode'),
      btnInitHandshake: document.getElementById('btnInitHandshake'),
      btnNextStep: document.getElementById('btnNextStep'),
      btnResetSim: document.getElementById('btnResetSim'),

      // Entity Cards & Key Displays
      cardAlice: document.getElementById('cardAlice'),
      cardKdc: document.getElementById('cardKdc'),
      cardBob: document.getElementById('cardBob'),
      nameAlice: document.getElementById('nameAlice'),
      nameBob: document.getElementById('nameBob'),

      badgeAlice: document.getElementById('badgeAlice'),
      badgeKdc: document.getElementById('badgeKdc'),
      badgeBob: document.getElementById('badgeBob'),

      valAliceKA: document.getElementById('valAliceKA'),
      valAliceKAB: document.getElementById('valAliceKAB'),
      valKdcKA: document.getElementById('valKdcKA'),
      valKdcKB: document.getElementById('valKdcKB'),
      valKdcKAB: document.getElementById('valKdcKAB'),
      valBobKB: document.getElementById('valBobKB'),
      valBobKAB: document.getElementById('valBobKAB'),

      // Animated Packet
      packet: document.getElementById('visualPacket'),
      pathAliceKdc: document.getElementById('pathAliceKdc'),
      pathKdcAlice: document.getElementById('pathKdcAlice'),
      pathAliceBob: document.getElementById('pathAliceBob'),

      // Inspector Panel
      inspectorTitle: document.getElementById('inspectorTitle'),
      inspectorMath: document.getElementById('inspectorMath'),
      inspectorCiphertext: document.getElementById('inspectorCiphertext'),
      inspectorTableBody: document.getElementById('inspectorTableBody'),
      inspectorExplain: document.getElementById('inspectorExplain')
    };
  }

  function bindEvents() {
    // Sidebar Tabs switching
    els.navLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetTab = link.getAttribute('data-tab');

        els.navLinks.forEach(l => l.classList.remove('active'));
        els.tabPanels.forEach(p => p.classList.remove('active'));

        link.classList.add('active');
        document.getElementById(`tab-${targetTab}`).classList.add('active');
      });
    });

    // Controls
    els.btnInitHandshake.addEventListener('click', initHandshake);
    els.btnNextStep.addEventListener('click', advanceStep);
    els.btnResetSim.addEventListener('click', resetSim);
  }

  function initHandshake() {
    state.aliceId = els.selectAlice.value;
    state.bobId = els.selectBob.value;
    state.nonceMode = els.selectNonceMode.value;

    if (state.nonceMode === 'auto') {
      state.nonceA = generateHexNonce();
      state.nonceB = generateHexNonce();
      state.sessionKey = generateHexKey();
    } else {
      state.nonceA = '0x4F92';
      state.nonceB = '0x8A1C';
      state.sessionKey = '0x7E2A91D4';
    }

    state.step = 1;
    state.isInitialized = true;
    updateUI();
    executeStep(1);
  }

  function advanceStep() {
    if (!state.isInitialized || state.step >= 5) return;
    state.step++;
    updateUI();
    executeStep(state.step);
  }

  function resetSim() {
    state.step = 0;
    state.isInitialized = false;
    els.packet.classList.remove('active');
    els.packet.style.left = '15%';
    els.packet.style.top = '75%';
    updateUI();
  }

  function executeStep(stepNum) {
    switch (stepNum) {
      case 1:
        // Step 1: Alice -> KDC
        animatePacket(nodePositions.alice, nodePositions.kdc, 'Step 1: Req');
        break;
      case 2:
        // Step 2: KDC -> Alice
        animatePacket(nodePositions.kdc, nodePositions.alice, 'Step 2: Resp');
        break;
      case 3:
        // Step 3: Alice -> Bob
        animatePacket(nodePositions.alice, nodePositions.bob, 'Step 3: Ticket');
        break;
      case 4:
        // Step 4: Bob -> Alice
        animatePacket(nodePositions.bob, nodePositions.alice, 'Step 4: Chlg');
        break;
      case 5:
        // Step 5: Alice -> Bob
        animatePacket(nodePositions.alice, nodePositions.bob, 'Step 5: Auth');
        break;
    }
  }

  function animatePacket(from, to, text) {
    els.packet.textContent = text;
    els.packet.style.left = `${from.x}%`;
    els.packet.style.top = `${from.y}%`;
    els.packet.classList.add('active');

    setTimeout(() => {
      els.packet.style.transition = 'left 0.9s ease-in-out, top 0.9s ease-in-out';
      els.packet.style.left = `${to.x}%`;
      els.packet.style.top = `${to.y}%`;
    }, 40);

    setTimeout(() => {
      els.packet.style.transition = 'none';
    }, 980);
  }

  function updateUI() {
    // Update Node Names
    els.nameAlice.textContent = state.aliceId;
    els.nameBob.textContent = state.bobId;

    // Update Stored Keys & Badges
    els.valAliceKA.textContent = state.keyA;
    els.valKdcKA.textContent = state.keyA;
    els.valKdcKB.textContent = state.keyB;
    els.valBobKB.textContent = state.keyB;

    if (state.step >= 2) {
      els.valKdcKAB.textContent = state.sessionKey;
      els.valAliceKAB.textContent = state.sessionKey;
      setBadge(els.badgeAlice, 'Waiting Ticket Forward', 'status-waiting');
      setBadge(els.badgeKdc, 'Issued K_AB & Ticket', 'status-authenticated');
    } else if (state.step === 1) {
      els.valKdcKAB.textContent = 'Generating...';
      els.valAliceKAB.textContent = 'None';
      setBadge(els.badgeAlice, 'Waiting KDC Response', 'status-waiting');
      setBadge(els.badgeKdc, 'Processing Request', 'status-encrypting');
    } else {
      els.valKdcKAB.textContent = 'None';
      els.valAliceKAB.textContent = 'None';
      setBadge(els.badgeAlice, 'Idle', 'status-idle');
      setBadge(els.badgeKdc, 'Listening', 'status-idle');
    }

    if (state.step >= 3) {
      els.valBobKAB.textContent = state.sessionKey;
      if (state.step === 3) {
        setBadge(els.badgeBob, 'Ticket Decrypted (K_AB Extracted)', 'status-decrypting');
      } else if (state.step === 4) {
        setBadge(els.badgeBob, 'Waiting Nonce Challenge Response', 'status-waiting');
        setBadge(els.badgeAlice, 'Decrypting Challenge (N_B)', 'status-decrypting');
      } else if (state.step === 5) {
        setBadge(els.badgeBob, 'Mutual Auth Complete!', 'status-authenticated');
        setBadge(els.badgeAlice, 'Authenticated!', 'status-authenticated');
      }
    } else {
      els.valBobKAB.textContent = 'None';
      setBadge(els.badgeBob, 'Idle', 'status-idle');
    }

    // Highlight active cards
    [els.cardAlice, els.cardKdc, els.cardBob].forEach(c => c.classList.remove('highlight'));
    if (state.step === 1 || state.step === 2) {
      els.cardAlice.classList.add('highlight');
      els.cardKdc.classList.add('highlight');
    } else if (state.step >= 3) {
      els.cardAlice.classList.add('highlight');
      els.cardBob.classList.add('highlight');
    }

    // Buttons
    els.btnInitHandshake.disabled = state.step > 0 && state.step < 5;
    els.btnNextStep.disabled = state.step === 0 || state.step === 5;

    // Render Inspector Data
    renderInspector(state.step);
  }

  function setBadge(element, text, statusClass) {
    element.textContent = text;
    element.className = `entity-badge ${statusClass}`;
  }

  function renderInspector(step) {
    let title = '';
    let mathStr = '';
    let ciphertext = '';
    let tableRows = '';
    let explain = '';

    const ticketStr = `{ K_AB: "${state.sessionKey}", A: "${state.aliceId}" }_K_B`;

    switch (step) {
      case 0:
        title = 'Protocol Idle';
        mathStr = 'A → S : A, B, N_A';
        ciphertext = 'No active payload transmitted yet.';
        tableRows = `<tr><td colspan="4" style="text-align:center; color:#777;">Click "Initialize Handshake" to begin.</td></tr>`;
        explain = 'The Needham-Schroeder symmetric key protocol establishes a mutual symmetric session key K_AB between Alice and Bob using trusted Server S.';
        break;

      case 1:
        title = `Step 1: Session Key Request (${state.aliceId} → KDC)`;
        mathStr = `${state.aliceId} → S : ${state.aliceId}, ${state.bobId}, ${state.nonceA}`;
        ciphertext = `Plaintext Request Payload: [ ID_A: "${state.aliceId}", ID_B: "${state.bobId}", Nonce_A: "${state.nonceA}" ]`;
        tableRows = `
          <tr><td>ID_A</td><td>${state.aliceId}</td><td>Plaintext</td><td>Identifies originator to KDC</td></tr>
          <tr><td>ID_B</td><td>${state.bobId}</td><td>Plaintext</td><td>Identifies intended target recipient</td></tr>
          <tr><td>N_A</td><td>${state.nonceA}</td><td>Plaintext</td><td>Fresh 16-bit nonce generated by Alice</td></tr>
        `;
        explain = `<strong>Security Purpose:</strong> Alice contacts the KDC requesting to communicate with Bob. Nonce <code>N_A</code> binds this session request to protect Alice from receiving old replayed responses.`;
        break;

      case 2:
        title = `Step 2: Key & Ticket Response (KDC → ${state.aliceId})`;
        mathStr = `S → ${state.aliceId} : { ${state.nonceA}, ${state.bobId}, K_AB, { K_AB, ${state.aliceId} }_{K_B} }_{K_A}`;
        ciphertext = `ENC_K_A (${state.keyA}) [ N_A: "${state.nonceA}", ID_B: "${state.bobId}", K_AB: "${state.sessionKey}", Ticket: "${ticketStr}" ]`;
        tableRows = `
          <tr><td>N_A</td><td>${state.nonceA}</td><td>K_A (${state.keyA})</td><td>Verifies freshness of KDC response to Alice</td></tr>
          <tr><td>ID_B</td><td>${state.bobId}</td><td>K_A (${state.keyA})</td><td>Confirms target identity</td></tr>
          <tr><td>K_AB</td><td>${state.sessionKey}</td><td>K_A (${state.keyA})</td><td>Newly issued symmetric session key</td></tr>
          <tr><td>Ticket</td><td><code>${ticketStr}</code></td><td>K_B (${state.keyB})</td><td>Encrypted ticket containing K_AB forwarded to Bob</td></tr>
        `;
        explain = `<strong>Security Purpose:</strong> KDC generates session key <code>K_AB</code>. Encrypts response with Alice's master key <code>K_A</code>. Alice decrypts this, confirms <code>N_A</code> matches, and extracts <code>K_AB</code> and the Ticket.`;
        break;

      case 3:
        title = `Step 3: Forward Ticket (${state.aliceId} → ${state.bobId})`;
        mathStr = `${state.aliceId} → ${state.bobId} : { K_AB, ${state.aliceId} }_{K_B}`;
        ciphertext = `FORWARDED TICKET PAYLOAD: ENC_K_B (${state.keyB}) [ K_AB: "${state.sessionKey}", ID_A: "${state.aliceId}" ]`;
        tableRows = `
          <tr><td>Ticket Payload</td><td><code>${ticketStr}</code></td><td>K_B (${state.keyB})</td><td>Opaque encrypted ticket from KDC</td></tr>
          <tr><td>K_AB (Extracted)</td><td>${state.sessionKey}</td><td>K_B (${state.keyB})</td><td>Bob decrypts ticket using K_B to extract session key</td></tr>
          <tr><td>ID_A</td><td>${state.aliceId}</td><td>K_B (${state.keyB})</td><td>Identifies authorized communication partner</td></tr>
        `;
        explain = `<strong>Security Purpose:</strong> Alice forwards the opaque ticket to Bob. Bob decrypts it using master key <code>K_B</code> to obtain session key <code>K_AB</code> without Alice learning <code>K_B</code>.`;
        break;

      case 4:
        title = `Step 4: Nonce Challenge (${state.bobId} → ${state.aliceId})`;
        mathStr = `${state.bobId} → ${state.aliceId} : { ${state.nonceB} }_{K_AB}`;
        ciphertext = `ENC_K_AB (${state.sessionKey}) [ Nonce_B: "${state.nonceB}" ]`;
        tableRows = `
          <tr><td>N_B</td><td>${state.nonceB}</td><td>K_AB (${state.sessionKey})</td><td>Bob's fresh 16-bit challenge nonce</td></tr>
        `;
        explain = `<strong>Security Purpose:</strong> Bob challenges the presenter of the ticket to prove knowledge of session key <code>K_AB</code> by generating fresh nonce <code>N_B</code> and encrypting it under <code>K_AB</code>.`;
        break;

      case 5:
        const nonceBVal = parseInt(state.nonceB, 16);
        const respNonceHex = '0x' + (isNaN(nonceBVal) ? '8A1B' : (nonceBVal - 1).toString(16).toUpperCase().padStart(4, '0'));
        title = `Step 5: Challenge Response (${state.aliceId} → ${state.bobId})`;
        mathStr = `${state.aliceId} → ${state.bobId} : { f(${state.nonceB}) }_{K_AB}  where f(N_B) = N_B - 1 (${respNonceHex})`;
        ciphertext = `ENC_K_AB (${state.sessionKey}) [ f(N_B): "${respNonceHex}" ]`;
        tableRows = `
          <tr><td>f(N_B)</td><td>${respNonceHex}</td><td>K_AB (${state.sessionKey})</td><td>Transformed nonce (N_B - 1) proving active key possession</td></tr>
          <tr><td>Mutual Auth</td><td><span style="color:var(--vlab-success-green); font-weight:bold;">SUCCESS</span></td><td>-</td><td>Both parties authenticated & share key K_AB</td></tr>
        `;
        explain = `<strong>Security Purpose:</strong> Alice decrypts <code>N_B</code>, calculates <code>N_B - 1</code>, re-encrypts with <code>K_AB</code>, and returns it. Bob verifies the value, completing mutual authentication!`;
        break;
    }

    els.inspectorTitle.textContent = title;
    els.inspectorMath.textContent = mathStr;
    els.inspectorCiphertext.textContent = ciphertext;
    els.inspectorTableBody.innerHTML = tableRows;
    els.inspectorExplain.innerHTML = explain;
  }

  // Quiz Engine for Pretest & Posttest
  function renderQuiz(containerId, questions, submitBtnId, resetBtnId, scoreBannerId) {
    const container = document.getElementById(containerId);
    const submitBtn = document.getElementById(submitBtnId);
    const resetBtn = document.getElementById(resetBtnId);
    const scoreBanner = document.getElementById(scoreBannerId);

    if (!container || !submitBtn) return;

    container.innerHTML = '';
    questions.forEach((q, qIndex) => {
      const card = document.createElement('div');
      card.className = 'quiz-question-card';

      let optsHtml = '';
      q.options.forEach((opt, optIndex) => {
        optsHtml += `
          <label class="quiz-option-item" id="lbl-${q.id}-${optIndex}">
            <input type="radio" name="${q.id}" value="${optIndex}">
            <span>${opt}</span>
          </label>
        `;
      });

      card.innerHTML = `
        <div class="quiz-question-text">${q.question}</div>
        <div class="quiz-option-list">${optsHtml}</div>
        <div class="quiz-explanation" id="explain-${q.id}"></div>
      `;
      container.appendChild(card);
    });

    submitBtn.addEventListener('click', () => {
      let score = 0;
      questions.forEach(q => {
        const selected = document.querySelector(`input[name="${q.id}"]:checked`);
        const explainBox = document.getElementById(`explain-${q.id}`);

        q.options.forEach((_, optIndex) => {
          const lbl = document.getElementById(`lbl-${q.id}-${optIndex}`);
          lbl.classList.remove('correct', 'incorrect');
        });

        if (selected) {
          const val = parseInt(selected.value, 10);
          const selLbl = document.getElementById(`lbl-${q.id}-${val}`);

          if (val === q.correct) {
            score++;
            selLbl.classList.add('correct');
            explainBox.className = 'quiz-explanation visible correct';
            explainBox.innerHTML = `<strong>Correct!</strong> ${q.explanation}`;
          } else {
            selLbl.classList.add('incorrect');
            const correctLbl = document.getElementById(`lbl-${q.id}-${q.correct}`);
            correctLbl.classList.add('correct');
            explainBox.className = 'quiz-explanation visible incorrect';
            explainBox.innerHTML = `<strong>Incorrect.</strong> ${q.explanation}`;
          }
        } else {
          explainBox.className = 'quiz-explanation visible incorrect';
          explainBox.innerHTML = `<strong>Not answered.</strong> ${q.explanation}`;
        }
      });

      scoreBanner.style.display = 'block';
      scoreBanner.className = 'inspector-explanation';
      scoreBanner.style.backgroundColor = 'var(--vlab-info-bg)';
      scoreBanner.style.borderColor = 'var(--vlab-primary-blue)';
      scoreBanner.innerHTML = `<strong>Score: ${score} / ${questions.length} (${(score/questions.length * 100).toFixed(0)}%)</strong>`;
    });

    resetBtn.addEventListener('click', () => {
      questions.forEach(q => {
        const selected = document.querySelector(`input[name="${q.id}"]:checked`);
        if (selected) selected.checked = false;
        q.options.forEach((_, optIndex) => {
          const lbl = document.getElementById(`lbl-${q.id}-${optIndex}`);
          lbl.classList.remove('correct', 'incorrect');
        });
        const explainBox = document.getElementById(`explain-${q.id}`);
        explainBox.className = 'quiz-explanation';
        explainBox.innerHTML = '';
      });
      scoreBanner.style.display = 'none';
    });
  }

  // Auto-init on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return {
    init,
    state
  };
})();
