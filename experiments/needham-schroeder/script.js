/**
 * Needham-Schroeder Symmetric Key Protocol Virtual Lab Engine
 * IIT Kharagpur Virtual Labs Specification
 * Fully Scoped Namespace: NSLab
 * Palette: Warm Brown (#764b38) & Soft Cream (#fdf8f5)
 * Features: Hamburger Sidebar Toggle, Single-Viewport Dashboard, Zero-Jargon Plain English Explanations
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
    alice: { x: 16, y: 72 },
    kdc: { x: 50, y: 20 },
    bob: { x: 84, y: 72 }
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
      explanation: 'Correct! A Key Distribution Center (KDC) acts as a trusted central authority holding master secret passwords shared individually with each client. It generates short-lived session keys on demand.'
    },
    {
      id: 'pre_2',
      question: '2. In network security, what is a Nonce (Random Challenge Number)?',
      options: [
        'a: A permanent master secret key shared between Alice and Bob',
        'b: A random or non-repeating value generated once to guarantee freshness and prevent replay attacks',
        'c: A hash digest of the user password',
        'd: An unencrypted public key certificate'
      ],
      correct: 1,
      explanation: 'Correct! A Nonce ("number used once") ensures that a message or challenge is fresh and has not been replayed by a hacker from a past recorded session.'
    },
    {
      id: 'pre_3',
      question: '3. Why is plaintext identity transmission required in Step 1 (A -> S: A, B, N_A)?',
      options: [
        'a: To allow KDC to look up Alice\'s Secret Master Password and Bob\'s Secret Master Password in its database',
        'b: To encrypt Alice\'s master key using Bob\'s ID',
        'c: To bypass KDC authentication rules',
        'd: To generate a public key certificate for Bob'
      ],
      correct: 0,
      explanation: 'Correct! The Server must know who is making the request (Alice) and who she wants to talk to (Bob) so it can select Alice\'s Secret Master Password and Bob\'s Secret Master Password to build the response and ticket.'
    },
    {
      id: 'pre_4',
      question: '4. In symmetric key establishment, what is a Ticket?',
      options: [
        'a: An unencrypted text file containing user login details',
        'b: An encrypted digital pass intended for Bob containing the Temporary Session Key and Alice\'s ID, encrypted with Bob\'s Secret Master Password',
        'c: A digital signature created with Alice\'s private key',
        'd: A token sent to KDC to invalidate old keys'
      ],
      correct: 1,
      explanation: 'Correct! The ticket allows Alice to pass Bob\'s portion of the session credentials without Alice being able to read or tamper with Bob\'s Secret Master Password.'
    },
    {
      id: 'pre_5',
      question: '5. Which of the following is NOT typically assumed in the threat model of a symmetric key exchange protocol?',
      options: [
        'a: An attacker can intercept and read messages on the network',
        'b: An attacker can inject or alter messages in transit',
        'c: An attacker has compromised the Key Distribution Center (KDC)',
        'd: An attacker can record past messages and attempt to replay them'
      ],
      correct: 2,
      explanation: 'Correct! The KDC is a Trusted Third Party. If the KDC is compromised, the entire security of the system is broken. We assume the KDC remains secure.'
    }
  ];

  // Posttest Questions Data
  const posttestQuestions = [
    {
      id: 'post_1',
      question: '1. What security property does Alice verify when she decrypts {N_A, Bob, K_AB, Ticket} in Step 2?',
      options: [
        'a: That Bob has already received the session key',
        'b: That the response is fresh and directly answers her Step 1 request because it contains Alice\'s Random Challenge Number (N_A)',
        'c: That KDC has deleted its copy of Alice\'s Secret Master Password',
        'd: That K_AB is an asymmetric key pair'
      ],
      correct: 1,
      explanation: 'Correct! Including N_A inside the ciphertext encrypted under Alice\'s master password proves to Alice that the Server received her recent request and generated a fresh response.'
    },
    {
      id: 'post_2',
      question: '2. Why does Bob send challenge {N_B} encrypted with the Temporary Session Key in Step 4?',
      options: [
        'a: To prove that the sender of the ticket actually possesses the Temporary Shared Secret Key (Session Key)',
        'b: To request KDC to issue a new ticket',
        'c: To decrypt Alice\'s Secret Master Password',
        'd: To calculate a hash digest of N_A'
      ],
      correct: 0,
      explanation: 'Correct! Anyone could eavesdrop and forward an encrypted ticket. Step 4 challenges the sender to prove active knowledge of the session key.'
    },
    {
      id: 'post_3',
      question: '3. In Step 5, Alice responds with {N_B - 1} encrypted under the session key. Why is the function (N_B - 1) performed?',
      options: [
        'a: To prevent reflection attacks where an adversary echoes back the exact same challenge ciphertext without knowing the session key',
        'b: To compress the session key for faster network transit',
        'c: To notify KDC that the handshake finished',
        'd: To reset Bob\'s Secret Master Password'
      ],
      correct: 0,
      explanation: 'Correct! Performing a known mathematical operation (such as subtracting 1) proves that Alice decrypted N_B, modified it, and re-encrypted it, proving active key possession.'
    },
    {
      id: 'post_4',
      question: '4. What is the major vulnerability of the original 1978 Needham-Schroeder symmetric protocol identified by Denning and Sacco (1981)?',
      options: [
        'a: Master keys are sent in plaintext',
        'b: Step 3\'s ticket lacks a timestamp or Bob-nonce, enabling replay of an old compromised ticket to Bob',
        'c: Nonces are restricted to 8 bits',
        'd: KDC cannot support more than two clients'
      ],
      correct: 1,
      explanation: 'Correct! The Denning-Sacco vulnerability showed that if an old session key is compromised, an attacker can replay an old ticket to Bob, who cannot verify ticket freshness without a timestamp.'
    },
    {
      id: 'post_5',
      question: '5. What modification did Denning and Sacco propose to fix the replay vulnerability in the original Needham-Schroeder protocol?',
      options: [
        'a: Removing the Key Distribution Center and using peer-to-peer key exchange',
        'b: Adding timestamps to the tickets to enforce a strict validity window',
        'c: Switching from symmetric encryption to public key cryptography',
        'd: Encrypting the plaintext identities in Step 1'
      ],
      correct: 1,
      explanation: 'Correct! Denning and Sacco proposed using timestamps in the tickets so Bob can verify that a ticket is recent, preventing the replay of old, compromised session keys.'
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

    // Auto-compute and draw topology interconnection lines
    window.addEventListener('resize', updateTopologyLines);
    if (window.ResizeObserver && els.container) {
      const ro = new ResizeObserver(() => updateTopologyLines());
      ro.observe(els.container);
    }
    setTimeout(updateTopologyLines, 50);
    setTimeout(updateTopologyLines, 200);
  }

  function cacheDOM() {
    els = {
      // Hamburger Menu & Content Grid
      btnToggleSidebar: document.getElementById('btnToggleSidebar'),
      contentGrid: document.querySelector('.vlab-content-grid'),

      // Sidebar Navigation Links & Panels
      navLinks: document.querySelectorAll('.vlab-nav-link'),
      tabPanels: document.querySelectorAll('.vlab-tab-panel'),

      // Simulation Controls
      selectAlice: document.getElementById('selectAlice'),
      selectBob: document.getElementById('selectBob'),
      selectNonceMode: document.getElementById('selectNonceMode'),
      btnInitHandshake: document.getElementById('btnInitHandshake'),
      btnNextStep: document.getElementById('btnNextStep'),
      btnResetSim: document.getElementById('btnResetSim'),
      btnToggleConcepts: document.getElementById('btnToggleConcepts'),
      fresherCollapsibleBox: document.getElementById('fresherCollapsibleBox'),

      // Stepper Pills
      stepPillItems: document.querySelectorAll('.step-pill-item'),

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

      // Animated Packet & Topology Canvas Elements
      packet: document.getElementById('visualPacket'),
      container: document.querySelector('.topology-container-compact'),
      topologySvg: document.getElementById('topologySvg'),
      lineBaseAliceKdc: document.getElementById('lineBaseAliceKdc'),
      lineBaseKdcBob: document.getElementById('lineBaseKdcBob'),
      lineBaseAliceBob: document.getElementById('lineBaseAliceBob'),
      lineActiveTransmission: document.getElementById('lineActiveTransmission'),
      labelAliceKdc: document.getElementById('labelAliceKdc'),
      labelKdcBob: document.getElementById('labelKdcBob'),
      labelAliceBob: document.getElementById('labelAliceBob'),

      // Inspector Panel & Audit
      inspectorTitle: document.getElementById('inspectorTitle'),
      inspectorMath: document.getElementById('inspectorMath'),
      inspectorCiphertext: document.getElementById('inspectorCiphertext'),
      inspectorTableBody: document.getElementById('inspectorTableBody'),
      inspectorStoryCallout: document.getElementById('inspectorStoryCallout'),
      auditConsole: document.getElementById('auditConsole')
    };
  }

  function bindEvents() {
    // Hamburger Sidebar Toggle
    if (els.btnToggleSidebar && els.contentGrid) {
      els.btnToggleSidebar.addEventListener('click', () => {
        els.contentGrid.classList.toggle('sidebar-collapsed');
        setTimeout(updateTopologyLines, 310);
      });
    }

    // Toggle Beginner Concepts Guide Box
    if (els.btnToggleConcepts && els.fresherCollapsibleBox) {
      els.btnToggleConcepts.addEventListener('click', () => {
        els.fresherCollapsibleBox.classList.toggle('visible');
        setTimeout(updateTopologyLines, 300);
      });
    }

      // Trigger SVG redraw when simulation tab is clicked
      const tabBtns = document.querySelectorAll('.tab-btn');
      tabBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
          if (btn.getAttribute('data-tab') === 'simulation') {
            setTimeout(updateTopologyLines, 40);
            setTimeout(updateTopologyLines, 180);
            setTimeout(updateTopologyLines, 400);
          }
        });
      });

    // Controls
    els.btnInitHandshake.addEventListener('click', initHandshake);
    els.btnNextStep.addEventListener('click', advanceStep);
    els.btnResetSim.addEventListener('click', resetSim);
  }

  // Calculate live geometric anchor points for all entity cards
  function getTopologyAnchors() {
    if (!els.container || !els.cardAlice || !els.cardKdc || !els.cardBob) return null;

    const cRect = els.container.getBoundingClientRect();
    if (cRect.width === 0 || cRect.height === 0) return null;

    const aRect = els.cardAlice.getBoundingClientRect();
    const kRect = els.cardKdc.getBoundingClientRect();
    const bRect = els.cardBob.getBoundingClientRect();

    // Alice anchors (relative to container)
    const aLeft = aRect.left - cRect.left;
    const aTop = aRect.top - cRect.top;
    const aWidth = aRect.width;
    const aHeight = aRect.height;
    const aTopAnchor = { x: aLeft + aWidth * 0.65, y: aTop };
    const aRightAnchor = { x: aLeft + aWidth, y: aTop + aHeight * 0.5 };

    // KDC anchors
    const kLeft = kRect.left - cRect.left;
    const kTop = kRect.top - cRect.top;
    const kWidth = kRect.width;
    const kHeight = kRect.height;
    const kBottomLeftAnchor = { x: kLeft + kWidth * 0.25, y: kTop + kHeight };
    const kBottomRightAnchor = { x: kLeft + kWidth * 0.75, y: kTop + kHeight };

    // Bob anchors
    const bLeft = bRect.left - cRect.left;
    const bTop = bRect.top - cRect.top;
    const bWidth = bRect.width;
    const bHeight = bRect.height;
    const bTopAnchor = { x: bLeft + bWidth * 0.35, y: bTop };
    const bLeftAnchor = { x: bLeft, y: bTop + bHeight * 0.5 };

    return {
      cRect,
      aTopAnchor,
      aRightAnchor,
      kBottomLeftAnchor,
      kBottomRightAnchor,
      bTopAnchor,
      bLeftAnchor
    };
  }

  // Dynamically position interconnection lines and active directional flows
  function updateTopologyLines() {
    const anchors = getTopologyAnchors();
    if (!anchors || !els.topologySvg) return;

    // Synchronize SVG viewBox with current container dimensions
    els.topologySvg.setAttribute('viewBox', `0 0 ${anchors.cRect.width} ${anchors.cRect.height}`);

    // 1. Base Line Alice <-> Server (KDC)
    if (els.lineBaseAliceKdc) {
      els.lineBaseAliceKdc.setAttribute('d', `M ${anchors.aTopAnchor.x.toFixed(1)} ${anchors.aTopAnchor.y.toFixed(1)} L ${anchors.kBottomLeftAnchor.x.toFixed(1)} ${anchors.kBottomLeftAnchor.y.toFixed(1)}`);
    }

    // 2. Base Line Server (KDC) <-> Bob
    if (els.lineBaseKdcBob) {
      els.lineBaseKdcBob.setAttribute('d', `M ${anchors.kBottomRightAnchor.x.toFixed(1)} ${anchors.kBottomRightAnchor.y.toFixed(1)} L ${anchors.bTopAnchor.x.toFixed(1)} ${anchors.bTopAnchor.y.toFixed(1)}`);
    }

    // 3. Base Line Alice <-> Bob
    if (els.lineBaseAliceBob) {
      els.lineBaseAliceBob.setAttribute('d', `M ${anchors.aRightAnchor.x.toFixed(1)} ${anchors.aRightAnchor.y.toFixed(1)} L ${anchors.bLeftAnchor.x.toFixed(1)} ${anchors.bLeftAnchor.y.toFixed(1)}`);
    }

    // Channel labels positioned at midpoints
    if (els.labelAliceKdc) {
      const midX = (anchors.aTopAnchor.x + anchors.kBottomLeftAnchor.x) / 2 - 20;
      const midY = (anchors.aTopAnchor.y + anchors.kBottomLeftAnchor.y) / 2;
      els.labelAliceKdc.setAttribute('x', midX.toFixed(1));
      els.labelAliceKdc.setAttribute('y', midY.toFixed(1));
    }

    if (els.labelKdcBob) {
      const midX = (anchors.kBottomRightAnchor.x + anchors.bTopAnchor.x) / 2 + 20;
      const midY = (anchors.kBottomRightAnchor.y + anchors.bTopAnchor.y) / 2;
      els.labelKdcBob.setAttribute('x', midX.toFixed(1));
      els.labelKdcBob.setAttribute('y', midY.toFixed(1));
    }

    if (els.labelAliceBob) {
      const midX = (anchors.aRightAnchor.x + anchors.bLeftAnchor.x) / 2;
      const midY = anchors.aRightAnchor.y - 12;
      els.labelAliceBob.setAttribute('x', midX.toFixed(1));
      els.labelAliceBob.setAttribute('y', midY.toFixed(1));
    }

    // Active Transmission Line
    if (els.lineActiveTransmission) {
      if (!state.isInitialized || state.step === 0) {
        els.lineActiveTransmission.classList.remove('visible', 'animating');
      } else {
        els.lineActiveTransmission.classList.add('visible', 'animating');
        let d = '';
        switch (state.step) {
          case 1:
            // Step 1: Alice -> KDC
            d = `M ${anchors.aTopAnchor.x.toFixed(1)} ${anchors.aTopAnchor.y.toFixed(1)} L ${anchors.kBottomLeftAnchor.x.toFixed(1)} ${anchors.kBottomLeftAnchor.y.toFixed(1)}`;
            break;
          case 2:
            // Step 2: KDC -> Alice
            d = `M ${anchors.kBottomLeftAnchor.x.toFixed(1)} ${anchors.kBottomLeftAnchor.y.toFixed(1)} L ${anchors.aTopAnchor.x.toFixed(1)} ${anchors.aTopAnchor.y.toFixed(1)}`;
            break;
          case 3:
            // Step 3: Alice -> Bob
            d = `M ${anchors.aRightAnchor.x.toFixed(1)} ${anchors.aRightAnchor.y.toFixed(1)} L ${anchors.bLeftAnchor.x.toFixed(1)} ${anchors.bLeftAnchor.y.toFixed(1)}`;
            break;
          case 4:
            // Step 4: Bob -> Alice
            d = `M ${anchors.bLeftAnchor.x.toFixed(1)} ${anchors.bLeftAnchor.y.toFixed(1)} L ${anchors.aRightAnchor.x.toFixed(1)} ${anchors.aRightAnchor.y.toFixed(1)}`;
            break;
          case 5:
            // Step 5: Alice -> Bob
            d = `M ${anchors.aRightAnchor.x.toFixed(1)} ${anchors.aRightAnchor.y.toFixed(1)} L ${anchors.bLeftAnchor.x.toFixed(1)} ${anchors.bLeftAnchor.y.toFixed(1)}`;
            break;
        }
        els.lineActiveTransmission.setAttribute('d', d);
      }
    }
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
    logAudit('INFO', `Handshake Initialized. Initiator: ${state.aliceId}, Target: ${state.bobId}, Master Password A: ${state.keyA}, Master Password B: ${state.keyB}`);
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
    if (els.packet) {
      els.packet.classList.remove('active');
      els.packet.style.transition = 'none';
    }
    logAudit('INFO', 'Simulation reset to idle configuration.');
    updateUI();
    updateTopologyLines();
  }

  function executeStep(stepNum) {
    updateTopologyLines();
    const anchors = getTopologyAnchors();
    if (!anchors) return;

    switch (stepNum) {
      case 1:
        logAudit('INFO', `Step 1: ${state.aliceId} requests Server for a session key to talk to ${state.bobId}. Payload: (${state.aliceId}, ${state.bobId}, Alice Nonce=${state.nonceA})`);
        animatePacket(anchors.aTopAnchor, anchors.kBottomLeftAnchor, 'Step 1: Request');
        break;
      case 2:
        logAudit('INFO', `Step 2: Server generates Temporary Session Key (${state.sessionKey}) and encrypted response for ${state.aliceId}.`);
        animatePacket(anchors.kBottomLeftAnchor, anchors.aTopAnchor, 'Step 2: Response');
        break;
      case 3:
        logAudit('INFO', `Step 3: ${state.aliceId} forwards opaque Ticket encrypted under Bob's Password to ${state.bobId}.`);
        animatePacket(anchors.aRightAnchor, anchors.bLeftAnchor, 'Step 3: Ticket');
        break;
      case 4:
        logAudit('INFO', `Step 4: ${state.bobId} unlocks ticket, extracts Session Key, and challenges ${state.aliceId} with encrypted Nonce=${state.nonceB}.`);
        animatePacket(anchors.bLeftAnchor, anchors.aRightAnchor, 'Step 4: Challenge');
        break;
      case 5:
        logAudit('SUCCESS', `Step 5: ${state.aliceId} responds with encrypted f(N_B) = N_B - 1. Mutual authentication complete!`);
        animatePacket(anchors.aRightAnchor, anchors.bLeftAnchor, 'Step 5: Authenticated');
        break;
    }
  }

  function animatePacket(from, to, text) {
    if (!els.packet) return;
    els.packet.textContent = text;
    els.packet.style.transition = 'none';
    els.packet.style.left = `${from.x}px`;
    els.packet.style.top = `${from.y}px`;
    els.packet.classList.add('active');

    // Force layout reflow
    void els.packet.offsetWidth;

    setTimeout(() => {
      els.packet.style.transition = 'left 0.85s cubic-bezier(0.4, 0, 0.2, 1), top 0.85s cubic-bezier(0.4, 0, 0.2, 1)';
      els.packet.style.left = `${to.x}px`;
      els.packet.style.top = `${to.y}px`;
    }, 30);

    setTimeout(() => {
      els.packet.style.transition = 'none';
    }, 900);
  }

  function logAudit(type, message) {
    if (!els.auditConsole) return;
    const time = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = 'audit-log-line';
    line.innerHTML = `<span style="color:#888;">[${time}]</span> <span class="audit-tag ${type}">${type}</span> ${message}`;
    els.auditConsole.prepend(line);
  }

  function updateUI() {
    // 1. Update Compact Stepper Pills Row
    els.stepPillItems.forEach((pill, idx) => {
      pill.classList.remove('active', 'completed');
      if (idx === state.step) {
        pill.classList.add('active');
      } else if (idx < state.step) {
        pill.classList.add('completed');
      }
    });

    // 2. Update Node Names
    els.nameAlice.textContent = state.aliceId;
    els.nameBob.textContent = state.bobId;

    // 3. Update Stored Keys & Badges
    els.valAliceKA.textContent = state.keyA;
    els.valKdcKA.textContent = state.keyA;
    els.valKdcKB.textContent = state.keyB;
    els.valBobKB.textContent = state.keyB;

    if (state.step >= 2) {
      els.valKdcKAB.textContent = state.sessionKey;
      els.valAliceKAB.textContent = state.sessionKey;
      setBadge(els.badgeAlice, 'WAITING TICKET FORWARD', 'status-waiting');
      setBadge(els.badgeKdc, 'ISSUED SESSION KEY AND TICKET', 'status-authenticated');
    } else if (state.step === 1) {
      els.valKdcKAB.textContent = 'Generating...';
      els.valAliceKAB.textContent = 'None';
      setBadge(els.badgeAlice, 'REQUESTING SERVER', 'status-requesting');
      setBadge(els.badgeKdc, 'PROCESSING REQUEST', 'status-encrypting');
    } else {
      els.valKdcKAB.textContent = 'None';
      els.valAliceKAB.textContent = 'None';
      setBadge(els.badgeAlice, 'IDLE', 'status-idle');
      setBadge(els.badgeKdc, 'LISTENING', 'status-idle');
    }

    if (state.step >= 3) {
      els.valBobKAB.textContent = state.sessionKey;
      if (state.step === 3) {
        setBadge(els.badgeBob, 'TICKET UNLOCKED (SESSION KEY EXTRACTED)', 'status-decrypting');
      } else if (state.step === 4) {
        setBadge(els.badgeBob, 'WAITING CHALLENGE RESPONSE', 'status-waiting');
        setBadge(els.badgeAlice, 'DECRYPTING CHALLENGE NUMBER', 'status-decrypting');
      } else if (state.step === 5) {
        setBadge(els.badgeBob, 'MUTUAL AUTHENTICATION COMPLETE', 'status-authenticated');
        setBadge(els.badgeAlice, 'AUTHENTICATED', 'status-authenticated');
      }
    } else {
      els.valBobKAB.textContent = 'None';
      setBadge(els.badgeBob, 'IDLE', 'status-idle');
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

    // Refresh topology lines and active flow
    updateTopologyLines();
  }

  function setBadge(element, text, statusClass) {
    element.textContent = text;
    element.className = `entity-badge-sm ${statusClass}`;
  }

  function renderInspector(step) {
    let title = '';
    let mathStr = '';
    let ciphertext = '';
    let tableRows = '';
    let storyText = '';

    const ticketStr = `{ Temporary Session Key: "${state.sessionKey}", Alice: "${state.aliceId}" }_BobPassword`;

    switch (step) {
      case 0:
        title = 'Step 1: System Setup (Idle)';
        mathStr = 'Alice -> Server (KDC) : Alice, Bob, Alice Challenge Number';
        ciphertext = 'No active message payload transmitted yet.';
        tableRows = `<tr><td colspan="5" style="text-align:center; color:#777;">Click "Initialize Handshake" to start the simulation.</td></tr>`;
        storyText = 'The system is ready. Click "Initialize Handshake" to see how Alice and Bob establish a temporary session pass using Server S.';
        break;

      case 1:
        title = `Step 1: Session Key Request (${state.aliceId} -> Server)`;
        mathStr = `${state.aliceId} -> Server : ${state.aliceId}, ${state.bobId}, ${state.nonceA}`;
        ciphertext = `Unencrypted Request Payload: [ Client_ID: "${state.aliceId}", Target_ID: "${state.bobId}", Alice_Challenge_Number: "${state.nonceA}" ]`;
        tableRows = `
          <tr>
            <td>Client ID</td>
            <td>${state.aliceId}</td>
            <td>Unencrypted (Plaintext)</td>
            <td>Identifies Alice to the Server</td>
            <td>Alice tells the Server who she is so the Server can fetch her secret password.</td>
          </tr>
          <tr>
            <td>Target ID</td>
            <td>${state.bobId}</td>
            <td>Unencrypted (Plaintext)</td>
            <td>Identifies intended target recipient</td>
            <td>Alice tells the Server she wants to open a private line with Bob.</td>
          </tr>
          <tr>
            <td>Alice Challenge Number</td>
            <td>${state.nonceA}</td>
            <td>Unencrypted (Plaintext)</td>
            <td>Alice's Random Challenge Number (N_A)</td>
            <td>Alice attaches a unique random number (${state.nonceA}) to ensure the Server's reply is brand new and not a hacker replaying an old answer.</td>
          </tr>
        `;
        storyText = `Alice asks the Server for a temporary key to talk to Bob and sends a single-use ticket number (${state.nonceA}). Because the message is unencrypted at this stage, any eavesdropper can see who is calling whom, but they cannot steal any passwords.`;
        break;

      case 2:
        title = `Step 2: Key & Ticket Response (Server -> ${state.aliceId})`;
        mathStr = `Server -> ${state.aliceId} : { ${state.nonceA}, ${state.bobId}, SessionKey, { SessionKey, ${state.aliceId} }_BobPassword }_AlicePassword`;
        ciphertext = `Encrypted with Alice Password (${state.keyA}) [ Challenge_Number: "${state.nonceA}", Target: "${state.bobId}", Session_Key: "${state.sessionKey}", Ticket: "${ticketStr}" ]`;
        tableRows = `
          <tr>
            <td>Challenge Number</td>
            <td>${state.nonceA}</td>
            <td>Alice's Secret Master Password (${state.keyA})</td>
            <td>Matches Alice's random challenge number</td>
            <td>Alice unlocks the box and sees her ticket number (${state.nonceA}). This proves 100% that the Server answered right now!</td>
          </tr>
          <tr>
            <td>Target ID</td>
            <td>${state.bobId}</td>
            <td>Alice's Secret Master Password (${state.keyA})</td>
            <td>Confirms target identity</td>
            <td>Confirms this temporary key is meant for talking to Bob.</td>
          </tr>
          <tr>
            <td>Session Key</td>
            <td>${state.sessionKey}</td>
            <td>Alice's Secret Master Password (${state.keyA})</td>
            <td>Temporary Shared Secret Key (Session Key)</td>
            <td>Alice extracts the new temporary pass (${state.sessionKey}) created for her chat with Bob.</td>
          </tr>
          <tr>
            <td>Ticket</td>
            <td><code>${ticketStr}</code></td>
            <td>Bob's Secret Master Password (${state.keyB})</td>
            <td>Encrypted digital envelope for Bob</td>
            <td>The Server includes a digital pass locked with Bob's Password. Alice cannot open it, but she will forward it to Bob.</td>
          </tr>
        `;
        storyText = `The Server creates a temporary visitor pass (${state.sessionKey}) and puts it inside a digital box locked with Alice's Secret Password. It also puts a locked envelope (the Ticket) inside that box for Bob. Alice unlocks her box, verifies her challenge number, and gets her pass code!`;
        break;

      case 3:
        title = `Step 3: Forward Ticket (${state.aliceId} -> ${state.bobId})`;
        mathStr = `${state.aliceId} -> ${state.bobId} : { SessionKey, ${state.aliceId} }_BobPassword`;
        ciphertext = `FORWARDED TICKET PAYLOAD: Encrypted with Bob Password (${state.keyB}) [ Session_Key: "${state.sessionKey}", Client_ID: "${state.aliceId}" ]`;
        tableRows = `
          <tr>
            <td>Ticket Payload</td>
            <td><code>${ticketStr}</code></td>
            <td>Bob's Secret Master Password (${state.keyB})</td>
            <td>Encrypted digital pass from Server</td>
            <td>Alice passes the locked digital envelope to Bob.</td>
          </tr>
          <tr>
            <td>Session Key (Extracted)</td>
            <td>${state.sessionKey}</td>
            <td>Bob's Secret Master Password (${state.keyB})</td>
            <td>Bob extracts Temporary Session Key</td>
            <td>Bob uses his Secret Master Password to unlock the envelope, retrieving the temporary pass (${state.sessionKey}).</td>
          </tr>
          <tr>
            <td>Client ID</td>
            <td>${state.aliceId}</td>
            <td>Bob's Secret Master Password (${state.keyB})</td>
            <td>Identifies authorized caller</td>
            <td>Bob verifies that the Server authorized Alice to speak with him.</td>
          </tr>
        `;
        storyText = `Alice forwards the locked envelope to Bob. Bob uses his secret password to open it, extracts the temporary pass code (${state.sessionKey}), and knows that Alice was authenticated by the Server!`;
        break;

      case 4:
        title = `Step 4: Nonce Challenge (${state.bobId} -> ${state.aliceId})`;
        mathStr = `${state.bobId} -> ${state.aliceId} : { ${state.nonceB} }_SessionKey`;
        ciphertext = `Encrypted with Session Key (${state.sessionKey}) [ Bob_Challenge_Number: "${state.nonceB}" ]`;
        tableRows = `
          <tr>
            <td>Bob Challenge Number</td>
            <td>${state.nonceB}</td>
            <td>Temporary Shared Secret Key (${state.sessionKey})</td>
            <td>Bob's Random Challenge Number (N_B)</td>
            <td>Bob locks a brand new random challenge number (${state.nonceB}) with the temporary pass and sends it to Alice.</td>
          </tr>
        `;
        storyText = `Bob wants to make sure that the person holding the ticket actually knows the temporary pass code! He locks a secret test number (${state.nonceB}) with the session key and challenges Alice to unlock it.`;
        break;

      case 5:
        const nonceBVal = parseInt(state.nonceB, 16);
        const respNonceHex = '0x' + (isNaN(nonceBVal) ? '8A1B' : (nonceBVal - 1).toString(16).toUpperCase().padStart(4, '0'));
        title = `Step 5: Challenge Response (${state.aliceId} -> ${state.bobId})`;
        mathStr = `${state.aliceId} -> ${state.bobId} : { f(${state.nonceB}) }_SessionKey where f(N_B) = N_B - 1 (${respNonceHex})`;
        ciphertext = `Encrypted with Session Key (${state.sessionKey}) [ Transformed_Number: "${respNonceHex}" ]`;
        tableRows = `
          <tr>
            <td>f(Bob Challenge Number)</td>
            <td>${respNonceHex}</td>
            <td>Temporary Shared Secret Key (${state.sessionKey})</td>
            <td>Transformed challenge number (N_B - 1)</td>
            <td>Alice unlocks Bob's test number, subtracts 1 to get ${respNonceHex}, locks it back with the temporary pass, and returns it.</td>
          </tr>
          <tr>
            <td>Mutual Authentication</td>
            <td><span style="color:var(--vlab-success-green); font-weight:bold;">SUCCESS</span></td>
            <td>-</td><td>Both parties authenticated</td>
            <td>Bob sees that the number was modified correctly. This proves Alice possesses the session key! Mutual authentication is complete.</td>
          </tr>
        `;
        storyText = `Alice unlocks Bob's test number, subtracts 1 to prove she didn't just echo back the same locked box, and sends it back encrypted. Bob checks the answer and confirms: Alice is genuine! Both parties now communicate safely.`;
        break;
    }

    els.inspectorTitle.textContent = title;
    els.inspectorMath.textContent = mathStr;
    els.inspectorCiphertext.textContent = ciphertext;
    els.inspectorTableBody.innerHTML = tableRows;
    els.inspectorStoryCallout.innerHTML = `<strong>Plain English Story:</strong> ${storyText}`;
  }

  // Quiz Engine for Pretest & Posttest
  function renderQuiz(containerId, questions, submitBtnId, resetBtnId, scoreBannerId) {
    const container = document.getElementById(containerId);
    const submitBtn = document.getElementById(submitBtnId);
    const resetBtn = document.getElementById(resetBtnId);
    const scoreBanner = document.getElementById(scoreBannerId);

    if (!container || !submitBtn) return;

    container.innerHTML = '';
    questions.forEach((q) => {
      const card = document.createElement('div');
      card.className = 'quiz-card question-item';

      let optsHtml = '';
      q.options.forEach((opt, optIndex) => {
        optsHtml += `
          <label class="option-label" id="lbl-${q.id}-${optIndex}">
            <input type="radio" name="${q.id}" value="${optIndex}" style="width:auto; margin-right: 0.5rem;">
            <span>${opt}</span>
          </label>
        `;
      });

      card.innerHTML = `
        <div class="question-title">${q.question}</div>
        <div class="options-list">${optsHtml}</div>
        <div class="explanation-box" id="explain-${q.id}"></div>
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
            explainBox.className = 'explanation-box visible correct';
            explainBox.innerHTML = `<strong>Correct.</strong> ${q.explanation}`;
          } else {
            selLbl.classList.add('incorrect');
            const correctLbl = document.getElementById(`lbl-${q.id}-${q.correct}`);
            correctLbl.classList.add('correct');
            explainBox.className = 'explanation-box visible incorrect';
            explainBox.innerHTML = `<strong>Incorrect.</strong> ${q.explanation}`;
          }
        } else {
          explainBox.className = 'explanation-box visible incorrect';
          explainBox.innerHTML = `<strong>Not answered.</strong> ${q.explanation}`;
        }
      });

      scoreBanner.style.display = 'flex';
      scoreBanner.className = 'quiz-score-banner';
      scoreBanner.innerHTML = `<strong>Assessment Result: ${score} / ${questions.length} (${(score/questions.length * 100).toFixed(0)}%)</strong>`;
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
        explainBox.className = 'explanation-box';
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
