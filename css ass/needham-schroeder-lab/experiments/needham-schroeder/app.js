/**
 * Needham-Schroeder Symmetric Key Protocol Simulation Engine
 * Virtual Cryptography Lab (EXP06)
 */

document.addEventListener('DOMContentLoaded', () => {
  // Navigation & Tab Management
  initNavigation();

  // Protocol Engine State
  const state = {
    aliceId: 'Alice',
    bobId: 'Bob',
    nonceA: 'NA-9812',
    nonceB: 'NB-4730',
    keyA: 'K_Alice_789',
    keyB: 'K_Bob_456',
    sessionKey: 'KAB-8821',
    oldSessionKey: 'KAB-OLD-1978',
    step: 0,
    replayMode: false,
    autoPlayInterval: null,
    autoPlaySpeed: 1800,
    history: []
  };

  // Node Positions for Animation (percentage coordinates)
  const nodeCoords = {
    alice: { x: 16, y: 72 },
    kdc: { x: 50, y: 22 },
    bob: { x: 84, y: 72 },
    eve: { x: 84, y: 44 }
  };

  // DOM Elements
  const els = {
    // Inputs
    aliceIdInput: document.getElementById('aliceId'),
    bobIdInput: document.getElementById('bobId'),
    nonceAInput: document.getElementById('nonceA'),
    nonceBInput: document.getElementById('nonceB'),
    keyAInput: document.getElementById('keyA'),
    keyBInput: document.getElementById('keyB'),
    btnRandNA: document.getElementById('btnRandNA'),
    btnRandNB: document.getElementById('btnRandNB'),
    replayToggle: document.getElementById('replayToggle'),

    // Control Buttons
    btnStart: document.getElementById('btnStart'),
    btnNext: document.getElementById('btnNext'),
    btnAuto: document.getElementById('btnAuto'),
    btnReset: document.getElementById('btnReset'),
    speedSelect: document.getElementById('speedSelect'),

    // Stepper
    stepperProgress: document.getElementById('stepperProgress'),
    stepNodes: document.querySelectorAll('.step-node'),

    // Diagram Nodes & Packet
    packet: document.getElementById('animatedPacket'),
    nodeAlice: document.getElementById('nodeAlice'),
    nodeKdc: document.getElementById('nodeKdc'),
    nodeBob: document.getElementById('nodeBob'),
    nodeEve: document.getElementById('nodeEve'),

    // Node Badges & Displays
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

    // Inspector Panel
    msgTitle: document.getElementById('msgTitle'),
    rawCiphertext: document.getElementById('rawCiphertext'),
    breakdownBody: document.getElementById('breakdownBody'),
    cryptoExplain: document.getElementById('cryptoExplain'),
    auditLog: document.getElementById('auditLog'),

    // Quiz & Feedback
    quizSubmit: document.getElementById('quizSubmit'),
    quizReset: document.getElementById('quizReset'),
    quizScoreBanner: document.getElementById('quizScoreBanner'),
    feedbackForm: document.getElementById('feedbackForm')
  };

  // Attach Event Listeners
  initEventListeners();
  initQuiz();
  initFeedback();
  updateUIState();
  logAudit('INFO', 'Lab module initialized. Configure inputs and click "Start Protocol".');

  // Navigation Tabs logic
  function initNavigation() {
    const tabs = document.querySelectorAll('.nav-tab');
    const contents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const target = tab.getAttribute('data-tab');
        tabs.forEach(t => t.classList.remove('active'));
        contents.forEach(c => c.classList.remove('active'));

        tab.classList.add('active');
        document.getElementById(target).classList.add('active');
      });
    });
  }

  function initEventListeners() {
    // Randomize nonces
    els.btnRandNA.addEventListener('click', () => {
      const rand = 'NA-' + Math.floor(1000 + Math.random() * 9000);
      els.nonceAInput.value = rand;
      state.nonceA = rand;
    });

    els.btnRandNB.addEventListener('click', () => {
      const rand = 'NB-' + Math.floor(1000 + Math.random() * 9000);
      els.nonceBInput.value = rand;
      state.nonceB = rand;
    });

    // Replay toggle
    els.replayToggle.addEventListener('change', (e) => {
      state.replayMode = e.target.checked;
      if (state.replayMode) {
        els.nodeEve.style.display = 'block';
        logAudit('WARN', 'Replay Attack Mode Enabled! Eve will inject an old ticket in Step 3.');
      } else {
        els.nodeEve.style.display = 'none';
        logAudit('INFO', 'Standard Needham-Schroeder protocol mode active.');
      }
      resetSimulation();
    });

    // Controls
    els.btnStart.addEventListener('click', startProtocol);
    els.btnNext.addEventListener('click', nextStep);
    els.btnAuto.addEventListener('click', toggleAutoPlay);
    els.btnReset.addEventListener('click', resetSimulation);

    // Speed Selector
    els.speedSelect.addEventListener('change', (e) => {
      state.autoPlaySpeed = parseInt(e.target.value, 10);
      if (state.autoPlayInterval) {
        toggleAutoPlay(); // stop
        toggleAutoPlay(); // restart with new speed
      }
    });

    // Sync input values
    ['aliceId', 'bobId', 'nonceA', 'nonceB', 'keyA', 'keyB'].forEach(field => {
      const input = els[field + 'Input'];
      if (input) {
        input.addEventListener('change', () => {
          state[field] = input.value.trim() || state[field];
        });
      }
    });
  }

  // Generate a random session key
  function generateSessionKey() {
    return 'KAB-' + Math.floor(1000 + Math.random() * 9000);
  }

  function startProtocol() {
    // Synchronize state from inputs
    state.aliceId = els.aliceIdInput.value.trim() || 'Alice';
    state.bobId = els.bobIdInput.value.trim() || 'Bob';
    state.nonceA = els.nonceAInput.value.trim() || 'NA-9812';
    state.nonceB = els.nonceBInput.value.trim() || 'NB-4730';
    state.keyA = els.keyAInput.value.trim() || 'K_Alice_789';
    state.keyB = els.keyBInput.value.trim() || 'K_Bob_456';
    state.sessionKey = generateSessionKey();

    state.step = 0;
    logAudit('INFO', `Protocol Run Started. Shared Keys -> K_A: ${state.keyA}, K_B: ${state.keyB}`);
    nextStep();
  }

  function nextStep() {
    if (state.step >= 5) {
      logAudit('SUCCESS', 'Protocol execution completed successfully!');
      if (state.autoPlayInterval) toggleAutoPlay();
      return;
    }

    state.step++;
    executeStep(state.step);
    updateUIState();
  }

  function executeStep(stepNum) {
    switch (stepNum) {
      case 1:
        // Step 1: Alice -> KDC (A, B, NA)
        logAudit('CRYPTO', `[Step 1] ${state.aliceId} requests KDC session key to talk to ${state.bobId}. Plaintext: (${state.aliceId}, ${state.bobId}, ${state.nonceA})`);
        animatePacket(nodeCoords.alice, nodeCoords.kdc, 'Step 1: A→S');
        break;

      case 2:
        // Step 2: KDC -> Alice {NA, B, K_AB, Ticket}_KA
        logAudit('CRYPTO', `[Step 2] KDC generates K_AB (${state.sessionKey}) and encrypted response for ${state.aliceId} using K_A.`);
        animatePacket(nodeCoords.kdc, nodeCoords.alice, 'Step 2: S→A');
        break;

      case 3:
        // Step 3: Alice -> Bob {K_AB, A}_KB (or Eve -> Bob in Replay Mode)
        if (state.replayMode) {
          logAudit('WARN', `[Step 3 - REPLAY ATTACK] Eve intercepts traffic and replays compromised Ticket {${state.oldSessionKey}, ${state.aliceId}} encrypted with K_B to ${state.bobId}!`);
          animatePacket(nodeCoords.eve, nodeCoords.bob, 'REPLAY');
        } else {
          logAudit('CRYPTO', `[Step 3] ${state.aliceId} forwards Ticket {K_AB, ${state.aliceId}}_KB to ${state.bobId}.`);
          animatePacket(nodeCoords.alice, nodeCoords.bob, 'Step 3: A→B');
        }
        break;

      case 4:
        // Step 4: Bob -> Alice {NB}_KAB
        logAudit('CRYPTO', `[Step 4] ${state.bobId} decrypts ticket, extracts session key, and challenges ${state.aliceId} with encrypted nonce {${state.nonceB}}_KAB.`);
        animatePacket(nodeCoords.bob, nodeCoords.alice, 'Step 4: B→A');
        break;

      case 5:
        // Step 5: Alice -> Bob {NB - 1}_KAB
        const responseNonce = decrementNonce(state.nonceB);
        if (state.replayMode) {
          logAudit('WARN', `[Step 5 - REPLAY FAILED] ${state.aliceId} cannot complete challenge because she does not hold the old key ${state.oldSessionKey}. Bob detects failure!`);
        } else {
          logAudit('SUCCESS', `[Step 5] ${state.aliceId} decrypts challenge, computes f(${state.nonceB}) = ${responseNonce}, and returns encrypted response to ${state.bobId}. Mutual authentication complete!`);
        }
        animatePacket(nodeCoords.alice, nodeCoords.bob, 'Step 5: A→B');
        break;
    }
  }

  function decrementNonce(nonceStr) {
    const parts = nonceStr.split('-');
    if (parts.length === 2 && !isNaN(parts[1])) {
      return `${parts[0]}-${parseInt(parts[1], 10) - 1}`;
    }
    return nonceStr + '-1';
  }

  function animatePacket(from, to, text) {
    els.packet.textContent = text;
    els.packet.style.left = `${from.x}%`;
    els.packet.style.top = `${from.y}%`;
    els.packet.classList.add('visible');

    // Trigger reflow & animate
    setTimeout(() => {
      els.packet.style.transition = 'all 1s ease-in-out';
      els.packet.style.left = `${to.x}%`;
      els.packet.style.top = `${to.y}%`;
    }, 50);

    setTimeout(() => {
      els.packet.style.transition = 'none';
    }, 1100);
  }

  function updateUIState() {
    // Update Stepper Progress Bar
    const progressPct = ((state.step) / 5) * 100;
    els.stepperProgress.style.width = `${progressPct}%`;

    els.stepNodes.forEach((node, idx) => {
      const stepIdx = idx + 1;
      node.classList.remove('active', 'completed');
      if (stepIdx === state.step) {
        node.classList.add('active');
      } else if (stepIdx < state.step) {
        node.classList.add('completed');
      }
    });

    // Update Node Key Displays & Badges
    els.valAliceKA.textContent = state.keyA;
    els.valKdcKA.textContent = state.keyA;
    els.valKdcKB.textContent = state.keyB;
    els.valBobKB.textContent = state.keyB;

    if (state.step >= 2) {
      els.valKdcKAB.textContent = state.sessionKey;
      els.valAliceKAB.textContent = state.sessionKey;
      els.badgeAlice.textContent = 'Key Received';
      els.badgeAlice.className = 'entity-state-badge active-state';
      els.badgeKdc.textContent = 'Key Issued';
      els.badgeKdc.className = 'entity-state-badge success-state';
    } else {
      els.valKdcKAB.textContent = 'None';
      els.valAliceKAB.textContent = 'None';
      els.badgeAlice.textContent = 'Idle';
      els.badgeAlice.className = 'entity-state-badge';
      els.badgeKdc.textContent = 'Listening';
      els.badgeKdc.className = 'entity-state-badge';
    }

    if (state.step >= 3) {
      if (state.replayMode) {
        els.valBobKAB.textContent = state.oldSessionKey + ' (OLD)';
        els.badgeBob.textContent = 'Duped by Replay!';
        els.badgeBob.className = 'entity-state-badge active-state';
      } else {
        els.valBobKAB.textContent = state.sessionKey;
        els.badgeBob.textContent = 'Ticket Decrypted';
        els.badgeBob.className = 'entity-state-badge active-state';
      }
    } else {
      els.valBobKAB.textContent = 'None';
      els.badgeBob.textContent = 'Idle';
      els.badgeBob.className = 'entity-state-badge';
    }

    if (state.step === 5) {
      if (state.replayMode) {
        els.badgeBob.textContent = 'Auth Failed!';
        els.badgeBob.className = 'entity-state-badge';
        els.badgeBob.style.backgroundColor = 'var(--warning-color)';
        els.badgeBob.style.color = '#fff';
      } else {
        els.badgeBob.textContent = 'Authenticated!';
        els.badgeBob.className = 'entity-state-badge success-state';
      }
    }

    // Highlight active nodes
    [els.nodeAlice, els.nodeKdc, els.nodeBob, els.nodeEve].forEach(n => n.classList.remove('highlight'));
    if (state.step === 1) { els.nodeAlice.classList.add('highlight'); els.nodeKdc.classList.add('highlight'); }
    else if (state.step === 2) { els.nodeKdc.classList.add('highlight'); els.nodeAlice.classList.add('highlight'); }
    else if (state.step === 3) { 
      if (state.replayMode) { els.nodeEve.classList.add('highlight'); els.nodeBob.classList.add('highlight'); }
      else { els.nodeAlice.classList.add('highlight'); els.nodeBob.classList.add('highlight'); }
    }
    else if (state.step === 4) { els.nodeBob.classList.add('highlight'); els.nodeAlice.classList.add('highlight'); }
    else if (state.step === 5) { els.nodeAlice.classList.add('highlight'); els.nodeBob.classList.add('highlight'); }

    // Update Controls Button States
    els.btnStart.disabled = state.step > 0 && state.step < 5;
    els.btnNext.disabled = state.step === 5;

    // Update Inspector Content
    updateInspector(state.step);
  }

  function updateInspector(step) {
    let title = '';
    let ciphertext = '';
    let tableRows = '';
    let explain = '';

    const ticketStr = `{ ${state.sessionKey}, ${state.aliceId} }_${state.keyB}`;
    const oldTicketStr = `{ ${state.oldSessionKey}, ${state.aliceId} }_${state.keyB}`;

    switch (step) {
      case 0:
        title = 'Protocol Idle';
        ciphertext = 'No active payload transmitted yet.';
        tableRows = `<tr><td colspan="4" style="text-align:center;">Click "Start Protocol" to begin message transmission.</td></tr>`;
        explain = 'The Needham-Schroeder protocol establishes a symmetric session key between Alice and Bob using a trusted Key Distribution Center (KDC).';
        break;

      case 1:
        title = `Step 1: Request Session Key (${state.aliceId} → KDC)`;
        ciphertext = `Plaintext Request: [ ID_A: "${state.aliceId}", ID_B: "${state.bobId}", N_A: "${state.nonceA}" ]`;
        tableRows = `
          <tr><td>ID_A</td><td>${state.aliceId}</td><td>None (Plaintext)</td><td>Identifies request originator</td></tr>
          <tr><td>ID_B</td><td>${state.bobId}</td><td>None (Plaintext)</td><td>Identifies intended target recipient</td></tr>
          <tr><td>N_A</td><td>${state.nonceA}</td><td>None (Plaintext)</td><td>Fresh nonce to prevent replay of Step 2</td></tr>
        `;
        explain = `<strong>Security Purpose:</strong> Alice contacts KDC asking for a key to talk to Bob. The nonce <code>N_A</code> binds this specific request session so Alice can verify that the KDC's response is fresh and not a replayed message.`;
        break;

      case 2:
        title = `Step 2: KDC Session Key Response & Ticket (KDC → ${state.aliceId})`;
        ciphertext = `ENC_${state.keyA}( N_A: "${state.nonceA}", ID_B: "${state.bobId}", K_AB: "${state.sessionKey}", Ticket: "${ticketStr}" )`;
        tableRows = `
          <tr><td>N_A</td><td>${state.nonceA}</td><td>K_A (${state.keyA})</td><td>Matches Alice's nonce to confirm freshness</td></tr>
          <tr><td>ID_B</td><td>${state.bobId}</td><td>K_A (${state.keyA})</td><td>Confirms key is intended for communication with Bob</td></tr>
          <tr><td>K_AB</td><td>${state.sessionKey}</td><td>K_A (${state.keyA})</td><td>Newly generated symmetric session key</td></tr>
          <tr><td>Ticket</td><td><code>${ticketStr}</code></td><td>K_B (${state.keyB})</td><td>Encrypted envelope containing K_AB forwarded to Bob</td></tr>
        `;
        explain = `<strong>Security Purpose:</strong> KDC generates session key <code>K_AB</code>. Encrypts everything with Alice's master key <code>K_A</code>. Alice decrypts this, checks <code>N_A</code>, and extracts <code>K_AB</code> and the opaque Ticket intended for Bob.`;
        break;

      case 3:
        if (state.replayMode) {
          title = `Step 3 (REPLAY ATTACK): Eve forwards Compromised Ticket (Eve → ${state.bobId})`;
          ciphertext = `REPLAYED TICKET: ENC_${state.keyB}( K_AB_OLD: "${state.oldSessionKey}", ID_A: "${state.aliceId}" )`;
          tableRows = `
            <tr><td>Replayed Ticket</td><td><code>${oldTicketStr}</code></td><td>K_B (${state.keyB})</td><td>Compromised old ticket replayed by adversary Eve</td></tr>
            <tr><td>K_AB (Extracted)</td><td>${state.oldSessionKey}</td><td>K_B (${state.keyB})</td><td>Bob decrypts old key, believing Alice originated this session!</td></tr>
            <tr><td>ID_A</td><td>${state.aliceId}</td><td>K_B (${state.keyB})</td><td>Bob thinks he is communicating with Alice</td></tr>
          `;
          explain = `<strong>Vulnerability Breakdown (Denning-Sacco Attack):</strong> Because the ticket in Step 3 does NOT contain a timestamp or Bob's nonce, Bob cannot tell if this ticket was created just now or years ago! An attacker who stole an old key <code>K_AB_OLD</code> can trick Bob into accepting it.`;
        } else {
          title = `Step 3: Forward Ticket to Bob (${state.aliceId} → ${state.bobId})`;
          ciphertext = `FORWARDED TICKET: ENC_${state.keyB}( K_AB: "${state.sessionKey}", ID_A: "${state.aliceId}" )`;
          tableRows = `
            <tr><td>Ticket Payload</td><td><code>${ticketStr}</code></td><td>K_B (${state.keyB})</td><td>Encrypted ticket from KDC</td></tr>
            <tr><td>K_AB (Extracted)</td><td>${state.sessionKey}</td><td>K_B (${state.keyB})</td><td>Bob decrypts ticket using K_B to obtain session key</td></tr>
            <tr><td>ID_A</td><td>${state.aliceId}</td><td>K_B (${state.keyB})</td><td>Confirms identity of communication partner</td></tr>
          `;
          explain = `<strong>Security Purpose:</strong> Alice passes the Ticket to Bob. Bob uses his shared secret master key <code>K_B</code> with KDC to decrypt it and obtain <code>K_AB</code> without ever sharing <code>K_B</code> with Alice.`;
        }
        break;

      case 4:
        title = `Step 4: Bob Challenge (${state.bobId} → ${state.aliceId})`;
        ciphertext = `ENC_${state.replayMode ? state.oldSessionKey : state.sessionKey}( N_B: "${state.nonceB}" )`;
        tableRows = `
          <tr><td>N_B</td><td>${state.nonceB}</td><td>K_AB (${state.replayMode ? state.oldSessionKey : state.sessionKey})</td><td>Bob's fresh challenge nonce</td></tr>
        `;
        explain = `<strong>Security Purpose:</strong> Bob needs to verify that the person presenting the ticket actually knows <code>K_AB</code> (and is not just an eavesdropper forwarding a packet). He generates a fresh nonce <code>N_B</code>, encrypts it with <code>K_AB</code>, and sends it to Alice.`;
        break;

      case 5:
        const respNonce = decrementNonce(state.nonceB);
        if (state.replayMode) {
          title = `Step 5: Mutual Authentication Verification (FAILED)`;
          ciphertext = `CHALLENGE FAILED: ${state.aliceId} does not possess old key ${state.oldSessionKey}.`;
          tableRows = `
            <tr><td>Expected Response</td><td>${respNonce}</td><td>K_AB_OLD</td><td>Alice cannot decrypt Bob's challenge because she doesn't use the compromised key</td></tr>
            <tr><td>Status</td><td><span style="color:var(--warning-color);font-weight:bold;">Authentication Failed</span></td><td>-</td><td>Bob detects challenge timeout / mismatch</td></tr>
          `;
          explain = `<strong>Outcome:</strong> In Replay Mode, Bob sends <code>{N_B}_KAB_OLD</code>. Alice cannot decrypt it with current key <code>K_AB</code>, so she fails to send back <code>f(N_B)</code>. Bob's challenge detects the anomaly!`;
        } else {
          title = `Step 5: Nonce Response & Mutual Authentication (${state.aliceId} → ${state.bobId})`;
          ciphertext = `ENC_${state.sessionKey}( f(N_B): "${respNonce}" )`;
          tableRows = `
            <tr><td>f(N_B)</td><td>${respNonce}</td><td>K_AB (${state.sessionKey})</td><td>Transformed nonce (N_B - 1) proving possession of K_AB</td></tr>
            <tr><td>Mutual Auth</td><td><span style="color:var(--success-color);font-weight:bold;">SUCCESS</span></td><td>-</td><td>Both parties authenticated & share secure key</td></tr>
          `;
          explain = `<strong>Security Purpose:</strong> Alice decrypts <code>N_B</code>, performs function <code>f(N_B) = N_B - 1</code>, encrypts it with <code>K_AB</code>, and returns it. Bob verifies the result. Mutual authentication is successfully achieved!`;
        }
        break;
    }

    els.msgTitle.textContent = title;
    els.rawCiphertext.textContent = ciphertext;
    els.breakdownBody.innerHTML = tableRows;
    els.cryptoExplain.innerHTML = explain;
  }

  function toggleAutoPlay() {
    if (state.autoPlayInterval) {
      clearInterval(state.autoPlayInterval);
      state.autoPlayInterval = null;
      els.btnAuto.innerHTML = '▶ Auto Play';
      els.btnAuto.classList.remove('btn-secondary');
      els.btnAuto.classList.add('btn-outline');
    } else {
      if (state.step >= 5) resetSimulation();
      els.btnAuto.innerHTML = '⏸ Pause';
      els.btnAuto.classList.remove('btn-outline');
      els.btnAuto.classList.add('btn-secondary');
      nextStep();
      state.autoPlayInterval = setInterval(() => {
        if (state.step < 5) {
          nextStep();
        } else {
          toggleAutoPlay();
        }
      }, state.autoPlaySpeed);
    }
  }

  function resetSimulation() {
    if (state.autoPlayInterval) toggleAutoPlay();
    state.step = 0;
    els.packet.classList.remove('visible');
    els.packet.style.left = '16%';
    els.packet.style.top = '72%';
    updateUIState();
    logAudit('INFO', 'Simulation reset to initial state.');
  }

  function logAudit(type, message) {
    const time = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `<span class="log-time">[${time}]</span> <span class="log-tag ${type}">${type}</span> ${message}`;
    els.auditLog.prepend(entry);
  }

  // Quiz Engine
  function initQuiz() {
    const quizData = [
      {
        id: 1,
        question: "1. What is the primary purpose of Nonce N_A sent by Alice in Step 1 of the protocol?",
        options: [
          "To derive the master key K_A",
          "To ensure freshness and prevent replay of KDC responses to Alice",
          "To encrypt the session payload sent to Bob",
          "To authenticate Bob to the KDC"
        ],
        correct: 1,
        explanation: "Correct! N_A is a random nonce generated by Alice. When KDC returns N_A encrypted inside K_A in Step 2, Alice knows the message is fresh and was created specifically in response to her current request."
      },
      {
        id: 2,
        question: "2. Who is able to decrypt the Ticket payload {K_AB, A}_KB transmitted in Step 2 and Step 3?",
        options: [
          "Alice only",
          "Anyone eavesdropping on the network",
          "Bob only, using his pre-shared master key K_B",
          "Both Alice and Bob using key K_AB"
        ],
        correct: 2,
        explanation: "Correct! The Ticket is encrypted using K_B, which is a master key shared strictly between Bob and the KDC. Alice cannot decrypt it; she simply forwards it to Bob."
      },
      {
        id: 3,
        question: "3. Why does Bob send challenge {N_B}_KAB to Alice in Step 4?",
        options: [
          "To prove that he has received and decrypted the Ticket, and to challenge Alice to prove she knows K_AB",
          "To request a new master key from the KDC",
          "To encrypt Alice's user ID",
          "To destroy the symmetric key after usage"
        ],
        correct: 0,
        explanation: "Correct! Step 4 initiates the challenge-response phase. It checks if the entity forwarding the ticket actually possesses the session key K_AB."
      },
      {
        id: 4,
        question: "4. What major flaw was identified in the 1978 Needham-Schroeder symmetric protocol by Denning and Sacco (1981)?",
        options: [
          "K_AB is transmitted as plaintext over the network",
          "Step 3's ticket lacks a timestamp/nonce, enabling an attacker with an old compromised K_AB to replay the ticket to Bob",
          "Master key K_A is transmitted to Bob",
          "KDC cannot generate random session keys"
        ],
        correct: 1,
        explanation: "Correct! The Denning-Sacco vulnerability shows that if an old session key K_AB is compromised, an attacker can replay the old Ticket {K_AB, A}_KB to Bob, who cannot verify its freshness. Adding timestamps (like in Kerberos) fixes this."
      },
      {
        id: 5,
        question: "5. In Step 5, Alice responds with {f(N_B)}_KAB where f(N_B) = N_B - 1. What does modifying N_B achieve?",
        options: [
          "It completes mutual authentication by proving Alice decrypted Bob's challenge and active key knowledge",
          "It regenerates Bob's master key K_B",
          "It notifies KDC that the session is complete",
          "It encrypts the payload with K_A"
        ],
        correct: 0,
        explanation: "Correct! Modifying N_B (e.g. subtracting 1) prevents reflection attacks where an adversary simply echoes back the same ciphertext without decrypting it."
      }
    ];

    const quizContainer = document.getElementById('quizContainer');
    if (!quizContainer) return;

    quizContainer.innerHTML = '';
    quizData.forEach((q, qIndex) => {
      const qCard = document.createElement('div');
      qCard.className = 'question-item';

      let optionsHtml = '';
      q.options.forEach((opt, optIndex) => {
        optionsHtml += `
          <label class="option-label" id="opt-label-${q.id}-${optIndex}">
            <input type="radio" name="question-${q.id}" value="${optIndex}">
            <span>${opt}</span>
          </label>
        `;
      });

      qCard.innerHTML = `
        <div class="question-title">${q.question}</div>
        <div class="options-list">${optionsHtml}</div>
        <div class="explanation-box" id="explain-${q.id}"></div>
      `;
      quizContainer.appendChild(qCard);
    });

    els.quizSubmit.addEventListener('click', () => {
      let score = 0;
      quizData.forEach((q) => {
        const selected = document.querySelector(`input[name="question-${q.id}"]:checked`);
        const explainBox = document.getElementById(`explain-${q.id}`);

        // reset classes
        q.options.forEach((_, optIndex) => {
          const lbl = document.getElementById(`opt-label-${q.id}-${optIndex}`);
          lbl.classList.remove('correct', 'incorrect');
        });

        if (selected) {
          const val = parseInt(selected.value, 10);
          const selectedLbl = document.getElementById(`opt-label-${q.id}-${val}`);

          if (val === q.correct) {
            score++;
            selectedLbl.classList.add('correct');
            explainBox.className = 'explanation-box visible correct';
            explainBox.innerHTML = `<strong>Correct!</strong> ${q.explanation}`;
          } else {
            selectedLbl.classList.add('incorrect');
            const correctLbl = document.getElementById(`opt-label-${q.id}-${q.correct}`);
            correctLbl.classList.add('correct');
            explainBox.className = 'explanation-box visible incorrect';
            explainBox.innerHTML = `<strong>Incorrect.</strong> ${q.explanation}`;
          }
        } else {
          explainBox.className = 'explanation-box visible incorrect';
          explainBox.innerHTML = `<strong>Not answered.</strong> ${q.explanation}`;
        }
      });

      els.quizScoreBanner.style.display = 'flex';
      els.quizScoreBanner.innerHTML = `
        <div>
          <h3>Quiz Result: ${score} / ${quizData.length} (${(score/quizData.length * 100).toFixed(0)}%)</h3>
          <p>${score === 5 ? 'Mastery Achieved! Excellent understanding of symmetric key protocols.' : 'Review the Theory and Simulation tabs to reinforce your knowledge.'}</p>
        </div>
      `;
    });

    els.quizReset.addEventListener('click', () => {
      quizData.forEach((q) => {
        const selected = document.querySelector(`input[name="question-${q.id}"]:checked`);
        if (selected) selected.checked = false;
        q.options.forEach((_, optIndex) => {
          const lbl = document.getElementById(`opt-label-${q.id}-${optIndex}`);
          lbl.classList.remove('correct', 'incorrect');
        });
        const explainBox = document.getElementById(`explain-${q.id}`);
        explainBox.className = 'explanation-box';
        explainBox.innerHTML = '';
      });
      els.quizScoreBanner.style.display = 'none';
    });
  }

  // Feedback Form Handler
  function initFeedback() {
    let currentRating = 0;
    const stars = document.querySelectorAll('.rating-stars .star');
    stars.forEach(star => {
      star.addEventListener('click', () => {
        currentRating = parseInt(star.getAttribute('data-value'), 10);
        stars.forEach(s => {
          const val = parseInt(s.getAttribute('data-value'), 10);
          if (val <= currentRating) {
            s.classList.add('selected');
          } else {
            s.classList.remove('selected');
          }
        });
      });
    });

    els.feedbackForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const name = document.getElementById('fbName').value.trim();
      const comments = document.getElementById('fbComments').value.trim();
      const messageDiv = document.getElementById('feedbackStatus');

      if (currentRating === 0) {
        messageDiv.className = 'crypto-explain-box';
        messageDiv.style.borderColor = 'var(--warning-color)';
        messageDiv.innerHTML = '<strong>Note:</strong> Please select a star rating before submitting.';
        return;
      }

      messageDiv.className = 'crypto-explain-box';
      messageDiv.style.backgroundColor = 'var(--success-bg)';
      messageDiv.style.color = 'var(--success-color)';
      messageDiv.style.borderColor = 'var(--success-color)';
      messageDiv.innerHTML = `<strong>Thank You, ${name || 'Learner'}!</strong> Your feedback (Rating: ${currentRating}/5 stars) has been saved locally.`;

      // Reset form
      els.feedbackForm.reset();
      stars.forEach(s => s.classList.remove('selected'));
      currentRating = 0;
    });
  }
});
