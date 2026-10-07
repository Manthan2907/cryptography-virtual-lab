/**
 * Kerberos Authentication Protocol - Virtual Laboratory Experiment Logic
 * Handles interactive 6-step authentication protocol visualization,
 * dynamic key & ticket generation, packet animations, and 10-question deferred quiz logic.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Protocol State Object
  const state = {
    clientName: 'Alice',
    serviceName: 'Bob',
    nonce: 'N12345',
    sessionKeyInput: 'KEY-12345',
    currentStep: 1,

    // Dynamic Tokens (Generated on simulation initialize)
    tgt: '',
    kcTgs: '',
    authenticatorTgs: '',
    serviceTicket: '',
    kcV: '',
    authenticatorApp: '',
    asReqTimestamp: ''
  };

  // Helper function to generate random 4-character hex strings
  function randomHex() {
    return Math.floor((1 + Math.random()) * 0x10000)
      .toString(16)
      .substring(1)
      .toUpperCase();
  }

  // Generate fresh dynamic protocol tickets & keys
  function generateDynamicTokens() {
    const cleanClient = state.clientName.trim().toUpperCase() || 'ALICE';
    const cleanService = state.serviceName.trim().toUpperCase() || 'BOB';

    state.tgt = `TGT-${cleanClient}-${randomHex()}`;
    state.kcTgs = `Kc,tgs-${randomHex()}`;
    state.authenticatorTgs = `AUTH-${cleanClient}-${randomHex()}`;
    state.serviceTicket = `ST-${cleanClient}-${cleanService}-${randomHex()}`;
    state.kcV = `Kc,v-${randomHex()}`;
    state.authenticatorApp = `AUTH-${cleanClient}-${randomHex()}`;
  }

  // Node Positions (Percentage relative to flow-path line)
  // Alice = 0%, AS = 33.3%, TGS = 66.6%, Bob = 100%
  const nodePercentages = [5, 35, 65, 95];
  const actorIds = ['actor-client', 'actor-as', 'actor-tgs', 'actor-service'];

  // Packet Transmission Animation Engine using Web Animations API
  function animatePacket(fromIdx, toIdx, label, callback) {
    const packet = document.getElementById('packet-badge');
    const flowText = document.getElementById('flow-status-text');

    if (!packet) {
      if (callback) callback();
      return;
    }

    const startPct = nodePercentages[fromIdx];
    const endPct = nodePercentages[toIdx];

    // Highlight active sender actor card
    const senderCard = document.getElementById(actorIds[fromIdx]);
    const receiverCard = document.getElementById(actorIds[toIdx]);

    if (senderCard) senderCard.classList.add('active-sender');
    if (receiverCard) receiverCard.classList.add('active-receiver');

    packet.textContent = label;
    packet.style.display = 'block';

    flowText.textContent = `Transmitting ${label}...`;

    const animation = packet.animate(
      [
        { left: `${startPct}%`, opacity: 0.2, transform: 'translate(-50%, -50%) scale(0.8)' },
        { left: `${startPct}%`, opacity: 1, transform: 'translate(-50%, -50%) scale(1)' },
        { left: `${endPct}%`, opacity: 1, transform: 'translate(-50%, -50%) scale(1)' }
      ],
      {
        duration: 750,
        easing: 'cubic-bezier(0.4, 0.0, 0.2, 1)',
        fill: 'forwards'
      }
    );

    animation.onfinish = () => {
      packet.style.display = 'none';
      if (senderCard) senderCard.classList.remove('active-sender');
      if (receiverCard) receiverCard.classList.remove('active-receiver');
      flowText.textContent = `${label} received successfully.`;
      if (callback) callback();
    };
  }

  // Update Stepper Navigation UI
  function updateStepper(activeStep) {
    const items = document.querySelectorAll('.stepper-item[data-step-nav]');
    items.forEach((item) => {
      const stepNum = parseInt(item.dataset.stepNav, 10);
      item.classList.remove('active', 'completed');
      if (stepNum === activeStep) {
        item.classList.add('active');
      } else if (stepNum < activeStep) {
        item.classList.add('completed');
      }
    });
  }

  // Show Active Step Card
  function showStepCard(stepNum) {
    state.currentStep = stepNum;
    updateStepper(stepNum);

    const cards = document.querySelectorAll('.step-card');
    cards.forEach((card) => {
      card.classList.remove('active');
    });

    const targetCard = document.getElementById(`step-card-${stepNum}`);
    if (targetCard) {
      targetCard.classList.add('active');
    }
  }

  // Update Dynamic UI Labels Across All Steps
  function updateDynamicFields() {
    const cName = state.clientName;
    const sName = state.serviceName;

    // Actor cards & stage labels
    document.getElementById('actor-client-name').textContent = cName;
    document.getElementById('actor-service-name').textContent = sName;
    document.getElementById('stage-client-label').textContent = cName;
    document.getElementById('stage-service-label').textContent = sName;

    // Step 2 Payload
    document.getElementById('asreq-client').textContent = cName;
    document.getElementById('asreq-nonce').textContent = state.nonce;

    // Step 3 TGT Output
    document.getElementById('val-tgt-id').textContent = state.tgt;
    document.getElementById('val-tgt-client').textContent = cName;
    document.getElementById('val-tgt-key').textContent = state.kcTgs;

    // Step 4 TGS-REQ Payload
    document.getElementById('tgsreq-client').textContent = cName;
    document.getElementById('tgsreq-service').textContent = sName;
    document.getElementById('tgsreq-tgt').textContent = state.tgt;
    document.getElementById('tgsreq-auth').textContent = state.authenticatorTgs;
    document.getElementById('tgsreq-nonce').textContent = state.nonce;

    // Step 5 ST Output
    document.getElementById('val-st-id').textContent = state.serviceTicket;
    document.getElementById('val-st-service').textContent = sName;
    document.getElementById('val-st-key').textContent = state.kcV;

    // Step 6 AP-REQ Payload
    document.getElementById('apreq-service').textContent = sName;
    document.getElementById('apreq-st').textContent = state.serviceTicket;
    document.getElementById('apreq-auth').textContent = state.authenticatorApp;
    document.getElementById('verify-nonce').textContent = state.nonce;

    // Step 7 Summary
    document.getElementById('final-client-name').textContent = cName;
    document.getElementById('final-service-name').textContent = sName;
  }

  // ==================== STEP 1: INITIALIZE ====================
  const btnStep1 = document.getElementById('btn-step1');
  if (btnStep1) {
    btnStep1.addEventListener('click', () => {
      const cVal = document.getElementById('input-client').value.trim();
      const sVal = document.getElementById('input-service').value.trim();
      const nVal = document.getElementById('input-nonce').value.trim();
      const kVal = document.getElementById('input-session').value.trim();
      const errBox = document.getElementById('step1-error');

      if (!cVal) {
        errBox.textContent = 'Please enter a client identity.';
        errBox.style.display = 'inline-flex';
        return;
      }
      if (!sVal) {
        errBox.textContent = 'Please enter a server identity.';
        errBox.style.display = 'inline-flex';
        return;
      }
      if (!nVal) {
        errBox.textContent = 'Please enter a nonce.';
        errBox.style.display = 'inline-flex';
        return;
      }
      if (!kVal) {
        errBox.textContent = 'Please enter a session-key placeholder.';
        errBox.style.display = 'inline-flex';
        return;
      }

      errBox.style.display = 'none';

      // Update state
      state.clientName = cVal;
      state.serviceName = sVal;
      state.nonce = nVal;
      state.sessionKeyInput = kVal;

      generateDynamicTokens();
      updateDynamicFields();

      document.getElementById('step1-status').style.display = 'inline-flex';
      document.getElementById('btn-step2').disabled = false;

      // Move to Step 2
      setTimeout(() => {
        showStepCard(2);
      }, 400);
    });
  }

  // ==================== STEP 2: AS-REQ ====================
  const btnStep2 = document.getElementById('btn-step2');
  if (btnStep2) {
    btnStep2.addEventListener('click', () => {
      btnStep2.disabled = true;
      state.asReqTimestamp = new Date().toLocaleTimeString();
      document.getElementById('asreq-time').textContent = state.asReqTimestamp;

      // Animate Alice (0) -> AS (1)
      animatePacket(0, 1, 'AS-REQ', () => {
        document.getElementById('step2-status').style.display = 'inline-flex';
        document.getElementById('btn-step3').disabled = false;

        setTimeout(() => {
          showStepCard(3);
        }, 500);
      });
    });
  }

  // ==================== STEP 3: AS-REP ====================
  const btnStep3 = document.getElementById('btn-step3');
  if (btnStep3) {
    btnStep3.addEventListener('click', () => {
      btnStep3.disabled = true;

      // Animate AS (1) -> Alice (0)
      animatePacket(1, 0, 'AS-REP (TGT)', () => {
        document.getElementById('tgt-display-box').style.display = 'block';
        document.getElementById('step3-status').style.display = 'inline-flex';
        document.getElementById('btn-step4').disabled = false;

        setTimeout(() => {
          showStepCard(4);
        }, 600);
      });
    });
  }

  // ==================== STEP 4: TGS-REQ ====================
  const btnStep4 = document.getElementById('btn-step4');
  if (btnStep4) {
    btnStep4.addEventListener('click', () => {
      btnStep4.disabled = true;

      // Animate Alice (0) -> TGS (2)
      animatePacket(0, 2, 'TGS-REQ', () => {
        document.getElementById('step4-status').style.display = 'inline-flex';
        document.getElementById('btn-step5').disabled = false;

        setTimeout(() => {
          showStepCard(5);
        }, 500);
      });
    });
  }

  // ==================== STEP 5: TGS-REP ====================
  const btnStep5 = document.getElementById('btn-step5');
  if (btnStep5) {
    btnStep5.addEventListener('click', () => {
      btnStep5.disabled = true;

      // Animate TGS (2) -> Alice (0)
      animatePacket(2, 0, 'TGS-REP (ST)', () => {
        document.getElementById('st-display-box').style.display = 'block';
        document.getElementById('step5-status').style.display = 'inline-flex';
        document.getElementById('btn-step6').disabled = false;

        setTimeout(() => {
          showStepCard(6);
        }, 600);
      });
    });
  }

  // ==================== STEP 6: AP-REQ ====================
  const btnStep6 = document.getElementById('btn-step6');
  if (btnStep6) {
    btnStep6.addEventListener('click', () => {
      btnStep6.disabled = true;

      // Animate Alice (0) -> Bob (3)
      animatePacket(0, 3, 'AP-REQ', () => {
        document.getElementById('bob-check-sequence').style.display = 'block';
        document.getElementById('step6-status').style.display = 'inline-flex';

        setTimeout(() => {
          showStepCard(7);
        }, 1200);
      });
    });
  }

  // ==================== STEP 7: RESET SIMULATION ====================
  const btnReset = document.getElementById('btn-reset');
  if (btnReset) {
    btnReset.addEventListener('click', () => {
      // Hide status pills & generated ticket boxes
      const statusPills = document.querySelectorAll('#simulation .status-pill');
      statusPills.forEach((pill) => (pill.style.display = 'none'));

      document.getElementById('tgt-display-box').style.display = 'none';
      document.getElementById('st-display-box').style.display = 'none';
      document.getElementById('bob-check-sequence').style.display = 'none';

      // Reset step buttons
      document.getElementById('btn-step2').disabled = true;
      document.getElementById('btn-step3').disabled = true;
      document.getElementById('btn-step4').disabled = true;
      document.getElementById('btn-step5').disabled = true;
      document.getElementById('btn-step6').disabled = true;

      document.getElementById('asreq-time').textContent = 'Pending send...';
      document.getElementById('flow-status-text').textContent = 'Simulation reset. Click Initialize to start a new authentication run.';

      // Go back to Step 1
      showStepCard(1);
    });
  }

  // ==================== 10-QUESTION QUIZ LOGIC ====================
  const quizAnswers = {
    q1: 'B',
    q2: 'B',
    q3: 'C',
    q4: 'B',
    q5: 'B',
    q6: 'B',
    q7: 'B',
    q8: 'B',
    q9: 'B',
    q10: 'A'
  };

  const quizExplanations = {
    q1: 'The Authentication Server (AS) verifies initial user credentials and issues the Ticket Granting Ticket (TGT).',
    q2: 'The TGT allows clients to request multiple service tickets without re-entering passwords.',
    q3: 'The Ticket Granting Server (TGS) validates the TGT and issues specific Service Tickets.',
    q4: 'The Authenticator contains a timestamp encrypted with the session key to prove request freshness and owner identity.',
    q5: 'Nonces link requests with responses to ensure freshness and defeat replay attacks.',
    q6: 'The target Server Identity decrypts the Service Ticket using its secret key and verifies the accompanying Authenticator.',
    q7: 'The Key Distribution Center (KDC) consists of the Authentication Server (AS) and Ticket Granting Server (TGS).',
    q8: 'Shared secret keys ensure confidentiality and authenticity of tickets exchanged across untrusted networks.',
    q9: 'Authenticators include short-lived timestamps; stale or duplicate timestamps are rejected to prevent replay attacks.',
    q10: 'Mutual authentication allows the client to verify the server identity and vice versa using shared secret session keys.'
  };

  // Selection visual feedback on radios
  for (let i = 1; i <= 10; i++) {
    const card = document.getElementById(`quiz-card-${i}`);
    if (!card) continue;

    const radios = card.querySelectorAll(`input[name="q${i}"]`);
    radios.forEach((radio) => {
      radio.addEventListener('change', () => {
        // Clear unattempted styling when user answers
        card.classList.remove('unattempted-card');
        const badge = document.getElementById(`unattempted-badge-${i}`);
        if (badge) badge.style.display = 'none';

        const options = card.querySelectorAll('.quiz-option');
        options.forEach((opt) => opt.classList.remove('selected-option'));
        const parentLabel = radio.closest('.quiz-option');
        if (parentLabel) parentLabel.classList.add('selected-option');
      });
    });
  }

  // SUBMIT QUIZ BUTTON WITH MANDATORY ALL-QUESTION VALIDATION
  const btnSubmitQuiz = document.getElementById('btn-submit-quiz');
  if (btnSubmitQuiz) {
    btnSubmitQuiz.addEventListener('click', () => {
      const unattemptedIndices = [];

      // Check which questions are missing an answer
      for (let i = 1; i <= 10; i++) {
        const selectedRadio = document.querySelector(`input[name="q${i}"]:checked`);
        const card = document.getElementById(`quiz-card-${i}`);
        const badge = document.getElementById(`unattempted-badge-${i}`);

        if (!selectedRadio) {
          unattemptedIndices.push(i);
          if (card) card.classList.add('unattempted-card');
          if (badge) badge.style.display = 'inline-block';
        } else {
          if (card) card.classList.remove('unattempted-card');
          if (badge) badge.style.display = 'none';
        }
      }

      // IF ANY QUESTION IS UNATTEMPTED: ALERT AND BLOCK SUBMISSION
      if (unattemptedIndices.length > 0) {
        const firstUnattempted = document.getElementById(`quiz-card-${unattemptedIndices[0]}`);
        if (firstUnattempted) {
          firstUnattempted.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
        alert(`Please attempt all questions before submitting the quiz! (${unattemptedIndices.length} question(s) remaining: Q${unattemptedIndices.join(', Q')})`);
        return; // STOP! DO NOT SUBMIT OR SHOW SCORES YET!
      }

      // ALL 10 QUESTIONS ATTEMPTED: PROCESS SUBMISSION & DISPLAY SCORE
      let score = 0;
      for (let i = 1; i <= 10; i++) {
        const card = document.getElementById(`quiz-card-${i}`);
        const selectedRadio = document.querySelector(`input[name="q${i}"]:checked`);
        const feedback = document.getElementById(`q${i}-feedback`);
        const options = card.querySelectorAll('.quiz-option');

        options.forEach((opt) => opt.classList.remove('correct', 'incorrect'));

        const correctAnswer = quizAnswers[`q${i}`];
        const userVal = selectedRadio.value;
        const userOptionLabel = selectedRadio.closest('.quiz-option');

        if (userVal === correctAnswer) {
          score++;
          userOptionLabel.classList.add('correct');
          feedback.textContent = `Correct! ${quizExplanations[`q${i}`]}`;
          feedback.style.color = '#4caf50';
        } else {
          userOptionLabel.classList.add('incorrect');
          options.forEach((opt) => {
            const input = opt.querySelector('input');
            if (input && input.value === correctAnswer) {
              opt.classList.add('correct');
            }
          });
          feedback.textContent = `Incorrect (Selected ${userVal}). Correct Answer: (${correctAnswer}). ${quizExplanations[`q${i}`]}`;
          feedback.style.color = '#f44336';
        }
        feedback.classList.add('show');
      }

      // Display Score Banner (No Emojis)
      const scoreBanner = document.getElementById('quiz-score-banner');
      const scoreTitle = document.getElementById('quiz-score-title');
      const scoreSubtitle = document.getElementById('quiz-score-subtitle');
      const scoreStatus = document.getElementById('quiz-score-status');

      const percentage = Math.round((score / 10) * 100);

      scoreTitle.textContent = `Your Quiz Score: ${score} / 10 (${percentage}%)`;
      scoreSubtitle.textContent = `Attempted: 10 / 10 | Correct: ${score} | Incorrect: ${10 - score}`;
      scoreStatus.className = 'status-pill';
      scoreStatus.textContent = `Quiz completed! All 10 questions attempted.`;

      scoreBanner.style.display = 'block';
      scoreBanner.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  }

  // RETAKE / RESET QUIZ BUTTON
  const btnResetQuiz = document.getElementById('btn-reset-quiz');
  if (btnResetQuiz) {
    btnResetQuiz.addEventListener('click', () => {
      for (let i = 1; i <= 10; i++) {
        const card = document.getElementById(`quiz-card-${i}`);
        if (!card) continue;

        card.classList.remove('unattempted-card');
        const badge = document.getElementById(`unattempted-badge-${i}`);
        if (badge) badge.style.display = 'none';

        const radios = card.querySelectorAll(`input[name="q${i}"]`);
        radios.forEach((r) => (r.checked = false));

        const options = card.querySelectorAll('.quiz-option');
        options.forEach((opt) => opt.classList.remove('correct', 'incorrect', 'selected-option'));

        const feedback = document.getElementById(`q${i}-feedback`);
        if (feedback) {
          feedback.classList.remove('show');
          feedback.textContent = '';
        }
      }

      const scoreBanner = document.getElementById('quiz-score-banner');
      if (scoreBanner) scoreBanner.style.display = 'none';

      window.scrollTo({ top: document.getElementById('quiz').offsetTop - 60, behavior: 'smooth' });
    });
  }
});
