/**
 * RSA as a Digital Signature — Virtual Lab Module
 * Fr. Conceicao Rodrigues College of Engineering
 * Group: RSA (Arnav Potale, Joel Wilson, Omkar Patil, Rahul Senapati)
 */

(() => {
  'use strict';

  // Small primes for random generation
  const SMALL_PRIMES = [
    7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n
  ];

  // ==========================================
  // MATHEMATICAL FUNCTIONS (BigInt)
  // ==========================================

  /**
   * Primality test with factor reporting
   */
  function isPrime(num) {
    if (num <= 1n) return { prime: false, factor: 0n };
    if (num <= 3n) return { prime: true };
    if (num % 2n === 0n) return { prime: false, factor: 2n };
    if (num % 3n === 0n) return { prime: false, factor: 3n };

    let i = 5n;
    while (i * i <= num) {
      if (num % i === 0n) return { prime: false, factor: i };
      if (num % (i + 2n) === 0n) return { prime: false, factor: i + 2n };
      i += 6n;
    }
    return { prime: true };
  }

  /**
   * Euclidean Greatest Common Divisor
   */
  function gcd(a, b) {
    let x = a < 0n ? -a : a;
    let y = b < 0n ? -b : b;
    while (y !== 0n) {
      const t = y;
      y = x % y;
      x = t;
    }
    return x;
  }

  /**
   * Extended Euclidean Algorithm
   */
  function extendedEuclidean(a, b) {
    let old_r = a, r = b;
    let old_s = 1n, s = 0n;
    let old_t = 0n, t = 1n;

    while (r !== 0n) {
      const q = old_r / r;
      let temp = old_r - q * r;
      old_r = r;
      r = temp;

      temp = old_s - q * s;
      old_s = s;
      s = temp;

      temp = old_t - q * t;
      old_t = t;
      t = temp;
    }
    return { gcd: old_r, x: old_s, y: old_t };
  }

  /**
   * Modular multiplicative inverse: d = e^-1 mod phi
   */
  function modInverse(e, phi) {
    const ext = extendedEuclidean(e, phi);
    if (ext.gcd !== 1n) return null;
    let d = ext.x % phi;
    if (d < 0n) d += phi;
    return d;
  }

  /**
   * Modular exponentiation: (base^exp) mod modulus
   */
  function modPow(base, exp, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    let b = base % modulus;
    let e = exp;
    while (e > 0n) {
      if (e % 2n === 1n) {
        result = (result * b) % modulus;
      }
      e = e / 2n;
      b = (b * b) % modulus;
    }
    return result;
  }

  /**
   * Computes actual cryptographic hash using CryptoJS (MD5 or SHA-1)
   */
  function computeHash(algo, messageStr) {
    if (typeof CryptoJS !== 'undefined') {
      if (algo === 'MD5') {
        return CryptoJS.MD5(messageStr).toString();
      } else {
        return CryptoJS.SHA1(messageStr).toString();
      }
    }
    // Deterministic fallback for isolated execution environments
    let hash = 0;
    for (let i = 0; i < messageStr.length; i++) {
      hash = ((hash << 5) - hash) + messageStr.charCodeAt(i);
      hash |= 0;
    }
    const hex = Math.abs(hash).toString(16).padStart(8, '0');
    return algo === 'MD5' ? hex.repeat(4) : hex.repeat(5);
  }

  /**
   * Returns human-readable bit length description
   */
  function getHashLengthDescription(algo) {
    if (algo === 'MD5') {
      return 'MD5 → 128 bits / 32 hexadecimal characters';
    }
    return 'SHA-1 → 160 bits / 40 hexadecimal characters';
  }

  /**
   * Generates step-by-step division and back-substitution trace for Extended Euclidean Algorithm
   */
  function getExtendedEuclideanTrace(e, phi) {
    let r0 = phi, r1 = e;
    const divs = [];
    while (r1 !== 0n) {
      const q = r0 / r1;
      const rem = r0 % r1;
      if (rem !== 0n) {
        divs.push({ a: r0, q: q, b: r1, rem: rem });
      }
      r0 = r1;
      r1 = rem;
    }

    const gcdVal = r0;
    if (gcdVal !== 1n) {
      return {
        valid: false,
        gcd: gcdVal,
        divEqs: divs.map(d => `${d.a} = ${d.q} × ${d.b} + ${d.rem}`)
      };
    }

    const divEqs = divs.map(d => `${d.a} = ${d.q} × ${d.b} + ${d.rem}`);
    const subSteps = [];

    if (divs.length === 0) {
      return {
        valid: true,
        gcd: 1n,
        divEqs: ['e = 1 (Trivial inverse d = 1)'],
        subSteps: ['d = 1'],
        d: 1n,
        verifyEquation: '1 × 1 ≡ 1 (mod φ(n))'
      };
    }

    let currTerms = [{ coeff: 1n, val: divs[divs.length - 1].rem }];
    subSteps.push(`1 = ${divs[divs.length - 1].a} - ${divs[divs.length - 1].q} × ${divs[divs.length - 1].b}`);

    for (let i = divs.length - 2; i >= 0; i--) {
      const step = divs[i];
      const nextTerms = [];
      currTerms.forEach(t => {
        if (t.val === step.rem) {
          nextTerms.push({ coeff: t.coeff, val: step.a });
          nextTerms.push({ coeff: -t.coeff * step.q, val: step.b });
        } else {
          nextTerms.push(t);
        }
      });

      const combined = {};
      nextTerms.forEach(t => {
        const key = t.val.toString();
        combined[key] = (combined[key] || 0n) + t.coeff;
      });

      currTerms = Object.keys(combined)
        .filter(k => combined[k] !== 0n)
        .map(k => ({ coeff: combined[k], val: BigInt(k) }));

      const termStrs = currTerms.map(t => {
        if (t.coeff === 1n) return `${t.val}`;
        if (t.coeff === -1n) return `- ${t.val}`;
        if (t.coeff < 0n) return `- ${-t.coeff} × ${t.val}`;
        return `${t.coeff} × ${t.val}`;
      });

      if (termStrs.length > 0) {
        subSteps.push(`1 = ${termStrs.join(' + ').replace(/\+ - /g, '- ').replace(/\+ -/g, '- ')}`);
      }
    }

    const eTerm = currTerms.find(t => t.val === e);
    let derivedD = eTerm ? eTerm.coeff : 0n;
    derivedD = ((derivedD % phi) + phi) % phi;

    const verifyEq = `${e} × ${derivedD} = ${e * derivedD} → ${e * derivedD} mod ${phi} = ${(e * derivedD) % phi}. Therefore d = ${derivedD} is correct.`;

    return {
      valid: true,
      gcd: 1n,
      divEqs: divEqs,
      subSteps: subSteps,
      d: derivedD,
      verifyEquation: verifyEq
    };
  }

  /**
   * Generates step-by-step modular repeated squaring power trace
   */
  function getRepeatedSquaringTrace(base, exp, mod) {
    const binaryStr = exp.toString(2);
    const powers = [];
    let currentPowerVal = base % mod;
    let currentExpPower = 1n;
    let accumulated = 1n;
    const multSteps = [];

    for (let i = binaryStr.length - 1; i >= 0; i--) {
      const bit = binaryStr[i];
      const isIncluded = (bit === '1');

      powers.push({
        expPower: currentExpPower,
        bit: bit,
        val: currentPowerVal,
        included: isIncluded
      });

      if (isIncluded) {
        const prevAccum = accumulated;
        accumulated = (accumulated * currentPowerVal) % mod;
        multSteps.push(`Accumulated × (${base}^${currentExpPower} mod ${mod}): (${prevAccum} × ${currentPowerVal}) mod ${mod} = ${accumulated}`);
      }

      currentPowerVal = (currentPowerVal * currentPowerVal) % mod;
      currentExpPower = currentExpPower * 2n;
    }

    const bitPowers = [];
    let pwr = 1n;
    for (let i = binaryStr.length - 1; i >= 0; i--) {
      if (binaryStr[i] === '1') bitPowers.push(pwr.toString());
      pwr *= 2n;
    }
    const sumPowers = bitPowers.reverse().join(' + ');

    return {
      binary: binaryStr,
      sumPowers: sumPowers || '0',
      powers: powers,
      multSteps: multSteps,
      finalResult: accumulated
    };
  }

  // ==========================================
  // STATE MANAGEMENT
  // ==========================================
  const state = {
    // Stage 1 & 2
    p: 7n,
    q: 23n,
    n: 161n,
    phi: 132n,
    e: 5n,
    d: 53n,
    keysValid: true,

    // Stage 3
    message: 23n,
    selectedHash: 'SHA-1', // 'MD5' or 'SHA-1'
    hashDigest: '',
    signature: 46n,
    signatureHashAlgorithm: 'SHA-1',
    signatureDigest: '',
    signatureValid: true,
    signed: true,

    // Stage 4 (Verification)
    verifHashAlgo: 'SHA-1',
    receivedMsg: 23n,
    receivedSig: 46n,
    recoveredMsg: 23n,
    verifCalcDigest: '',
    verifRecDigest: '',
    verdict: 'VALID',

    // Stage 5 (Interception / Tampering)
    isIntercepted: false,
    tamperedMsg: 24n,
    interceptionTested: false
  };

  // ==========================================
  // DOM REFERENCES
  // ==========================================
  let dom = {};

  function cacheDom() {
    dom = {
      // Stage 1: Primes
      inputP: document.getElementById('inputP'),
      inputQ: document.getElementById('inputQ'),
      btnUseExample: document.getElementById('btnUseExample'),
      btnUseExample17: document.getElementById('btnUseExample17'),
      btnRandomPrimes: document.getElementById('btnRandomPrimes'),
      primeGenStatus: document.getElementById('primeGenStatus'),
      primeAlert: document.getElementById('primeAlert'),
      primeStatusP: document.getElementById('primeStatusP'),
      primeStatusQ: document.getElementById('primeStatusQ'),

      // Stage 2: Keys
      inputE: document.getElementById('inputE'),
      btnSuggestE: document.getElementById('btnSuggestE'),
      btnGenerateKeys: document.getElementById('btnGenerateKeys'),
      keyAlert: document.getElementById('keyAlert'),
      pipeN: document.getElementById('pipeN'),
      pipePhi: document.getElementById('pipePhi'),
      pipeE: document.getElementById('pipeE'),
      pipeD: document.getElementById('pipeD'),
      pipeStatus: document.getElementById('pipeStatus'),
      cardPubKey: document.getElementById('cardPubKey'),
      cardPrivKey: document.getElementById('cardPrivKey'),
      badgePublicKey: document.getElementById('badgePublicKey'),
      badgePrivateKey: document.getElementById('badgePrivateKey'),

      // Stage 2 Math Working Panel
      btnToggleKeyMath: document.getElementById('btnToggleKeyMath'),
      keyMathWorkingPanel: document.getElementById('keyMathWorkingPanel'),
      mathKeyStep1Subst: document.getElementById('mathKeyStep1Subst'),
      mathKeyStep1Result: document.getElementById('mathKeyStep1Result'),
      mathKeyStep2Subst: document.getElementById('mathKeyStep2Subst'),
      mathKeyStep2Result: document.getElementById('mathKeyStep2Result'),
      mathKeyStep3E: document.getElementById('mathKeyStep3E'),
      mathKeyStep3Gcd: document.getElementById('mathKeyStep3Gcd'),
      mathKeyStep3Status: document.getElementById('mathKeyStep3Status'),
      mathKeyStep4Div: document.getElementById('mathKeyStep4Div'),
      mathKeyStep4BackSub: document.getElementById('mathKeyStep4BackSub'),
      mathKeyStep4Result: document.getElementById('mathKeyStep4Result'),
      mathKeyStep4Verify: document.getElementById('mathKeyStep4Verify'),
      mathKeyPubDisplay: document.getElementById('mathKeyPubDisplay'),
      mathKeyPrivDisplay: document.getElementById('mathKeyPrivDisplay'),

      // Stage 3: Signing & Hashing
      inputMsg: document.getElementById('inputMsg'),
      msgRangeNote: document.getElementById('msgRangeNote'),
      cardHashMd5: document.getElementById('cardHashMd5'),
      cardHashSha1: document.getElementById('cardHashSha1'),
      radioSignMd5: document.getElementById('radioSignMd5'),
      radioSignSha1: document.getElementById('radioSignSha1'),
      btnGenHash: document.getElementById('btnGenHash'),
      btnSign: document.getElementById('btnSign'),
      signAlert: document.getElementById('signAlert'),
      signSelectedHashText: document.getElementById('signSelectedHashText'),
      signDigestLengthBadge: document.getElementById('signDigestLengthBadge'),
      signDigestDisplay: document.getElementById('signDigestDisplay'),
      signMathFormula: document.getElementById('signMathFormula'),
      signMathSubst: document.getElementById('signMathSubst'),
      signMathResult: document.getElementById('signMathResult'),

      // Stage 3 Repeated Squaring Math
      btnToggleSignPowMath: document.getElementById('btnToggleSignPowMath'),
      signPowMathPanel: document.getElementById('signPowMathPanel'),
      signPowHeading: document.getElementById('signPowHeading'),
      signPowBinary: document.getElementById('signPowBinary'),
      signPowTableBody: document.getElementById('signPowTableBody'),
      signPowAccumSteps: document.getElementById('signPowAccumSteps'),
      signPowFinalResult: document.getElementById('signPowFinalResult'),

      // Stage 4: Verification
      verifAlert: document.getElementById('verifAlert'),
      verifStep1Msg: document.getElementById('verifStep1Msg'),
      cardVerifMd5: document.getElementById('cardVerifMd5'),
      cardVerifSha1: document.getElementById('cardVerifSha1'),
      radioVerifMd5: document.getElementById('radioVerifMd5'),
      radioVerifSha1: document.getElementById('radioVerifSha1'),
      hashMismatchWarning: document.getElementById('hashMismatchWarning'),
      verifAlgoLabelStep3: document.getElementById('verifAlgoLabelStep3'),
      verifCalcDigest: document.getElementById('verifCalcDigest'),
      verifRecoveredDigest: document.getElementById('verifRecoveredDigest'),
      digestCompareBox: document.getElementById('digestCompareBox'),
      btnVerifyOriginal: document.getElementById('btnVerifyOriginal'),
      verifMathFormula: document.getElementById('verifMathFormula'),
      verifMathSubst: document.getElementById('verifMathSubst'),
      verifMathRecovered: document.getElementById('verifMathRecovered'),
      verdictBox: document.getElementById('verdictBox'),
      verdictTitle: document.getElementById('verdictTitle'),
      verdictText: document.getElementById('verdictText'),

      // Stage 4 Math Working (Repeated Squaring)
      btnToggleVerifyPowMath: document.getElementById('btnToggleVerifyPowMath'),
      verifyPowMathPanel: document.getElementById('verifyPowMathPanel'),
      verifyPowHeading: document.getElementById('verifyPowHeading'),
      verifyPowBinary: document.getElementById('verifyPowBinary'),
      verifyPowTableBody: document.getElementById('verifyPowTableBody'),
      verifyPowAccumSteps: document.getElementById('verifyPowAccumSteps'),
      verifyPowFinalResult: document.getElementById('verifyPowFinalResult'),

      // Stage 5: Interception & Tampering
      btnInterceptMessage: document.getElementById('btnInterceptMessage'),
      btnVerifyTampered: document.getElementById('btnVerifyTampered'),
      btnRestoreOriginal: document.getElementById('btnRestoreOriginal'),
      transitMsgDisplay: document.getElementById('transitMsgDisplay'),
      transitSigDisplay: document.getElementById('transitSigDisplay'),
      transitStatusPill: document.getElementById('transitStatusPill'),
      tamperMathCard: document.getElementById('tamperMathCard'),
      tamperMathOrigM: document.getElementById('tamperMathOrigM'),
      tamperMathOrigS: document.getElementById('tamperMathOrigS'),
      tamperMathOrigVerif: document.getElementById('tamperMathOrigVerif'),
      tamperMathFromM: document.getElementById('tamperMathFromM'),
      tamperMathToM: document.getElementById('tamperMathToM'),
      tamperMathSigKept: document.getElementById('tamperMathSigKept'),
      tamperMathRecCalc: document.getElementById('tamperMathRecCalc'),
      tamperMathRecReceived: document.getElementById('tamperMathRecReceived'),
      tamperMathRecRecovered: document.getElementById('tamperMathRecRecovered'),
      tamperShaOrigM: document.getElementById('tamperShaOrigM'),
      tamperShaDigestOrig: document.getElementById('tamperShaDigestOrig'),
      tamperShaModM: document.getElementById('tamperShaModM'),
      tamperShaDigestMod: document.getElementById('tamperShaDigestMod'),

      // Master Mathematical Working Section
      masterMathCard: document.getElementById('masterMathCard'),
      btnToggleMasterMath: document.getElementById('btnToggleMasterMath'),
      masterMathWorkingContent: document.getElementById('masterMathWorkingContent'),

      // Diagram nodes
      diagramSender: document.getElementById('diagSender'),
      diagramSenderContent: document.getElementById('diagSenderContent'),
      diagramSignature: document.getElementById('diagSignature'),
      diagramSignatureContent: document.getElementById('diagSignatureContent'),
      diagramInterceptor: document.getElementById('diagInterceptor'),
      diagramReceiver: document.getElementById('diagReceiver'),
      diagramReceiverContent: document.getElementById('diagReceiverContent'),
      diagramVerify: document.getElementById('diagVerify'),
      diagramVerifyContent: document.getElementById('diagVerifyContent'),
      diagramResult: document.getElementById('diagResult'),
      diagramResultContent: document.getElementById('diagResultContent'),

      // Observations
      obsP: document.getElementById('obsP'),
      obsQ: document.getElementById('obsQ'),
      obsE: document.getElementById('obsE'),
      obsMsg: document.getElementById('obsMsg'),
      obsN: document.getElementById('obsN'),
      obsPhi: document.getElementById('obsPhi'),
      obsD: document.getElementById('obsD'),
      obsSignHashAlgo: document.getElementById('obsSignHashAlgo'),
      obsSignDigest: document.getElementById('obsSignDigest'),
      obsSig: document.getElementById('obsSig'),
      obsVerifHashAlgo: document.getElementById('obsVerifHashAlgo'),
      obsVerifCalcDigest: document.getElementById('obsVerifCalcDigest'),
      obsVerifRecDigest: document.getElementById('obsVerifRecDigest'),
      obsVerifStatus: document.getElementById('obsVerifStatus'),
      btnResetSim: document.getElementById('btnResetSim'),
      btnResetSimTab: document.getElementById('btnResetSimTab'),

      // Observations Math Summary
      obsMathP: document.getElementById('obsMathP'),
      obsMathQ: document.getElementById('obsMathQ'),
      obsMathNExpr: document.getElementById('obsMathNExpr'),
      obsMathPhiExpr: document.getElementById('obsMathPhiExpr'),
      obsMathEGcd: document.getElementById('obsMathEGcd'),
      obsMathD: document.getElementById('obsMathD'),
      obsMathPub: document.getElementById('obsMathPub'),
      obsMathPriv: document.getElementById('obsMathPriv'),
      obsMathSignSubst: document.getElementById('obsMathSignSubst'),
      obsMathSignVal: document.getElementById('obsMathSignVal'),
      obsMathVerifSubst: document.getElementById('obsMathVerifSubst'),
      obsMathVerifVal: document.getElementById('obsMathVerifVal'),
      obsMathCompare: document.getElementById('obsMathCompare'),

      // Quiz
      quizForm: document.getElementById('quizForm'),
      btnSubmitQuiz: document.getElementById('btnSubmitQuiz'),
      btnResetQuiz: document.getElementById('btnResetQuiz'),
      quizScoreBanner: document.getElementById('quizScoreBanner'),
      quizScoreText: document.getElementById('quizScoreText'),
      quizAppraisalText: document.getElementById('quizAppraisalText'),

      // Interactive "Why?" triggers
      whyButtons: document.querySelectorAll('.why-toggle')
    };
  }

  // ==========================================
  // INITIALIZATION
  // ==========================================
  function init() {
    cacheDom();
    bindEvents();
    renderState();
    initQuiz();
  }

  // ==========================================
  // STATE INVALIDATION & SYNCHRONIZATION HELPERS
  // ==========================================
  function markKeysOutdated() {
    state.keysValid = false;
    state.signatureValid = false;

    if (dom.cardPubKey) dom.cardPubKey.classList.add('outdated');
    if (dom.cardPrivKey) dom.cardPrivKey.classList.add('outdated');

    if (dom.badgePublicKey) {
      dom.badgePublicKey.innerHTML = '<span class="key-outdated-badge">&#9888; Outdated &mdash; Click &ldquo;Generate Keys&rdquo;</span>';
    }
    if (dom.badgePrivateKey) {
      dom.badgePrivateKey.innerHTML = '<span class="key-outdated-badge">&#9888; Outdated &mdash; Click &ldquo;Generate Keys&rdquo;</span>';
    }
    if (dom.pipeStatus) {
      dom.pipeStatus.textContent = 'Outdated';
      dom.pipeStatus.style.color = '#fca5a5';
    }

    markSignatureOutdated('Parameters changed. Please regenerate RSA keys.');
  }

  function markSignatureOutdated(reason = 'Parameters changed. Please generate a new signature.') {
    state.signatureValid = false;
    showAlert(dom.signAlert, reason, 'warning');

    if (dom.digestCompareBox) {
      dom.digestCompareBox.className = 'digest-compare-status mismatch';
      dom.digestCompareBox.innerHTML = `&#9888; ${reason}`;
    }

    if (dom.verdictBox) {
      dom.verdictBox.className = 'verdict-banner invalid';
      dom.verdictTitle.innerHTML = '&#9888; SIGNATURE OUTDATED / INCOMPATIBLE';
      dom.verdictText.innerHTML = `${reason}<br>Click <strong>"Generate Signature"</strong> in Step 3 to synchronize.`;
    }

    if (dom.obsVerifStatus) {
      dom.obsVerifStatus.textContent = 'OUTDATED';
      dom.obsVerifStatus.style.color = '#fca5a5';
    }
  }

  // ==========================================
  // EVENT BINDINGS
  // ==========================================
  function bindEvents() {
    // Stage 1: Primes
    dom.btnUseExample.addEventListener('click', handleUseExample7);
    if (dom.btnUseExample17) {
      dom.btnUseExample17.addEventListener('click', handleUseExample17);
    }
    dom.btnRandomPrimes.addEventListener('click', handleGenerateRandomPrimes);

    dom.inputP.addEventListener('input', () => {
      hideAlert(dom.primeAlert);
      updatePrimeMathStatus();
      markKeysOutdated();
    });
    dom.inputQ.addEventListener('input', () => {
      hideAlert(dom.primeAlert);
      updatePrimeMathStatus();
      markKeysOutdated();
    });

    // Stage 2: Keys
    dom.inputE.addEventListener('input', () => {
      hideAlert(dom.keyAlert);
      markKeysOutdated();
    });
    dom.btnSuggestE.addEventListener('click', handleSuggestE);
    dom.btnGenerateKeys.addEventListener('click', () => handleGenerateKeys(true));

    if (dom.btnToggleKeyMath && dom.keyMathWorkingPanel) {
      dom.btnToggleKeyMath.addEventListener('click', () => {
        const isVis = dom.keyMathWorkingPanel.classList.toggle('visible');
        dom.btnToggleKeyMath.setAttribute('data-expanded', isVis ? 'true' : 'false');
        dom.btnToggleKeyMath.innerHTML = isVis ? '&#128221; Hide Mathematical Working' : '&#128221; Show Mathematical Working';
      });
    }

    // Stage 3: Signing & Hashing
    dom.inputMsg.addEventListener('input', () => {
      hideAlert(dom.signAlert);
      updateSignDigestDisplay();
      markSignatureOutdated('Message changed. Generate a new signature.');
    });

    if (dom.radioSignMd5) {
      dom.radioSignMd5.addEventListener('change', () => handleSelectHash('MD5'));
    }
    if (dom.radioSignSha1) {
      dom.radioSignSha1.addEventListener('change', () => handleSelectHash('SHA-1'));
    }
    if (dom.cardHashMd5) {
      dom.cardHashMd5.addEventListener('click', () => handleSelectHash('MD5'));
    }
    if (dom.cardHashSha1) {
      dom.cardHashSha1.addEventListener('click', () => handleSelectHash('SHA-1'));
    }

    dom.btnGenHash.addEventListener('click', handleGenerateHashExplicit);
    dom.btnSign.addEventListener('click', handleSignMessage);

    if (dom.btnToggleSignPowMath && dom.signPowMathPanel) {
      dom.btnToggleSignPowMath.addEventListener('click', () => {
        const isVis = dom.signPowMathPanel.classList.toggle('visible');
        dom.btnToggleSignPowMath.setAttribute('data-expanded', isVis ? 'true' : 'false');
        dom.btnToggleSignPowMath.innerHTML = isVis ? '&#9881; Hide Calculation Details' : '&#9881; How is this power calculated? (Repeated Squaring)';
      });
    }

    // Stage 4: Verification Hash selection
    if (dom.radioVerifMd5) {
      dom.radioVerifMd5.addEventListener('change', () => handleSelectVerifHash('MD5'));
    }
    if (dom.radioVerifSha1) {
      dom.radioVerifSha1.addEventListener('change', () => handleSelectVerifHash('SHA-1'));
    }
    if (dom.cardVerifMd5) {
      dom.cardVerifMd5.addEventListener('click', () => handleSelectVerifHash('MD5'));
    }
    if (dom.cardVerifSha1) {
      dom.cardVerifSha1.addEventListener('click', () => handleSelectVerifHash('SHA-1'));
    }

    dom.btnVerifyOriginal.addEventListener('click', handleVerifyOriginal);

    if (dom.btnToggleVerifyPowMath && dom.verifyPowMathPanel) {
      dom.btnToggleVerifyPowMath.addEventListener('click', () => {
        const isVis = dom.verifyPowMathPanel.classList.toggle('visible');
        dom.btnToggleVerifyPowMath.setAttribute('data-expanded', isVis ? 'true' : 'false');
        dom.btnToggleVerifyPowMath.innerHTML = isVis ? '&#9881; Hide Calculation Details' : '&#9881; How is this power calculated? (Repeated Squaring)';
      });
    }

    // Stage 5: Interception & Tampering
    dom.btnInterceptMessage.addEventListener('click', handleInterceptMessage);
    dom.btnVerifyTampered.addEventListener('click', handleVerifyTampered);
    dom.btnRestoreOriginal.addEventListener('click', handleRestoreOriginal);

    // Master Math Section Toggle
    if (dom.btnToggleMasterMath && dom.masterMathWorkingContent) {
      dom.btnToggleMasterMath.addEventListener('click', () => {
        const isVis = dom.masterMathWorkingContent.classList.toggle('visible');
        dom.btnToggleMasterMath.setAttribute('data-expanded', isVis ? 'true' : 'false');
        dom.btnToggleMasterMath.innerHTML = isVis ? '&#128221; Collapse / Expand All Math Working' : '&#128221; Show All Mathematical Working';
      });
    }

    // Reset
    if (dom.btnResetSim) dom.btnResetSim.addEventListener('click', handleResetAll);
    if (dom.btnResetSimTab) dom.btnResetSimTab.addEventListener('click', handleResetAll);

    // Interactive Why? buttons
    dom.whyButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        const content = document.getElementById(targetId);
        if (content) {
          content.classList.toggle('visible');
          btn.textContent = content.classList.contains('visible') ? '▲ Hide Explanation' : btn.getAttribute('data-original-text') || '▼ Why?';
        }
      });
    });

    // Quiz
    dom.btnSubmitQuiz.addEventListener('click', handleSubmitQuiz);
    dom.btnResetQuiz.addEventListener('click', handleResetQuiz);
  }

  // ==========================================
  // STAGE 1: PRIME SELECTION & GENERATION
  // ==========================================
  function handleUseExample7() {
    dom.inputP.value = '7';
    dom.inputQ.value = '23';
    dom.inputE.value = '5';
    dom.inputMsg.value = '23';
    hideAlert(dom.primeAlert);
    hideAlert(dom.keyAlert);
    hideAlert(dom.signAlert);
    handleSelectHash('SHA-1');
    handleGenerateKeys(false);
  }

  function handleUseExample17() {
    dom.inputP.value = '17';
    dom.inputQ.value = '11';
    dom.inputE.value = '7';
    dom.inputMsg.value = '88';
    hideAlert(dom.primeAlert);
    hideAlert(dom.keyAlert);
    hideAlert(dom.signAlert);
    handleSelectHash('SHA-1');
    handleGenerateKeys(false);
  }

  function handleGenerateRandomPrimes() {
    hideAlert(dom.primeAlert);
    dom.primeGenStatus.classList.add('active');
    dom.primeGenStatus.innerHTML = 'Selecting random prime <em>p</em>...';

    setTimeout(() => {
      const idx1 = Math.floor(Math.random() * SMALL_PRIMES.length);
      let idx2 = Math.floor(Math.random() * SMALL_PRIMES.length);
      while (idx2 === idx1) {
        idx2 = Math.floor(Math.random() * SMALL_PRIMES.length);
      }

      const p = SMALL_PRIMES[idx1];
      dom.inputP.value = p.toString();
      dom.primeGenStatus.innerHTML = `✓ Found prime <strong>p = ${p}</strong>. Now selecting prime <em>q</em>...`;

      setTimeout(() => {
        const q = SMALL_PRIMES[idx2];
        dom.inputQ.value = q.toString();
        dom.primeGenStatus.innerHTML = `✓ <strong>Prime Pair Ready:</strong> p = ${p}, q = ${q}. Now click <em>"Generate Keys"</em>.`;

        // Automatically choose a valid e
        const phi = (p - 1n) * (q - 1n);
        const candidates = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n];
        for (const c of candidates) {
          if (c < phi && gcd(c, phi) === 1n) {
            dom.inputE.value = c.toString();
            break;
          }
        }

        // Set safe demonstration message
        const n = p * q;
        const sampleM = 2n + BigInt(Math.floor(Math.random() * Number(n > 40n ? 30n : n - 3n)));
        dom.inputMsg.value = sampleM.toString();

        handleGenerateKeys(false);
      }, 350);
    }, 300);
  }

  // ==========================================
  // STAGE 2: KEY GENERATION
  // ==========================================
  function handleSuggestE() {
    let p, q;
    try {
      p = BigInt(dom.inputP.value.trim());
      q = BigInt(dom.inputQ.value.trim());
    } catch {
      showAlert(dom.keyAlert, 'Enter valid prime numbers p and q first!', 'warning');
      return;
    }

    if (p <= 1n || q <= 1n || p === q) {
      showAlert(dom.keyAlert, 'Enter two distinct primes p and q first!', 'warning');
      return;
    }

    const phi = (p - 1n) * (q - 1n);
    const candidates = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 65537n];
    for (const c of candidates) {
      if (c < phi && gcd(c, phi) === 1n) {
        dom.inputE.value = c.toString();
        showAlert(dom.keyAlert, `Selected valid coprime exponent e = ${c} where gcd(${c}, ${phi}) = 1. Click "Generate Keys".`, 'success');
        markKeysOutdated();
        return;
      }
    }
  }

  function handleGenerateKeys(showFeedback = true) {
    hideAlert(dom.primeAlert);
    hideAlert(dom.keyAlert);

    let p, q, e;
    try {
      p = BigInt(dom.inputP.value.trim());
      q = BigInt(dom.inputQ.value.trim());
      e = BigInt(dom.inputE.value.trim());
    } catch {
      showAlert(dom.primeAlert, 'Please enter valid integer values for p, q, and e.', 'error');
      markKeysOutdated();
      return;
    }

    // 1. Primality of p
    const checkP = isPrime(p);
    if (!checkP.prime) {
      showAlert(dom.primeAlert, `Parameter p (${p}) is not a valid prime number! It is divisible by ${checkP.factor}.`, 'error');
      markKeysOutdated();
      return;
    }

    // 2. Primality of q
    const checkQ = isPrime(q);
    if (!checkQ.prime) {
      showAlert(dom.primeAlert, `Parameter q (${q}) is not a valid prime number! It is divisible by ${checkQ.factor}.`, 'error');
      markKeysOutdated();
      return;
    }

    // 3. p != q
    if (p === q) {
      showAlert(dom.primeAlert, 'p and q must be different prime numbers! If p = q, Euler totient calculation fails.', 'error');
      markKeysOutdated();
      return;
    }

    // 4. Calculate n = p * q
    const n = p * q;

    // 5. Calculate phi(n) = (p - 1) * (q - 1)
    const phi = (p - 1n) * (q - 1n);

    // 6. Validate e range: 1 < e < phi(n)
    if (e <= 1n || e >= phi) {
      showAlert(dom.keyAlert, `Public exponent e must satisfy 1 < e < phi(n) (1 < ${e} < ${phi}).`, 'error');
      markKeysOutdated();
      return;
    }

    // 7. Validate gcd(e, phi(n)) = 1
    const gcdVal = gcd(e, phi);
    if (gcdVal !== 1n) {
      showAlert(
        dom.keyAlert,
        `gcd(${e}, ${phi}) = ${gcdVal}\n✕ Invalid public exponent\nReason: e must be coprime with phi(n) so that its modular inverse exists.\nd cannot be calculated because e has no modular inverse modulo phi(n).`,
        'error'
      );

      state.keysValid = false;
      state.signatureValid = false;

      if (dom.cardPubKey) dom.cardPubKey.classList.add('outdated');
      if (dom.cardPrivKey) dom.cardPrivKey.classList.add('outdated');
      if (dom.badgePublicKey) dom.badgePublicKey.textContent = 'None (Invalid e)';
      if (dom.badgePrivateKey) dom.badgePrivateKey.textContent = 'None (Invalid e)';
      if (dom.pipeStatus) {
        dom.pipeStatus.textContent = 'Invalid e';
        dom.pipeStatus.style.color = '#fca5a5';
      }

      // Step-by-step breakdown updates
      if (dom.mathKeyStep3E) dom.mathKeyStep3E.textContent = `e = ${e}`;
      if (dom.mathKeyStep3Gcd) dom.mathKeyStep3Gcd.textContent = `gcd(e, phi(n)) = gcd(${e}, ${phi}) = ${gcdVal}`;
      if (dom.mathKeyStep3Status) {
        dom.mathKeyStep3Status.innerHTML = `<span style="color:#fca5a5; font-weight:bold;">✕ Invalid public exponent<br>Reason: e must be coprime with phi(n) so that its modular inverse exists.</span>`;
      }
      if (dom.mathKeyStep4Div) {
        dom.mathKeyStep4Div.textContent = `gcd(${e}, ${phi}) = ${gcdVal} ≠ 1. Because e is not coprime with phi(n), no modular multiplicative inverse exists.`;
      }
      if (dom.mathKeyStep4BackSub) dom.mathKeyStep4BackSub.textContent = 'Calculation halted.';
      if (dom.mathKeyStep4Result) dom.mathKeyStep4Result.textContent = 'd cannot be calculated because e has no modular inverse modulo phi(n).';
      if (dom.mathKeyStep4Verify) dom.mathKeyStep4Verify.textContent = 'No private key generated.';

      markSignatureOutdated('Public exponent e is invalid. Keys were not generated.');
      updateObservations();
      return;
    }

    // 8. Calculate d = e^-1 mod phi(n)
    const d = modInverse(e, phi);
    if (!d) {
      showAlert(dom.keyAlert, `Could not find modular inverse d for e=${e} mod phi(n)=${phi}.`, 'error');
      markKeysOutdated();
      return;
    }

    // State is synchronized with validated inputs
    state.p = p;
    state.q = q;
    state.n = n;
    state.phi = phi;
    state.e = e;
    state.d = d;
    state.keysValid = true;

    // Reset outdated UI markers
    if (dom.cardPubKey) dom.cardPubKey.classList.remove('outdated');
    if (dom.cardPrivKey) dom.cardPrivKey.classList.remove('outdated');

    // Progressive pipeline display
    if (dom.pipeN) dom.pipeN.textContent = `n = ${n}`;
    if (dom.pipePhi) dom.pipePhi.textContent = `phi(n) = ${phi}`;
    if (dom.pipeE) dom.pipeE.textContent = `e = ${e}`;
    if (dom.pipeD) dom.pipeD.textContent = `d = ${d}`;
    if (dom.pipeStatus) {
      dom.pipeStatus.textContent = 'Keys Ready';
      dom.pipeStatus.style.color = '#86efac';
    }

    // Badges derived strictly from state
    if (dom.badgePublicKey) dom.badgePublicKey.textContent = `(e = ${state.e}, n = ${state.n})`;
    if (dom.badgePrivateKey) dom.badgePrivateKey.textContent = `(d = ${state.d}, n = ${state.n})`;

    if (dom.msgRangeNote) dom.msgRangeNote.textContent = `Requirement: 0 < m < ${state.n}`;

    if (showFeedback) {
      showAlert(dom.keyAlert, `Keys Ready! Public Key (e, n) = (${state.e}, ${state.n}), Private Key (d, n) = (${state.d}, ${state.n}). Verified: ${state.e} × ${state.d} ≡ 1 (mod ${state.phi}).`, 'success');
    }

    updateObservations();
    updateMathematicalWorking();
    handleSignMessage();
  }

  // ==========================================
  // STAGE 3: HASHING & SIGNING
  // ==========================================
  function handleSelectHash(algo) {
    state.selectedHash = algo;

    if (dom.cardHashMd5 && dom.cardHashSha1) {
      dom.cardHashMd5.classList.toggle('active', algo === 'MD5');
      dom.cardHashSha1.classList.toggle('active', algo === 'SHA-1');
    }
    if (dom.radioSignMd5) dom.radioSignMd5.checked = (algo === 'MD5');
    if (dom.radioSignSha1) dom.radioSignSha1.checked = (algo === 'SHA-1');

    updateSignDigestDisplay();

    // Check if user changed hash algorithm after signing
    if (state.signed && state.signatureHashAlgorithm !== algo) {
      markSignatureOutdated(`Hash algorithm changed. Signature was generated using ${state.signatureHashAlgorithm}. Generate a new signature using ${algo}.`);
    }
  }

  function updateSignDigestDisplay() {
    const rawMsg = dom.inputMsg.value.trim();
    const digest = computeHash(state.selectedHash, rawMsg);
    state.hashDigest = digest;

    if (dom.signSelectedHashText) dom.signSelectedHashText.textContent = state.selectedHash;
    if (dom.signDigestLengthBadge) dom.signDigestLengthBadge.textContent = getHashLengthDescription(state.selectedHash);
    if (dom.signDigestDisplay) dom.signDigestDisplay.textContent = digest;
  }

  function handleGenerateHashExplicit() {
    updateSignDigestDisplay();
    showAlert(dom.signAlert, `Computed ${state.selectedHash} digest for message ${dom.inputMsg.value.trim()}.`, 'info');
  }

  function handleSignMessage() {
    hideAlert(dom.signAlert);

    if (!state.keysValid) {
      showAlert(dom.signAlert, 'Please generate RSA keys in Step 2 first using valid coprime parameters!', 'warning');
      return;
    }

    let m;
    try {
      m = BigInt(dom.inputMsg.value.trim());
    } catch {
      showAlert(dom.signAlert, 'Please enter a valid numeric message m!', 'error');
      return;
    }

    if (m <= 0n) {
      showAlert(dom.signAlert, `Message m must be a positive integer (m > 0). Entered: ${m}.`, 'error');
      return;
    }

    if (m >= state.n) {
      showAlert(dom.signAlert, `Validation Error: Message m (${m}) must be strictly less than modulus n (${state.n})! All RSA modular operations occur modulo n.`, 'error');
      return;
    }

    // 1. Generate live cryptographic hash
    const digest = computeHash(state.selectedHash, m.toString());
    state.hashDigest = digest;
    state.signatureHashAlgorithm = state.selectedHash;
    state.signatureDigest = digest;

    // 2. Compute educational RSA signature: s = m^d mod n
    const s = modPow(m, state.d, state.n);

    state.message = m;
    state.signature = s;
    state.receivedMsg = m;
    state.receivedSig = s;
    state.signed = true;
    state.signatureValid = true;
    state.isIntercepted = false;
    state.interceptionTested = false;

    // Automatically align verification hash algorithm to match signer
    state.verifHashAlgo = state.selectedHash;
    if (dom.cardVerifMd5 && dom.cardVerifSha1) {
      dom.cardVerifMd5.classList.toggle('active', state.selectedHash === 'MD5');
      dom.cardVerifSha1.classList.toggle('active', state.selectedHash === 'SHA-1');
    }
    if (dom.radioVerifMd5) dom.radioVerifMd5.checked = (state.selectedHash === 'MD5');
    if (dom.radioVerifSha1) dom.radioVerifSha1.checked = (state.selectedHash === 'SHA-1');
    if (dom.hashMismatchWarning) dom.hashMismatchWarning.style.display = 'none';

    // Display clean formula without LaTeX
    if (dom.signMathFormula) {
      dom.signMathFormula.textContent = `Educational RSA Signing Operation: s = m^d mod n (Using Private Key d = ${state.d}, n = ${state.n})`;
    }
    if (dom.signMathSubst) {
      dom.signMathSubst.textContent = `Substitution: s = ${m}^${state.d} mod ${state.n}`;
    }
    if (dom.signMathResult) {
      dom.signMathResult.textContent = `Digital Signature s = ${s}`;
    }

    updateSignDigestDisplay();

    // In-Transit Display updates
    if (dom.transitMsgDisplay) dom.transitMsgDisplay.textContent = m.toString();
    if (dom.transitSigDisplay) dom.transitSigDisplay.textContent = s.toString();
    if (dom.transitStatusPill) {
      dom.transitStatusPill.className = 'pipeline-node';
      dom.transitStatusPill.style.color = '#86efac';
      dom.transitStatusPill.textContent = 'Untampered';
    }

    // Set diagram
    setDiagramState('normal');

    updateObservations();
    updateMathematicalWorking();
    handleVerifyOriginal();
  }

  // ==========================================
  // STAGE 4: SIGNATURE VERIFICATION
  // ==========================================
  function handleSelectVerifHash(algo) {
    state.verifHashAlgo = algo;

    if (dom.cardVerifMd5 && dom.cardVerifSha1) {
      dom.cardVerifMd5.classList.toggle('active', algo === 'MD5');
      dom.cardVerifSha1.classList.toggle('active', algo === 'SHA-1');
    }
    if (dom.radioVerifMd5) dom.radioVerifMd5.checked = (algo === 'MD5');
    if (dom.radioVerifSha1) dom.radioVerifSha1.checked = (algo === 'SHA-1');

    if (dom.verifAlgoLabelStep3) dom.verifAlgoLabelStep3.textContent = algo;

    // Check algorithm mismatch against signing algorithm
    if (state.signatureValid && state.signatureHashAlgorithm !== algo) {
      if (dom.hashMismatchWarning) {
        dom.hashMismatchWarning.style.display = 'block';
        dom.hashMismatchWarning.textContent = `Hash algorithm changed! Signature was generated using ${state.signatureHashAlgorithm}. Generate a new signature using ${algo}.`;
      }
    } else {
      if (dom.hashMismatchWarning) dom.hashMismatchWarning.style.display = 'none';
    }

    handleVerifyOriginal();
  }

  function handleVerifyOriginal() {
    if (!state.signed) return;

    state.receivedMsg = state.message;
    state.receivedSig = state.signature;
    state.isIntercepted = false;
    state.interceptionTested = false;

    executeVerification(state.receivedMsg, state.receivedSig, state.verifHashAlgo);
  }

  function executeVerification(msgToVerify, sigToVerify, algoToVerify) {
    if (dom.verifStep1Msg) dom.verifStep1Msg.textContent = msgToVerify.toString();
    if (dom.verifAlgoLabelStep3) dom.verifAlgoLabelStep3.textContent = algoToVerify;

    // 1. Calculate message digest of received message
    const calcDigest = computeHash(algoToVerify, msgToVerify.toString());
    state.verifCalcDigest = calcDigest;
    if (dom.verifCalcDigest) dom.verifCalcDigest.textContent = calcDigest;

    // 2. Recover message representation using public key: m' = s^e mod n
    const mRecovered = modPow(sigToVerify, state.e, state.n);
    state.recoveredMsg = mRecovered;

    // 3. Signature-side digest representation
    const recDigest = computeHash(state.signatureHashAlgorithm, mRecovered.toString());
    state.verifRecDigest = recDigest;
    if (dom.verifRecoveredDigest) dom.verifRecoveredDigest.textContent = `${recDigest} (m' = ${mRecovered})`;

    // Check conditions:
    // a. Hash algorithm must match
    const algoMatch = (algoToVerify === state.signatureHashAlgorithm);
    // b. Digests must match
    const digestMatch = (calcDigest === recDigest);
    // c. Integer recovery match
    const mathMatch = (mRecovered === msgToVerify);
    // d. Key and signature must be currently valid (not outdated)
    const isStateValid = state.keysValid && state.signatureValid;

    const isValid = algoMatch && digestMatch && mathMatch && isStateValid;
    state.verdict = isValid ? 'VALID' : 'INVALID';

    if (dom.verifMathFormula) {
      dom.verifMathFormula.textContent = `Verification Equation: m' = s^e mod n (Using Public Key e = ${state.e}, n = ${state.n})`;
    }
    if (dom.verifMathSubst) {
      dom.verifMathSubst.textContent = `Substitution: m' = ${sigToVerify}^${state.e} mod ${state.n}`;
    }
    if (dom.verifMathRecovered) {
      dom.verifMathRecovered.textContent = `Recovered Message m' = ${mRecovered} | Received Message m = ${msgToVerify}`;
    }

    // Step 5 digest comparison UI
    if (dom.digestCompareBox) {
      if (!isStateValid) {
        dom.digestCompareBox.className = 'digest-compare-status mismatch';
        dom.digestCompareBox.innerHTML = '&#9888; Keys or Signature Outdated! Please regenerate.';
      } else if (!algoMatch) {
        dom.digestCompareBox.className = 'digest-compare-status mismatch';
        dom.digestCompareBox.innerHTML = `&#10005; Hash Algorithm Mismatch! Signed with ${state.signatureHashAlgorithm}, verifying with ${algoToVerify}.`;
      } else if (digestMatch) {
        dom.digestCompareBox.className = 'digest-compare-status match';
        dom.digestCompareBox.innerHTML = `&check; Calculated Digest = Recovered Digest &rarr; Match (${algoToVerify})`;
      } else {
        dom.digestCompareBox.className = 'digest-compare-status mismatch';
        dom.digestCompareBox.innerHTML = `&#10005; Calculated Digest &ne; Recovered Digest &rarr; Mismatch!`;
      }
    }

    // Verdict Banner updates
    if (isValid) {
      if (dom.verdictBox) dom.verdictBox.className = 'verdict-banner valid';
      if (dom.verdictTitle) dom.verdictTitle.innerHTML = '&check; VALID SIGNATURE';
      if (dom.verdictText) {
        dom.verdictText.innerHTML = `During verification, the receiver hashes the received message using the selected hash algorithm (${algoToVerify}) and compares it with the digest represented by the signature. If they match, the signature is valid.<br>` +
          `Original Message = <strong>${msgToVerify}</strong>, Recovered Message = <strong>${mRecovered}</strong>.<br>` +
          `Because both digests match, message authenticity and integrity are verified!`;
      }
      setDiagramState('valid');
    } else {
      if (dom.verdictBox) dom.verdictBox.className = 'verdict-banner invalid';
      if (dom.verdictTitle) dom.verdictTitle.innerHTML = '&#10005; INVALID SIGNATURE';

      let reasonText = '';
      if (!isStateValid) {
        reasonText = 'The current keys or signature are outdated. Regenerate them in Step 2 and Step 3.';
      } else if (!algoMatch) {
        reasonText = `Signature was generated using ${state.signatureHashAlgorithm}. Verification used ${algoToVerify}. Generate a new signature using ${algoToVerify}.`;
      } else {
        reasonText = `Received Message (${msgToVerify}) digest does not match the signature digest. Tampering or key mismatch was detected!`;
      }

      if (dom.verdictText) {
        dom.verdictText.innerHTML = `${reasonText}<br>` +
          `During verification, the receiver hashes the received message using the selected hash algorithm and compares it with the digest represented by the signature. If they match, the signature is valid.`;
      }
      setDiagramState('invalid');
    }

    updateObservations();
    updateMathematicalWorking();
  }

  // ==========================================
  // STAGE 5: INTERCEPTION & TAMPERING DEMONSTRATION
  // ==========================================
  function handleInterceptMessage() {
    if (!state.signed) {
      alert('Please generate a signature in Step 3 first!');
      return;
    }

    let modified = state.message + 1n;
    if (modified >= state.n) modified = 1n;

    state.tamperedMsg = modified;
    state.receivedMsg = modified;
    state.isIntercepted = true;

    if (dom.transitMsgDisplay) {
      dom.transitMsgDisplay.textContent = `${modified} (Altered by Interceptor)`;
    }
    if (dom.transitStatusPill) {
      dom.transitStatusPill.className = 'pipeline-node';
      dom.transitStatusPill.style.color = '#fca5a5';
      dom.transitStatusPill.textContent = 'TAMPERED IN TRANSIT';
    }

    if (dom.tamperMathCard) dom.tamperMathCard.style.display = 'block';

    setDiagramState('interception');
    updateObservations();
    updateMathematicalWorking();
  }

  function handleVerifyTampered() {
    if (!state.isIntercepted) {
      handleInterceptMessage();
    }
    state.interceptionTested = true;
    executeVerification(state.tamperedMsg, state.signature, state.verifHashAlgo);
  }

  function handleRestoreOriginal() {
    state.isIntercepted = false;
    state.interceptionTested = false;
    state.receivedMsg = state.message;
    state.receivedSig = state.signature;

    if (dom.transitMsgDisplay) dom.transitMsgDisplay.textContent = state.message.toString();
    if (dom.transitSigDisplay) dom.transitSigDisplay.textContent = state.signature.toString();
    if (dom.transitStatusPill) {
      dom.transitStatusPill.className = 'pipeline-node';
      dom.transitStatusPill.style.color = '#86efac';
      dom.transitStatusPill.textContent = 'Untampered';
    }

    if (dom.tamperMathCard) dom.tamperMathCard.style.display = 'none';

    handleVerifyOriginal();
  }

  // ==========================================
  // SECURITY DIAGRAM STATE HIGHLIGHTER
  // ==========================================
  function setDiagramState(mode) {
    if (!dom.diagramSender) return;

    [dom.diagramSender, dom.diagramSignature, dom.diagramInterceptor, dom.diagramReceiver, dom.diagramVerify, dom.diagramResult].forEach(node => {
      if (node) node.className = 'diagram-step';
    });

    if (dom.diagramSenderContent) {
      dom.diagramSenderContent.textContent = `m = ${state.message} • ${state.signatureHashAlgorithm}`;
    }
    if (dom.diagramSignatureContent) {
      dom.diagramSignatureContent.textContent = `s = ${state.signature}`;
    }
    if (dom.diagramReceiverContent) {
      dom.diagramReceiverContent.textContent = `Public Key (${state.e}, ${state.n})`;
    }

    if (mode === 'normal') {
      dom.diagramSender.classList.add('active');
      dom.diagramSignature.classList.add('active');
      dom.diagramReceiver.classList.add('active');
    } else if (mode === 'interception') {
      dom.diagramSender.classList.add('active');
      dom.diagramSignature.classList.add('active');
      dom.diagramInterceptor.classList.add('interception-active');
      dom.diagramReceiver.classList.add('active');
    } else if (mode === 'valid') {
      dom.diagramSender.classList.add('active');
      dom.diagramSignature.classList.add('active');
      dom.diagramReceiver.classList.add('active');
      dom.diagramVerify.classList.add('active');
      dom.diagramResult.classList.add('active');
      if (dom.diagramResultContent) {
        dom.diagramResultContent.textContent = 'VALID (H(m) = H(m\'))';
        dom.diagramResultContent.style.color = '#86efac';
      }
    } else if (mode === 'invalid') {
      dom.diagramInterceptor.classList.add('interception-active');
      dom.diagramReceiver.classList.add('active');
      dom.diagramVerify.classList.add('active');
      dom.diagramResult.classList.add('fail');
      if (dom.diagramResultContent) {
        dom.diagramResultContent.textContent = 'INVALID (Mismatch)';
        dom.diagramResultContent.style.color = '#fca5a5';
      }
    }
  }

  // ==========================================
  // OBSERVATIONS & RESULTS DASHBOARD
  // ==========================================
  function updateObservations() {
    if (!dom.obsP) return;

    dom.obsP.textContent = state.p.toString();
    dom.obsQ.textContent = state.q.toString();
    dom.obsE.textContent = state.e.toString();
    dom.obsMsg.textContent = state.message.toString();

    dom.obsN.textContent = state.n.toString();
    dom.obsPhi.textContent = state.phi.toString();
    dom.obsD.textContent = state.d.toString();

    if (dom.obsSignHashAlgo) dom.obsSignHashAlgo.textContent = state.signatureHashAlgorithm;
    if (dom.obsSignDigest) dom.obsSignDigest.textContent = state.signatureDigest || computeHash(state.signatureHashAlgorithm, state.message.toString());

    dom.obsSig.textContent = state.signature.toString();

    if (dom.obsVerifHashAlgo) dom.obsVerifHashAlgo.textContent = state.verifHashAlgo;
    if (dom.obsVerifCalcDigest) dom.obsVerifCalcDigest.textContent = state.verifCalcDigest;
    if (dom.obsVerifRecDigest) dom.obsVerifRecDigest.textContent = `${state.verifRecDigest} (m'=${state.recoveredMsg})`;
    dom.obsVerifStatus.textContent = state.verdict;
    dom.obsVerifStatus.style.color = state.verdict === 'VALID' ? '#86efac' : '#fca5a5';
  }

  function handleResetAll() {
    handleUseExample7();
    state.interceptionTested = false;
    updateObservations();
    updateMathematicalWorking();
    alert('Experiment reset to initial demonstration state (p=7, q=23, e=5, m=23, SHA-1).');
  }

  // ==========================================
  // MATHEMATICAL WORKING ENGINE
  // ==========================================
  function updatePrimeMathStatus() {
    if (!dom.primeStatusP || !dom.primeStatusQ) return;
    let p = null, q = null;
    try {
      p = BigInt(dom.inputP.value.trim());
    } catch { p = null; }
    try {
      q = BigInt(dom.inputQ.value.trim());
    } catch { q = null; }

    if (p !== null && p > 0n) {
      const chkP = isPrime(p);
      if (chkP.prime) {
        dom.primeStatusP.innerHTML = `p = ${p}: <span style="color:#86efac; font-weight:bold;">&check; Prime</span>`;
      } else {
        const factorText = chkP.factor ? ` (${p} = ${chkP.factor} &times; ${p / chkP.factor})` : '';
        dom.primeStatusP.innerHTML = `p = ${p}: <span style="color:#fca5a5; font-weight:bold;">&#10005; Not Prime${factorText}</span>`;
      }
    } else {
      dom.primeStatusP.innerHTML = '<span style="color:var(--color-text-muted);">p: Enter integer</span>';
    }

    if (q !== null && q > 0n) {
      const chkQ = isPrime(q);
      if (chkQ.prime) {
        dom.primeStatusQ.innerHTML = `q = ${q}: <span style="color:#86efac; font-weight:bold;">&check; Prime</span>`;
      } else {
        const factorText = chkQ.factor ? ` (${q} = ${chkQ.factor} &times; ${q / chkQ.factor})` : '';
        dom.primeStatusQ.innerHTML = `q = ${q}: <span style="color:#fca5a5; font-weight:bold;">&#10005; Not Prime${factorText}</span>`;
      }
    } else {
      dom.primeStatusQ.innerHTML = '<span style="color:var(--color-text-muted);">q: Enter integer</span>';
    }
  }

  function updateMathematicalWorking() {
    updatePrimeMathStatus();

    // 1. Stage 2 Key Gen Math
    if (state.keysValid) {
      if (dom.mathKeyStep1Subst) dom.mathKeyStep1Subst.textContent = `n = ${state.p} × ${state.q}`;
      if (dom.mathKeyStep1Result) dom.mathKeyStep1Result.textContent = `n = ${state.n}`;

      if (dom.mathKeyStep2Subst) {
        dom.mathKeyStep2Subst.textContent = `phi(n) = (${state.p} - 1)(${state.q} - 1) = ${state.p - 1n} × ${state.q - 1n}`;
      }
      if (dom.mathKeyStep2Result) dom.mathKeyStep2Result.textContent = `phi(n) = ${state.phi}`;

      if (dom.mathKeyStep3E) dom.mathKeyStep3E.textContent = `e = ${state.e}`;
      const gcdVal = gcd(state.e, state.phi);
      if (dom.mathKeyStep3Gcd) dom.mathKeyStep3Gcd.textContent = `gcd(e, phi(n)) = gcd(${state.e}, ${state.phi}) = ${gcdVal}`;
      if (dom.mathKeyStep3Status) {
        if (gcdVal === 1n) {
          dom.mathKeyStep3Status.innerHTML = '<span style="color:#86efac; font-weight:bold;">Therefore: e is valid.</span>';
        } else {
          dom.mathKeyStep3Status.innerHTML = `<span style="color:#fca5a5; font-weight:bold;">✕ e is not valid (gcd = ${gcdVal} ≠ 1). Modular inverse d cannot be calculated.</span>`;
        }
      }

      const eeTrace = getExtendedEuclideanTrace(state.e, state.phi);
      if (eeTrace.valid) {
        if (dom.mathKeyStep4Div) dom.mathKeyStep4Div.innerHTML = eeTrace.divEqs.join('<br>');
        if (dom.mathKeyStep4BackSub) dom.mathKeyStep4BackSub.innerHTML = eeTrace.subSteps.join('<br>');
        if (dom.mathKeyStep4Result) dom.mathKeyStep4Result.textContent = `Therefore: d = ${state.d}`;
        if (dom.mathKeyStep4Verify) dom.mathKeyStep4Verify.innerHTML = eeTrace.verifyEquation;
      }

      if (dom.mathKeyPubDisplay) dom.mathKeyPubDisplay.textContent = `(${state.e}, ${state.n})`;
      if (dom.mathKeyPrivDisplay) dom.mathKeyPrivDisplay.textContent = `(${state.d}, ${state.n})`;
    }

    // 2. Stage 3 Signing Math & Repeated Squaring
    if (state.signed && state.keysValid) {
      if (dom.signPowHeading) dom.signPowHeading.textContent = `${state.message}^${state.d} mod ${state.n}`;
      const signTrace = getRepeatedSquaringTrace(state.message, state.d, state.n);
      if (dom.signPowBinary) dom.signPowBinary.textContent = `${state.d} in binary: ${state.d} = ${signTrace.binary}₂ (${signTrace.sumPowers})`;

      if (dom.signPowTableBody) {
        let rowsHtml = '';
        signTrace.powers.forEach((p, idx) => {
          const cls = p.included ? 'included' : '';
          const incText = p.included ? '<strong style="color:#86efac;">✓ Yes (bit = 1)</strong>' : '<span style="color:var(--color-text-muted);">— No (bit = 0)</span>';
          rowsHtml += `
            <tr class="${cls}">
              <td>2^${idx} = ${p.expPower}</td>
              <td><strong>${p.bit}</strong></td>
              <td><code>${state.message}^${p.expPower} mod ${state.n} = ${p.val}</code></td>
              <td>${incText}</td>
            </tr>
          `;
        });
        dom.signPowTableBody.innerHTML = rowsHtml;
      }

      if (dom.signPowAccumSteps) {
        dom.signPowAccumSteps.innerHTML = signTrace.multSteps.join('<br>');
      }
      if (dom.signPowFinalResult) {
        dom.signPowFinalResult.textContent = `Final Result: ${state.message}^${state.d} mod ${state.n} = ${state.signature}`;
      }
    }

    // 3. Stage 4 Verification Math & Repeated Squaring
    if (state.signed && state.keysValid) {
      if (dom.verifyPowHeading) dom.verifyPowHeading.textContent = `${state.receivedSig}^${state.e} mod ${state.n}`;
      const verifTrace = getRepeatedSquaringTrace(state.receivedSig, state.e, state.n);
      if (dom.verifyPowBinary) dom.verifyPowBinary.textContent = `${state.e} in binary: ${state.e} = ${verifTrace.binary}₂ (${verifTrace.sumPowers})`;

      if (dom.verifyPowTableBody) {
        let rowsHtml = '';
        verifTrace.powers.forEach((p, idx) => {
          const cls = p.included ? 'included' : '';
          const incText = p.included ? '<strong style="color:#86efac;">✓ Yes (bit = 1)</strong>' : '<span style="color:var(--color-text-muted);">— No (bit = 0)</span>';
          rowsHtml += `
            <tr class="${cls}">
              <td>2^${idx} = ${p.expPower}</td>
              <td><strong>${p.bit}</strong></td>
              <td><code>${state.receivedSig}^${p.expPower} mod ${state.n} = ${p.val}</code></td>
              <td>${incText}</td>
            </tr>
          `;
        });
        dom.verifyPowTableBody.innerHTML = rowsHtml;
      }

      if (dom.verifyPowAccumSteps) {
        dom.verifyPowAccumSteps.innerHTML = verifTrace.multSteps.join('<br>');
      }
      if (dom.verifyPowFinalResult) {
        dom.verifyPowFinalResult.textContent = `Final Result: ${state.receivedSig}^${state.e} mod ${state.n} = ${state.recoveredMsg}`;
      }
    }

    // 4. Stage 5 Tampering Math Card
    if (dom.tamperMathCard) {
      if (state.isIntercepted) {
        dom.tamperMathCard.style.display = 'block';
        if (dom.tamperMathOrigM) dom.tamperMathOrigM.textContent = state.message.toString();
        if (dom.tamperMathOrigS) dom.tamperMathOrigS.textContent = state.signature.toString();
        if (dom.tamperMathOrigVerif) dom.tamperMathOrigVerif.textContent = `${state.signature}^${state.e} mod ${state.n} = ${state.message}`;
        if (dom.tamperMathFromM) dom.tamperMathFromM.textContent = state.message.toString();
        if (dom.tamperMathToM) dom.tamperMathToM.textContent = state.tamperedMsg.toString();
        if (dom.tamperMathSigKept) dom.tamperMathSigKept.textContent = state.signature.toString();
        if (dom.tamperMathRecCalc) dom.tamperMathRecCalc.textContent = `${state.receivedSig}^${state.e} mod ${state.n} = ${state.recoveredMsg}`;
        if (dom.tamperMathRecReceived) dom.tamperMathRecReceived.textContent = state.receivedMsg.toString();
        if (dom.tamperMathRecRecovered) dom.tamperMathRecRecovered.textContent = state.recoveredMsg.toString();

        const activeAlgo = state.verifHashAlgo || 'SHA-1';
        if (dom.tamperShaOrigM) dom.tamperShaOrigM.textContent = `${state.message} (${activeAlgo})`;
        if (dom.tamperShaDigestOrig) dom.tamperShaDigestOrig.textContent = computeHash(activeAlgo, state.message.toString());
        if (dom.tamperShaModM) dom.tamperShaModM.textContent = `${state.tamperedMsg} (${activeAlgo})`;
        if (dom.tamperShaDigestMod) dom.tamperShaDigestMod.textContent = computeHash(activeAlgo, state.tamperedMsg.toString());
      } else {
        dom.tamperMathCard.style.display = 'none';
      }
    }

    // 5. Master Mathematical Walkthrough Section
    if (dom.masterMathWorkingContent && state.keysValid) {
      const eeTrace = getExtendedEuclideanTrace(state.e, state.phi);
      const signTrace = getRepeatedSquaringTrace(state.message, state.d, state.n);
      const verifTrace = getRepeatedSquaringTrace(state.signature, state.e, state.n);

      let masterHtml = `
        <div class="math-step-card">
          <div class="math-step-header">
            <span class="math-step-title">Stage 1 &amp; 2 &mdash; Key Generation Mathematics</span>
            <span class="math-code-tag">Implemented by: n = p * q, phi = (p-1)*(q-1), modInverse(e, phi)</span>
          </div>
          <div class="math-calc-line"><strong>Primes Selected:</strong> p = ${state.p} (✓ Prime), q = ${state.q} (✓ Prime)</div>
          <div class="math-calc-line"><strong>Step 1 &mdash; Modulus:</strong> n = p &times; q = ${state.p} &times; ${state.q} = <strong>${state.n}</strong></div>
          <div class="math-calc-line"><strong>Step 2 &mdash; Euler's Totient:</strong> phi(n) = (p - 1)(q - 1) = (${state.p} - 1)(${state.q} - 1) = ${state.p - 1n} &times; ${state.q - 1n} = <strong>${state.phi}</strong></div>
          <div class="math-calc-line"><strong>Step 3 &mdash; Public Exponent Check:</strong> e = ${state.e}, gcd(e, phi(n)) = gcd(${state.e}, ${state.phi}) = 1 &rarr; Coprime condition satisfied, modular inverse exists.</div>
          <div class="math-calc-line"><strong>Step 4 &mdash; Private Exponent Derivation:</strong> d = e⁻¹ mod phi(n) = ${state.e}⁻¹ mod ${state.phi}</div>
          <div class="math-calc-line math-calc-subst" style="margin-top: 4px;">
            <strong>Euclidean Division Steps:</strong><br>${eeTrace.divEqs.join('<br>')}<br>
            <strong>Extended Euclidean Derivation (Back-Substitution):</strong><br>${eeTrace.subSteps.join('<br>')}
          </div>
          <div class="math-calc-line math-calc-result" style="margin-top: 4px;">Private Exponent d = ${state.d}</div>
          <div class="math-calc-line math-calc-subst">${eeTrace.verifyEquation}</div>
          <div class="math-calc-line" style="margin-top: 6px;">
            <strong>PUBLIC KEY (e, n):</strong> (${state.e}, ${state.n}) &emsp;|&emsp;
            <strong>PRIVATE KEY (d, n):</strong> (${state.d}, ${state.n})
          </div>
        </div>

        <div class="math-step-card">
          <div class="math-step-header">
            <span class="math-step-title">Stage 3 &mdash; Message Hashing &amp; Digital Signature Generation</span>
            <span class="math-code-tag">Implemented by: CryptoJS.${state.signatureHashAlgorithm === 'MD5' ? 'MD5' : 'SHA1'}(m) and modPow(m, d, n)</span>
          </div>
          <div class="math-calc-line"><strong>Message:</strong> m = ${state.message}</div>
          <div class="math-calc-line"><strong>Selected Hash Algorithm:</strong> ${state.signatureHashAlgorithm} (${getHashLengthDescription(state.signatureHashAlgorithm)})</div>
          <div class="math-calc-line math-calc-subst"><strong>Message Digest:</strong> ${state.signatureDigest || computeHash(state.signatureHashAlgorithm, state.message.toString())}</div>
          <div class="math-calc-line"><strong>Signing Operation:</strong> s = m^d mod n (Using Private Exponent d = ${state.d})</div>
          <div class="math-calc-line math-calc-subst"><strong>Substitution:</strong> s = ${state.message}^${state.d} mod ${state.n}</div>
          <div class="math-calc-line"><strong>Repeated-Squaring Breakdown:</strong> ${state.d} = ${signTrace.binary}₂ (${signTrace.sumPowers})</div>
          <div class="math-calc-line math-calc-subst">${signTrace.multSteps.join('<br>')}</div>
          <div class="math-calc-line math-calc-result" style="margin-top: 4px;"><strong>Digital Signature s = ${state.signature}</strong></div>
          <div class="math-explanation-note">Educational RSA demonstration: The mathematical operation s = m^d mod n binds private key d to message m, while cryptographic digest H(m) guarantees message integrity.</div>
        </div>

        <div class="math-step-card">
          <div class="math-step-header">
            <span class="math-step-title">Stage 4 &mdash; Digital Signature Verification &amp; Digest Comparison</span>
            <span class="math-code-tag">Implemented by: modPow(s, e, n) and digest comparison</span>
          </div>
          <div class="math-calc-line"><strong>Step 1:</strong> Received Message = ${state.receivedMsg}</div>
          <div class="math-calc-line"><strong>Step 2:</strong> Verification Hash Algorithm = ${state.verifHashAlgo}</div>
          <div class="math-calc-line math-calc-subst"><strong>Step 3:</strong> Calculated Digest H(m) = ${state.verifCalcDigest}</div>
          <div class="math-calc-line"><strong>Step 4:</strong> Public Key Operation: m' = s^e mod n = ${state.signature}^${state.e} mod ${state.n} = <strong>${state.recoveredMsg}</strong></div>
          <div class="math-calc-line math-calc-subst">Recovered Digest Representation: ${state.verifRecDigest}</div>
          <div class="math-calc-line"><strong>Step 5:</strong> Comparison: Calculated Digest = Recovered Digest &rarr; <span style="color:#86efac; font-weight:bold;">&check; VALID SIGNATURE</span></div>
          <div class="math-explanation-note">During verification, the receiver hashes the received message using the selected hash algorithm and compares it with the digest represented by the signature. If they match, the signature is valid.</div>
        </div>
      `;

      dom.masterMathWorkingContent.innerHTML = masterHtml;
    }

    // 6. Observations Summary Card
    if (dom.obsMathP) dom.obsMathP.textContent = state.p.toString();
    if (dom.obsMathQ) dom.obsMathQ.textContent = state.q.toString();
    if (dom.obsMathNExpr) dom.obsMathNExpr.textContent = `${state.p} × ${state.q} = ${state.n}`;
    if (dom.obsMathPhiExpr) dom.obsMathPhiExpr.textContent = `(${state.p} - 1)(${state.q} - 1) = ${state.phi}`;
    if (dom.obsMathEGcd) dom.obsMathEGcd.textContent = `${state.e}, ${state.phi}`;
    if (dom.obsMathD) dom.obsMathD.textContent = state.d.toString();
    if (dom.obsMathPub) dom.obsMathPub.textContent = `${state.e}, ${state.n}`;
    if (dom.obsMathPriv) dom.obsMathPriv.textContent = `${state.d}, ${state.n}`;

    if (dom.obsMathSignSubst) dom.obsMathSignSubst.textContent = `${state.message}^${state.d} mod ${state.n}`;
    if (dom.obsMathSignVal) dom.obsMathSignVal.textContent = state.signature.toString();
    if (dom.obsMathVerifSubst) dom.obsMathVerifSubst.textContent = `${state.receivedSig}^${state.e} mod ${state.n}`;
    if (dom.obsMathVerifVal) dom.obsMathVerifVal.textContent = state.recoveredMsg.toString();
    if (dom.obsMathCompare) {
      const isVal = (state.verdict === 'VALID');
      dom.obsMathCompare.innerHTML = `Digest Match &rarr; <strong style="color:${isVal ? '#86efac' : '#fca5a5'};">${isVal ? 'VALID' : 'INVALID'}</strong>`;
    }
  }

  // ==========================================
  // ASSESSMENT / QUIZ (10 High-Yield MCQs)
  // ==========================================
  const QUIZ_DATA = [
    {
      id: 1,
      q: 'Why must gcd(e, phi(n)) = 1 in RSA key generation?',
      options: [
        'e must be strictly larger than phi(n).',
        'e and phi(n) must be coprime so that the modular multiplicative inverse d exists (e × d ≡ 1 mod phi(n)).',
        'e must divide phi(n) evenly to avoid remainders.',
        'phi(n) must be a prime number.'
      ],
      correct: 1,
      expl: 'e must be coprime with phi(n) (gcd(e, phi(n)) = 1) so that its modular multiplicative inverse d exists via the Extended Euclidean Algorithm.'
    },
    {
      id: 2,
      q: 'What is the purpose of hashing a message before signing in digital signature systems?',
      options: [
        'To secretly encrypt the message so unintended recipients cannot read it.',
        'To convert arbitrary-length messages into a fixed-length digest, improving signing efficiency and ensuring message integrity.',
        'To expand the message beyond modulus n so that modular arithmetic does not overflow.',
        'To avoid needing a private key during the signing operation.'
      ],
      correct: 1,
      expl: 'Hashing compresses arbitrary-length messages into a fixed-length digest (H(m)), ensuring computational efficiency and cryptographically binding message integrity.'
    },
    {
      id: 3,
      q: 'What is the output digest length of the MD5 hash function?',
      options: [
        '64 bits / 16 hexadecimal characters',
        '128 bits / 32 hexadecimal characters',
        '160 bits / 40 hexadecimal characters',
        '256 bits / 64 hexadecimal characters'
      ],
      correct: 1,
      expl: 'MD5 generates a 128-bit message digest, which is standardly represented as 32 hexadecimal characters.'
    },
    {
      id: 4,
      q: 'What is the output digest length of the SHA-1 hash function?',
      options: [
        '128 bits / 32 hexadecimal characters',
        '160 bits / 40 hexadecimal characters',
        '256 bits / 64 hexadecimal characters',
        '512 bits / 128 hexadecimal characters'
      ],
      correct: 1,
      expl: 'SHA-1 generates a 160-bit message digest, standardly represented as 40 hexadecimal characters.'
    },
    {
      id: 5,
      q: 'What happens if a message is modified in transit after being digitally signed?',
      options: [
        'The public exponent automatically updates itself to accept the modified message.',
        'The receiver recalculated digest will not match the digest represented by the signature, resulting in an INVALID verdict.',
        'The private exponent d is transmitted to the receiver to repair the message.',
        'The signature changes value dynamically to match the altered message.'
      ],
      correct: 1,
      expl: 'Due to the cryptographic hash avalanche effect, even a 1-bit alteration to the message yields an entirely different digest, causing verification to fail immediately.'
    },
    {
      id: 6,
      q: 'Why must the verifier use the EXACT same hash algorithm that the signer used?',
      options: [
        'Because different hash algorithms produce completely different digests of different bit lengths, making valid digest comparison impossible.',
        'Because modulus n changes value whenever a hash algorithm is switched.',
        'Because the signer private key d is dependent on the hash algorithm.',
        'Because primes p and q must match the word size of the hash function.'
      ],
      correct: 0,
      expl: 'MD5 and SHA-1 use entirely different compression functions and produce different output sizes (128 vs 160 bits). Evaluating a SHA-1 signature with MD5 produces an instant mismatch.'
    },
    {
      id: 7,
      q: 'What is the core difference between RSA encryption and an RSA digital signature?',
      options: [
        'Encryption uses symmetric keys; digital signature uses asymmetric keys.',
        'In encryption, the sender uses the recipient\'s public key; in signing, the sender uses their own private key.',
        'In signing, the private key is published openly to all verifiers.',
        'Encryption and signing are mathematically identical and use the same key.'
      ],
      correct: 1,
      expl: 'In encryption, anyone uses the receiver\'s public key (e, n) to encrypt. In digital signatures, only the signer can sign using their private key (d, n).'
    },
    {
      id: 8,
      q: 'How is the RSA modulus n calculated from the chosen prime numbers p and q?',
      options: [
        'n = p + q',
        'n = (p - 1) × (q - 1)',
        'n = p × q',
        'n = (p × q) mod (p - 1)'
      ],
      correct: 2,
      expl: 'The modulus n is the product of the two primes: n = p × q.'
    },
    {
      id: 9,
      q: 'Which formula does the signer compute in an educational RSA digital signature for message m?',
      options: [
        's = m^e mod n',
        's = m^d mod n',
        's = (m × d) mod n',
        's = d^m mod phi(n)'
      ],
      correct: 1,
      expl: 'The signer computes s = m^d mod n using their secret private key exponent d.'
    },
    {
      id: 10,
      q: 'Which security service is NOT provided by a standalone RSA digital signature on a message?',
      options: [
        'Authentication (proving message origin)',
        'Integrity (detecting message tampering)',
        'Non-repudiation (preventing sender denial)',
        'Confidentiality (hiding message content)'
      ],
      correct: 3,
      expl: 'A digital signature provides authenticity, integrity, and non-repudiation, but NOT confidentiality. The message itself is transmitted in plaintext alongside the signature unless separately encrypted.'
    }
  ];

  function initQuiz() {
    if (!dom.quizForm) return;
    dom.quizForm.innerHTML = '';

    QUIZ_DATA.forEach((item, idx) => {
      const card = document.createElement('div');
      card.className = 'quiz-card';
      card.id = `quizCard_${item.id}`;

      let optionsMarkup = '';
      item.options.forEach((opt, optIdx) => {
        optionsMarkup += `
          <label class="quiz-choice-item" for="q_${item.id}_${optIdx}">
            <input type="radio" id="q_${item.id}_${optIdx}" name="quiz_q_${item.id}" value="${optIdx}">
            <span>${opt}</span>
          </label>
        `;
      });

      card.innerHTML = `
        <div class="quiz-card-question">Q${idx + 1}. ${item.q}</div>
        <div class="quiz-choices">${optionsMarkup}</div>
        <div class="quiz-feedback-box" id="quizFb_${item.id}"></div>
      `;

      dom.quizForm.appendChild(card);
    });
  }

  function handleSubmitQuiz() {
    let score = 0;

    QUIZ_DATA.forEach(item => {
      const selected = document.querySelector(`input[name="quiz_q_${item.id}"]:checked`);
      const card = document.getElementById(`quizCard_${item.id}`);
      const fb = document.getElementById(`quizFb_${item.id}`);

      const choices = card.querySelectorAll('.quiz-choice-item');
      choices.forEach(c => c.classList.remove('correct', 'incorrect'));

      if (selected) {
        const val = parseInt(selected.value, 10);
        if (val === item.correct) {
          score++;
          choices[val].classList.add('correct');
          fb.innerHTML = `<strong>✓ Correct!</strong> ${item.expl}`;
          fb.style.borderLeftColor = '#22c55e';
        } else {
          choices[val].classList.add('incorrect');
          choices[item.correct].classList.add('correct');
          fb.innerHTML = `<strong>✕ Incorrect.</strong> ${item.expl}`;
          fb.style.borderLeftColor = '#ef4444';
        }
      } else {
        choices[item.correct].classList.add('correct');
        fb.innerHTML = `<strong>Not answered.</strong> Correct answer: ${item.options[item.correct]}. ${item.expl}`;
        fb.style.borderLeftColor = '#f59e0b';
      }
      fb.classList.add('active');
    });

    const pct = Math.round((score / QUIZ_DATA.length) * 100);
    dom.quizScoreText.textContent = `${score} / ${QUIZ_DATA.length} (${pct}%)`;

    if (score === QUIZ_DATA.length) {
      dom.quizAppraisalText.textContent = 'Flawless! You have mastered RSA key generation, coprimality, MD5/SHA-1 hashing, and signature verification.';
    } else if (score >= 7) {
      dom.quizAppraisalText.textContent = 'Good performance! Review the questions above to solidify your understanding of hashing and signature mechanics.';
    } else {
      dom.quizAppraisalText.textContent = 'Review the Theory and Simulation tabs, then reattempt the quiz.';
    }

    dom.quizScoreBanner.classList.add('active');
    dom.quizScoreBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function handleResetQuiz() {
    initQuiz();
    dom.quizScoreBanner.classList.remove('active');
    window.scrollTo({ top: dom.quizForm.offsetTop - 100, behavior: 'smooth' });
  }

  // ==========================================
  // HELPERS
  // ==========================================
  function showAlert(el, msg, type = 'info') {
    if (!el) return;
    el.className = `sim-alert sim-alert-${type}`;
    el.textContent = msg;
    el.style.display = 'block';
  }

  function hideAlert(el) {
    if (!el) return;
    el.style.display = 'none';
  }

  function renderState() {
    dom.inputP.value = state.p.toString();
    dom.inputQ.value = state.q.toString();
    dom.inputE.value = state.e.toString();
    dom.inputMsg.value = state.message.toString();

    handleSelectHash(state.selectedHash);
    handleGenerateKeys(false);
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
