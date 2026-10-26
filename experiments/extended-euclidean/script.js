document.addEventListener('DOMContentLoaded', () => {
  const inputA = document.getElementById('inputA');
  const inputB = document.getElementById('inputB');
  const btnCalculate = document.getElementById('btnCalculate');
  const btnClear = document.getElementById('btnClear');
  const errorMessage = document.getElementById('errorMessage');
  const resultsContainer = document.getElementById('resultsContainer');
  const initialMessage = document.getElementById('initialMessage');
  const resultGcd = document.getElementById('resultGcd');
  const resultX = document.getElementById('resultX');
  const resultY = document.getElementById('resultY');
  const bezoutVerification = document.getElementById('bezoutVerification');
  const verificationStatus = document.getElementById('verificationStatus');
  const bezoutCard = document.getElementById('bezoutCard');
  const stepsTableBody = document.getElementById('stepsTableBody');
  const coeffTableBody = document.getElementById('coeffTableBody');
  const modularInverseSection = document.getElementById('modularInverseSection');
  const modularInverseContent = document.getElementById('modularInverseContent');

  // Quiz elements
  const quizForm = document.getElementById('quizForm');
  const btnSubmitQuiz = document.getElementById('btnSubmitQuiz');
  const quizScore = document.getElementById('quizScore');

  // Extended Euclidean Algorithm implementation
  function extendedEuclidean(a, b) {
    // Store original values for coefficient adjustment
    const originalA = a;
    const originalB = b;

    // Work with absolute values for the algorithm
    a = Math.abs(a);
    b = Math.abs(b);

    // Handle special cases
    if (a === 0 && b === 0) {
      return { gcd: 0, x: 0, y: 0, steps: [], coeffs: [], error: 'GCD(0, 0) is undefined' };
    }
    if (a === 0) {
      return { gcd: b, x: 0, y: originalB >= 0 ? 1 : -1, steps: [], coeffs: [{ r: b, x: 0, y: originalB >= 0 ? 1 : -1, check: b }] };
    }
    if (b === 0) {
      return { gcd: a, x: originalA >= 0 ? 1 : -1, y: 0, steps: [], coeffs: [{ r: a, x: originalA >= 0 ? 1 : -1, y: 0, check: a }] };
    }

    // Initialize for iterative algorithm
    let old_r = a, r = b;
    let old_x = 1, x = 0;
    let old_y = 0, y = 1;

    // Store steps for display
    const steps = [];
    const coeffs = [];

    // Record initial state
    coeffs.push({ r: old_r, x: old_x, y: old_y, check: originalA * old_x + originalB * old_y });
    coeffs.push({ r: r, x: x, y: y, check: originalA * x + originalB * y });

    let stepNum = 0;

    while (r !== 0) {
      stepNum++;
      const quotient = Math.floor(old_r / r);
      const remainder = old_r - quotient * r;

      // Store division step
      steps.push({
        step: stepNum,
        dividend: old_r,
        divisor: r,
        quotient: quotient,
        remainder: remainder
      });

      // Update coefficients
      const new_x = old_x - quotient * x;
      const new_y = old_y - quotient * y;

      // Shift values
      old_r = r;
      r = remainder;
      old_x = x;
      x = new_x;
      old_y = y;
      y = new_y;

      // Record coefficient state
      coeffs.push({ r: old_r, x: old_x, y: old_y, check: originalA * old_x + originalB * old_y });
    }

    // The iterative algorithm tracks coefficients for |a| and |b|. Convert
    // every row to the original signed inputs so each row's coefficients and
    // displayed check satisfy originalA * x + originalB * y = r.
    const signA = originalA < 0 ? -1 : 1;
    const signB = originalB < 0 ? -1 : 1;
    const finalX = old_x * signA;
    const finalY = old_y * signB;

    coeffs.forEach((coeff) => {
      coeff.x *= signA;
      coeff.y *= signB;
      coeff.check = originalA * coeff.x + originalB * coeff.y;
    });

    return { gcd: old_r, x: finalX, y: finalY, steps, coeffs };
  }

  // Input validation
  function validateInputs(aStr, bStr) {
    if (aStr.trim() === '' || bStr.trim() === '') {
      return { valid: false, error: 'Please enter both integers.' };
    }

    // Check for non-integer values (decimals, scientific notation, etc.)
    if (!/^-?\d+$/.test(aStr.trim()) || !/^-?\d+$/.test(bStr.trim())) {
      return { valid: false, error: 'Please enter valid integers only (no decimals, fractions, or special characters).' };
    }

    const a = parseInt(aStr, 10);
    const b = parseInt(bStr, 10);

    // Check for safe integer range (JavaScript safe integers)
    if (!Number.isSafeInteger(a) || !Number.isSafeInteger(b)) {
      return { valid: false, error: 'Integers must be within safe range (±9,007,199,254,740,991).' };
    }

    return { valid: true, a, b };
  }

  // Format number for display
  function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  // Display results
  function displayResults(data, a, b) {
    const { gcd, x, y, steps, coeffs } = data;

    // Show results container
    resultsContainer.style.display = 'block';
    initialMessage.style.display = 'none';

    // Results summary
    resultGcd.textContent = formatNumber(gcd);
    resultX.textContent = formatNumber(x);
    resultY.textContent = formatNumber(y);

    // Bézout's Identity proof card — every value is derived from this calculation.
    const aFormatted = formatNumber(a);
    const bFormatted = formatNumber(b);
    const xFormatted = formatNumber(x);
    const yFormatted = formatNumber(y);
    const gcdFormatted = formatNumber(gcd);

    const axProduct = a * x;
    const byProduct = b * y;
    const computed = axProduct + byProduct;
    // formatNumber assumes safe integers; fall back to plain text for overflow.
    const proofNum = (value) => (Number.isSafeInteger(value) ? formatNumber(value) : String(value));
    const computedFormatted = proofNum(computed);
    const axFormatted = proofNum(axProduct);
    const byFormatted = proofNum(byProduct);
    const verified = computed === gcd;

    // Parenthesise any negative factor so the equation reads unambiguously.
    const wrapNeg = (value) => (value < 0 ? `(${formatNumber(value)})` : formatNumber(value));
    const aExpr = `${wrapNeg(a)} &times; (${xFormatted})`;
    const bExpr = `${wrapNeg(b)} &times; (${yFormatted})`;

    bezoutVerification.innerHTML = `
      <div class="proof-card__equation">
        <span class="proof-term">${aExpr}</span>
        <span class="proof-op">+</span>
        <span class="proof-term">${bExpr}</span>
        <span class="proof-op">=</span>
        <span class="proof-result">${computedFormatted}</span>
        <span class="proof-result-tag">B&eacute;zout result</span>
      </div>
      <dl class="proof-grid">
        <div class="proof-row">
          <dt class="proof-row__label">a &times; x</dt>
          <dd class="proof-row__expr">${aExpr}</dd>
          <dd class="proof-row__value">${axFormatted}</dd>
        </div>
        <div class="proof-row">
          <dt class="proof-row__label">b &times; y</dt>
          <dd class="proof-row__expr">${bExpr}</dd>
          <dd class="proof-row__value">${byFormatted}</dd>
        </div>
        <div class="proof-row proof-row--sum">
          <dt class="proof-row__label">Sum</dt>
          <dd class="proof-row__expr">(${axFormatted}) + (${byFormatted})</dd>
          <dd class="proof-row__value">${computedFormatted}</dd>
        </div>
      </dl>
      <div class="proof-compare">
        <span>a &times; x + b &times; y = <strong>${computedFormatted}</strong></span>
        <span class="proof-compare__sep">vs</span>
        <span>gcd(${aFormatted}, ${bFormatted}) = <strong>${gcdFormatted}</strong></span>
      </div>
    `;

    // Success / warning state.
    if (bezoutCard) bezoutCard.dataset.state = verified ? 'verified' : 'failed';

    if (verified) {
      verificationStatus.setAttribute('role', 'status');
      verificationStatus.innerHTML = `
        <span class="proof-badge proof-badge--success">&#10003; Identity verified</span>
        <p class="proof-note">
          Because <span class="proof-mono">a &times; x + b &times; y</span> equals
          <span class="proof-mono">gcd(${aFormatted}, ${bFormatted})</span>, the B&eacute;zout coefficients
          <span class="proof-mono">x = ${xFormatted}</span> and <span class="proof-mono">y = ${yFormatted}</span> are correct.
        </p>
        ${steps.length > 0 ? '<p class="proof-link">&#8627; Matches the GCD circled in the steps table below.</p>' : ''}
      `;
    } else {
      verificationStatus.setAttribute('role', 'alert');
      verificationStatus.innerHTML = `
        <span class="proof-badge proof-badge--error">&#9888; Identity not verified</span>
        <p class="proof-note">
          <span class="proof-mono">a &times; x + b &times; y</span> evaluates to
          <span class="proof-mono">${computedFormatted}</span>, which does not equal
          <span class="proof-mono">gcd(${aFormatted}, ${bFormatted}) = ${gcdFormatted}</span>.
          The displayed coefficients are not valid for these inputs.
        </p>
      `;
    }

    // Steps table
    stepsTableBody.innerHTML = '';
    steps.forEach(step => {
      const row = document.createElement('tr');
      row.style.background = step.step % 2 === 0 ? 'var(--color-surface-muted)' : 'var(--color-surface)';
      row.innerHTML = `
        <td data-col="step" style="padding: 10px; border: 1px solid var(--color-border); text-align: center;">${step.step}</td>
        <td data-col="dividend" style="padding: 10px; border: 1px solid var(--color-border); text-align: right; font-family: 'JetBrains Mono', monospace;">${formatNumber(step.dividend)}</td>
        <td data-col="divisor" style="padding: 10px; border: 1px solid var(--color-border); text-align: right; font-family: 'JetBrains Mono', monospace;">${formatNumber(step.divisor)}</td>
        <td data-col="quotient" style="padding: 10px; border: 1px solid var(--color-border); text-align: right; font-family: 'JetBrains Mono', monospace;">${formatNumber(step.quotient)}</td>
        <td data-col="remainder" style="padding: 10px; border: 1px solid var(--color-border); text-align: right; font-family: 'JetBrains Mono', monospace;">${formatNumber(step.remainder)}</td>
      `;
      stepsTableBody.appendChild(row);
    });

    // Draw the diagonal transition arrows and the GCD ring for the new table.
    renderStepsVisualization();

    // Coefficients table
    coeffTableBody.innerHTML = '';
    coeffs.forEach((coeff, index) => {
      const row = document.createElement('tr');
      row.style.background = index % 2 === 0 ? 'var(--color-surface-muted)' : 'var(--color-surface)';
      // Highlight the final row (GCD row)
      if (index === coeffs.length - 1) {
        row.style.background = 'rgba(76, 140, 232, 0.15)';
        row.style.fontWeight = 'bold';
      }
      const stepLabel = index === 0 ? 'Init (a)' : (index === 1 ? 'Init (b)' : `Step ${index - 1}`);
      row.innerHTML = `
        <td style="padding: 10px; border: 1px solid var(--color-border); text-align: center;">${stepLabel}</td>
        <td style="padding: 10px; border: 1px solid var(--color-border); text-align: right; font-family: 'JetBrains Mono', monospace;">${formatNumber(coeff.r)}</td>
        <td style="padding: 10px; border: 1px solid var(--color-border); text-align: right; font-family: 'JetBrains Mono', monospace;">${formatNumber(coeff.x)}</td>
        <td style="padding: 10px; border: 1px solid var(--color-border); text-align: right; font-family: 'JetBrains Mono', monospace;">${formatNumber(coeff.y)}</td>
        <td style="padding: 10px; border: 1px solid var(--color-border); text-align: right; font-family: 'JetBrains Mono', monospace;">${formatNumber(coeff.check)}</td>
      `;
      coeffTableBody.appendChild(row);
    });

    // Modular inverse section
    // An inverse of u modulo m exists iff gcd(u, m) = 1 and m > 1.
    // A zero modulus is never evaluated (u % 0 is NaN); modulus 1 is trivial.
    const modA = Math.abs(a);
    const modB = Math.abs(b);
    const modNorm = (value, modulus) => ((value % modulus) + modulus) % modulus;

    const inverseCard = (heading, symbol, coeffSymbol, target, coeff, modulus) => {
      const box = 'padding: 12px; background: var(--color-surface-muted); border-radius: var(--radius-sm);';
      if (modulus === 0) {
        return `<div style="${box}">
          <strong>${heading}</strong><br>
          <span style="color: var(--color-text-muted);">Not defined: the modulus is 0, so there is no modular inverse.</span>
        </div>`;
      }
      if (modulus === 1) {
        return `<div style="${box}">
          <strong>${heading}</strong><br>
          <span style="color: var(--color-text-muted);">Not defined for modulus 1 (the trivial ring).</span>
        </div>`;
      }
      const value = modNorm(coeff, modulus);
      const check = modNorm(target * value, modulus);
      return `<div style="${box}">
          <strong>${heading}</strong><br>
          ${symbol} &equiv; ${coeffSymbol} (mod ${formatNumber(modulus)})<br>
          ${symbol} &equiv; ${formatNumber(coeff)} (mod ${formatNumber(modulus)})<br>
          <strong>${symbol} = ${formatNumber(value)}</strong>
          <div style="margin-top: 8px; font-size: var(--font-size-sm); color: var(--color-text-muted);">
            Verification: ${formatNumber(target)} &times; ${formatNumber(value)} &equiv; ${formatNumber(check)} (mod ${formatNumber(modulus)})
          </div>
        </div>`;
    };

    if (gcd === 1) {
      modularInverseSection.style.display = 'block';
      modularInverseContent.innerHTML = `
        <p><strong>Since gcd(${aFormatted}, ${bFormatted}) = 1, modular inverses exist for moduli greater than 1:</strong></p>
        <div style="display: grid; gap: 12px; margin-top: 12px;">
          ${inverseCard('Inverse of a modulo b', 'a⁻¹', 'x', a, x, modB)}
          ${inverseCard('Inverse of b modulo a', 'b⁻¹', 'y', b, y, modA)}
        </div>
        <p style="margin-top: 16px; font-size: var(--font-size-sm); color: var(--color-text-muted);">
          <em>Note:</em> Negative B&eacute;zout coefficients are converted to their positive modular equivalents.
          The inverse is the unique integer in [0, modulus-1] satisfying the congruence when the modulus is greater than 1.
          A modulus of 0 is undefined; modulus 1 is the trivial ring.
        </p>
      `;
    } else {
      modularInverseSection.style.display = 'block';
      modularInverseContent.innerHTML = `
        <p><strong>Since gcd(${aFormatted}, ${bFormatted}) = ${gcdFormatted} ≠ 1, modular inverses do NOT exist.</strong></p>
        <p style="margin-top: 12px;">A modular inverse of <code>a</code> modulo <code>b</code> exists only when <code>gcd(a, b) = 1</code> (i.e., when <code>a</code> and <code>b</code> are coprime).</p>
        <p>Here, <code>gcd(${aFormatted}, ${bFormatted}) = ${gcdFormatted}</code>, so <code>a</code> and <code>b</code> share a common factor of ${gcdFormatted}.</p>
        <p style="margin-top: 8px; font-size: var(--font-size-sm); color: var(--color-text-muted);">
          <em>Mathematical reason:</em> If <code>gcd(a, b) = d > 1</code>, then <code>a = d·a'</code> and <code>b = d·b'</code>.
          Any linear combination <code>ax + by = d(a'x + b'y)</code> is a multiple of <code>d</code>,
          so it can never equal 1. Thus no integer <code>x</code> satisfies <code>ax ≡ 1 (mod b)</code>.
        </p>
      `;
    }
  }

  // ---------------------------------------------------------------------------
  // Euclidean Algorithm Steps table visualization
  //
  // Purely presentational: it draws diagonal transition arrows between
  // consecutive rows and rings the final step's divisor (the GCD). It reads
  // the rendered <table id="stepsTable"> and never touches the EEA / Bézout
  // calculation logic above.
  // ---------------------------------------------------------------------------
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const STEPS_ARROW_DIVISOR = '#7fb2f0';   // Divisor -> next Dividend
  const STEPS_ARROW_REMAINDER = '#f5a623'; // Remainder -> next Divisor
  const STEPS_GCD_COLOR = '#2ed573';       // GCD ring
  const stepsScroll = document.getElementById('stepsScroll');
  const stepsArrows = document.getElementById('stepsArrows');

  let stepsVizPending = false;

  // Coalesce high-frequency refresh requests (e.g. resize) into one frame.
  function scheduleStepsVisualization() {
    if (stepsVizPending) return;
    stepsVizPending = true;
    const run = () => {
      stepsVizPending = false;
      renderStepsVisualization();
    };
    // Background tabs never run rAF callbacks, so fall back to a direct call.
    if (typeof requestAnimationFrame === 'function' && document.visibilityState === 'visible') {
      requestAnimationFrame(run);
    } else {
      run();
    }
  }

  // Bounding box of a cell's actual text (falls back to the cell box).
  function stepsTextBox(cell) {
    if (!cell) return null;
    const range = document.createRange();
    range.selectNodeContents(cell);
    const rect = range.getBoundingClientRect();
    if (rect && (rect.width > 0 || rect.height > 0)) return rect;
    return cell.getBoundingClientRect();
  }

  // Convert a viewport rect into the SVG's own coordinate system.
  function stepsSvgCoords(rect) {
    const base = stepsScroll.getBoundingClientRect();
    return {
      left: rect.left - base.left + stepsScroll.scrollLeft,
      top: rect.top - base.top + stepsScroll.scrollTop,
      width: rect.width,
      height: rect.height
    };
  }

  function stepsSvgEl(name, attrs) {
    const el = document.createElementNS(SVG_NS, name);
    Object.keys(attrs).forEach(key => el.setAttribute(key, attrs[key]));
    return el;
  }

  function renderStepsVisualization() {
    if (!stepsScroll || !stepsArrows || !stepsTableBody) return;

    // When the Simulation panel is hidden every measurement is zero, so wait
    // until it is actually on screen (re-rendered on tab activation / resize).
    if (stepsScroll.offsetParent === null) return;

    const table = document.getElementById('stepsTable');
    const width = table ? table.offsetWidth : stepsScroll.clientWidth;
    const height = table ? table.offsetHeight : stepsScroll.clientHeight;

    stepsArrows.setAttribute('width', width);
    stepsArrows.setAttribute('height', height);
    stepsArrows.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
    stepsArrows.style.width = width + 'px';
    stepsArrows.style.height = height + 'px';

    // Clear the previous drawing.
    while (stepsArrows.firstChild) stepsArrows.removeChild(stepsArrows.firstChild);

    const rows = Array.from(stepsTableBody.rows);
    if (!rows.length) return;

    // Arrowheads, one per transition colour.
    const defs = stepsSvgEl('defs', {});
    [
      { id: 'stepsArrowHeadDivisor', fill: STEPS_ARROW_DIVISOR },
      { id: 'stepsArrowHeadRemainder', fill: STEPS_ARROW_REMAINDER }
    ].forEach(function (marker) {
      const node = stepsSvgEl('marker', {
        id: marker.id,
        markerWidth: 9,
        markerHeight: 9,
        refX: 7,
        refY: 3,
        orient: 'auto',
        markerUnits: 'userSpaceOnUse'
      });
      node.appendChild(stepsSvgEl('path', { d: 'M0,0 L7,3 L0,6 Z', fill: marker.fill }));
      defs.appendChild(node);
    });
    stepsArrows.appendChild(defs);

    // One pair of diagonal transitions per consecutive row pair.
    for (let i = 0; i < rows.length - 1; i++) {
      const nextRow = rows[i + 1];
      drawStepsTransition(
        rows[i].querySelector('[data-col="divisor"]'),
        nextRow.querySelector('[data-col="dividend"]'),
        STEPS_ARROW_DIVISOR,
        'stepsArrowHeadDivisor'
      );
      drawStepsTransition(
        rows[i].querySelector('[data-col="remainder"]'),
        nextRow.querySelector('[data-col="divisor"]'),
        STEPS_ARROW_REMAINDER,
        'stepsArrowHeadRemainder'
      );
    }

    drawStepsGcdRing(rows);
  }

  // Diagonal arrow from just below the source value to just above the target.
  function drawStepsTransition(srcCell, dstCell, color, markerId) {
    const src = stepsTextBox(srcCell);
    const dst = stepsTextBox(dstCell);
    if (!src || !dst) return;

    const s = stepsSvgCoords(src);
    const d = stepsSvgCoords(dst);
    const gap = 4;

    stepsArrows.appendChild(stepsSvgEl('line', {
      x1: s.left + s.width / 2,
      y1: s.top + s.height + gap,
      x2: d.left + d.width / 2,
      y2: d.top - gap,
      stroke: color,
      'stroke-width': 2,
      'stroke-linecap': 'round',
      'marker-end': 'url(#' + markerId + ')'
    }));
  }

  // Ring the GCD: the divisor of the final step (the step whose remainder is 0).
  function drawStepsGcdRing(rows) {
    if (!rows.length) return;

    // The Euclidean algorithm's last step is "a = gcd × q + 0", so the GCD is
    // that step's divisor. (The final zero remainder itself is never ringed.)
    const targetCell = rows[rows.length - 1].querySelector('[data-col="divisor"]');
    if (!targetCell) return;

    const box = stepsSvgCoords(stepsTextBox(targetCell));
    const cx = box.left + box.width / 2;
    const cy = box.top + box.height / 2;
    const rx = box.width / 2 + 7;
    const ry = box.height / 2 + 4;
    const ringTransform = 'rotate(-4 ' + cx + ' ' + cy + ')';

    // Faint outer halo + crisp inner ring = a polished annotation.
    stepsArrows.appendChild(stepsSvgEl('ellipse', {
      cx: cx, cy: cy, rx: rx + 3, ry: ry + 3,
      fill: 'none', stroke: STEPS_GCD_COLOR,
      'stroke-width': 1, opacity: 0.35, transform: ringTransform
    }));
    stepsArrows.appendChild(stepsSvgEl('ellipse', {
      cx: cx, cy: cy, rx: rx, ry: ry,
      fill: 'none', stroke: STEPS_GCD_COLOR,
      'stroke-width': 2.5, opacity: 0.95, transform: ringTransform
    }));
  }

  // Keep the overlay aligned when the layout changes or the panel reappears.
  window.addEventListener('resize', scheduleStepsVisualization);
  window.addEventListener('focus', scheduleStepsVisualization);
  const simulationTabBtn = document.querySelector('.tab-btn[data-tab="simulation"]');
  if (simulationTabBtn) {
    // common.js shows the panel synchronously, so a direct render is safe here.
    simulationTabBtn.addEventListener('click', renderStepsVisualization);
  }

  // Handle calculate button
  btnCalculate.addEventListener('click', () => {
    errorMessage.textContent = '';
    errorMessage.style.display = 'none';

    const validation = validateInputs(inputA.value, inputB.value);

    if (!validation.valid) {
      errorMessage.textContent = validation.error;
      errorMessage.style.display = 'block';
      resultsContainer.style.display = 'none';
      initialMessage.style.display = 'block';
      return;
    }

    const { a, b } = validation;

    // Run algorithm
    const result = extendedEuclidean(a, b);

    if (result.error) {
      errorMessage.textContent = result.error;
      errorMessage.style.display = 'block';
      resultsContainer.style.display = 'none';
      initialMessage.style.display = 'block';
      return;
    }

    displayResults(result, a, b);
  });

  // Handle clear button
  btnClear.addEventListener('click', () => {
    inputA.value = '';
    inputB.value = '';
    errorMessage.textContent = '';
    errorMessage.style.display = 'none';
    resultsContainer.style.display = 'none';
    initialMessage.style.display = 'block';
    inputA.focus();
  });

  // Allow Enter key to trigger calculation
  [inputA, inputB].forEach(input => {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        btnCalculate.click();
      }
    });
  });

  // Quiz functionality
  const quizAnswers = {
    q1: 'b',
    q2: 'b',
    q3: 'b',
    q4: 'b',
    q5: 'b',
    q6: 'b',
    q7: 'a',
    q8: 'a',
    q9: 'a',
    q10: 'a'
  };

  const quizExplanations = {
    q1: {
      correct: 'Correct! The Euclidean Algorithm is a method for finding the greatest common divisor (GCD) of two integers.',
      incorrect: 'The Euclidean Algorithm finds the GCD of two integers. Finding modular inverses requires the Extended Euclidean Algorithm.'
    },
    q2: {
      correct: 'Correct! The Extended Euclidean Algorithm computes Bézout coefficients x and y such that ax + by = gcd(a, b).',
      incorrect: 'The Extended Euclidean Algorithm finds Bézout coefficients (x, y) satisfying ax + by = gcd(a, b). The LCM and prime factorization are separate computations.'
    },
    q3: {
      correct: 'Correct! When gcd(a, b) = 1, Bézout\'s identity gives ax + by = 1, so ax ≡ 1 (mod b), making x the modular inverse of a modulo b.',
      incorrect: 'When gcd(a, b) = 1, ax + by = 1 implies ax ≡ 1 (mod b), so x (mod b) is the modular inverse of a modulo b.'
    },
    q4: {
      correct: 'Correct! gcd(240, 46) = 2. The steps are: 240 = 46×5 + 10, 46 = 10×4 + 6, 10 = 6×1 + 4, 6 = 4×1 + 2, 4 = 2×2 + 0.',
      incorrect: 'gcd(240, 46) = 2. You can verify this using the simulation with a=240, b=46.'
    },
    q5: {
      correct: 'Correct! The Euclidean Algorithm terminates when the remainder becomes zero. The last non-zero remainder is the GCD.',
      incorrect: 'The algorithm terminates when the remainder becomes zero. The divisor at that step (the last non-zero remainder) is the GCD.'
    },
    q6: {
      correct: 'Correct! A modular inverse exists only when the numbers are coprime (gcd = 1). If gcd(a, b) ≠ 1, no modular inverse exists.',
      incorrect: 'A modular inverse of a modulo b exists if and only if gcd(a, b) = 1. If they share a common factor > 1, no inverse exists.'
    },
    q7: {
      correct: 'Correct! gcd(17, 5) = 1 since 17 is prime and not a multiple of 5. The steps: 17 = 5×3 + 2, 5 = 2×2 + 1, 2 = 1×2 + 0.',
      incorrect: 'gcd(17, 5) = 1. Since 17 is prime and not divisible by 5, their GCD is 1.'
    },
    q8: {
      correct: 'Correct! The first step is 240 = 46×5 + 10, so the quotient is 5 and the remainder is 10.',
      incorrect: 'The first division is 240 = 46×5 + 10, giving quotient 5 and remainder 10.'
    },
    q9: {
      correct: 'Correct! 240×(-9) + 46×47 = -2160 + 2162 = 2, which equals gcd(240, 46).',
      incorrect: 'Bézout\'s identity is a×x + b×y = gcd(a, b). Substituting: 240×(-9) + 46×47 = -2160 + 2162 = 2 = gcd(240, 46).'
    },
    q10: {
      correct: 'Correct! 3×4 = 12 ≡ 1 (mod 11), so 4 is the modular inverse of 3 modulo 11.',
      incorrect: 'The inverse x satisfies 3x ≡ 1 (mod 11). Since 3×4 = 12 ≡ 1 (mod 11), the inverse is 4.'
    }
  };

  if (btnSubmitQuiz) {
    btnSubmitQuiz.addEventListener('click', () => {
      let score = 0;
      const total = Object.keys(quizAnswers).length;

      Object.keys(quizAnswers).forEach(key => {
        const selected = quizForm.querySelector(`input[name="${key}"]:checked`);
        const feedbackEl = document.getElementById(`feedback${key.slice(1)}`);
        const questionDiv = quizForm.querySelector(`[data-q="${key.slice(1)}"]`);

        if (!feedbackEl || !questionDiv) {
          console.warn(`Quiz elements not found for ${key}`);
          return;
        }

        if (selected) {
          if (selected.value === quizAnswers[key]) {
            score++;
            feedbackEl.innerHTML = `<span style="color: #15803d;">✓ ${quizExplanations[key].correct}</span>`;
            questionDiv.style.borderLeft = '3px solid #15803d';
          } else {
            feedbackEl.innerHTML = `<span style="color: #b91c1c;">✗ ${quizExplanations[key].incorrect}</span>`;
            questionDiv.style.borderLeft = '3px solid #b91c1c';
          }
          feedbackEl.style.display = 'block';
        } else {
          feedbackEl.innerHTML = `<span style="color: #b91c1c;">✗ No answer selected. ${quizExplanations[key].incorrect}</span>`;
          feedbackEl.style.display = 'block';
          questionDiv.style.borderLeft = '3px solid #b91c1c';
        }
      });

    const percentage = Math.round((score / total) * 100);
    let message = `Score: ${score}/${total} (${percentage}%)`;
    if (percentage >= 80) {
      message += ' - Excellent!';
      quizScore.style.color = '#15803d';
    } else if (percentage >= 60) {
      message += ' - Good effort!';
      quizScore.style.color = '#ca8a04';
    } else {
      message += ' - Review the theory and try again.';
      quizScore.style.color = '#b91c1c';
    }
    quizScore.textContent = message;
  });
}
});