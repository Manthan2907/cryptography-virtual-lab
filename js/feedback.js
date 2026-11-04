/**
 * Cryptography Virtual Lab - Universal Feedback Component
 * Standardized across all experiments with Roll Number Auto-Fetch.
 */
(() => {
  // Set to false in future if opening feedback to public / external visitors
  const AUTO_FETCH_STUDENTS = true;

  function getExperimentMeta() {
    const titleEl = document.getElementById('exp-title');
    let title = titleEl ? titleEl.textContent.trim() : document.title.replace(' | Virtual Cryptography Laboratory', '').trim();
    
    // Extract folder name from path (e.g., .../experiments/mac/ or .../experiments/mac/index.html -> 'mac')
    const cleanPath = window.location.pathname.replace(/\/index\.html?$/i, '').replace(/\/+$/, '');
    const pathParts = cleanPath.split('/');
    let slug = pathParts[pathParts.length - 1] || 'general';
    if (slug === '' || slug === 'experiments') slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-');

    if (title === 'Experiment Title' && slug !== 'general') {
      title = slug.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    return { title, slug };
  }

  function initFeedbackTab() {
    const feedbackSection = document.getElementById('feedback');
    if (!feedbackSection) return;

    const { title, slug } = getExperimentMeta();

    // Render standardized feedback form
    feedbackSection.innerHTML = `
      <div class="feedback-card">
        <div class="feedback-header">
          <div class="feedback-badge"><span class="lock-icon">&#128274;</span> End-to-End Encrypted</div>
          <h2>Feedback for ${title}</h2>
          <p class="feedback-subtext">
            Please share your feedback regarding this experiment simulation. Submissions are encrypted with <strong>RSA-2048 Public Key Cryptography</strong> in your browser before transmission.
          </p>
        </div>

        <form id="expFeedbackForm" class="feedback-form" novalidate>
          <div class="feedback-row">
            <div class="feedback-field">
              <label for="fbRollNo">Roll No / Student ID <span class="required">*</span></label>
              <input type="text" id="fbRollNo" name="rollNo" placeholder="e.g. 10701 or 01" autocomplete="off" required>
              <div id="fbRollHint" class="feedback-hint">Enter your roll number to auto-fill your verified name</div>
            </div>

            <div class="feedback-field">
              <label for="fbStudentName">Full Name <span class="required">*</span></label>
              <div class="input-with-badge">
                <input type="text" id="fbStudentName" name="studentName" placeholder="Auto-populated upon roll number entry" ${AUTO_FETCH_STUDENTS ? 'readonly' : ''} required>
                <span id="fbVerifiedBadge" class="verified-tag" hidden>&#10003; Verified</span>
              </div>
            </div>
          </div>

          <div class="feedback-field">
            <label>Overall Experiment Rating <span class="required">*</span></label>
            <div class="star-rating" id="fbStarRating" role="radiogroup" aria-label="Overall experiment rating">
              <button type="button" class="star-btn" data-value="1" title="1 - Needs Improvement" aria-label="1 star">&#9733;</button>
              <button type="button" class="star-btn" data-value="2" title="2 - Fair" aria-label="2 stars">&#9733;</button>
              <button type="button" class="star-btn" data-value="3" title="3 - Good" aria-label="3 stars">&#9733;</button>
              <button type="button" class="star-btn" data-value="4" title="4 - Very Good" aria-label="4 stars">&#9733;</button>
              <button type="button" class="star-btn" data-value="5" title="5 - Excellent" aria-label="5 stars">&#9733;</button>
              <span class="star-rating-label" id="starRatingLabel">Select rating</span>
            </div>
            <input type="hidden" id="fbRatingVal" name="rating" value="0">
          </div>

          <div class="feedback-row">
            <div class="feedback-field">
              <label for="fbClarity">Concept Clarity</label>
              <select id="fbClarity" name="clarity">
                <option value="5">5 - Exceptionally Clear</option>
                <option value="4" selected>4 - Clear & Easy to Follow</option>
                <option value="3">3 - Moderately Clear</option>
                <option value="2">2 - Needs More Theory</option>
                <option value="1">1 - Difficult to Understand</option>
              </select>
            </div>
            <div class="feedback-field">
              <label for="fbEase">Simulation Ease of Use</label>
              <select id="fbEase" name="ease">
                <option value="5">5 - Highly Intuitive & Responsive</option>
                <option value="4" selected>4 - Easy to Operate</option>
                <option value="3">3 - Acceptable</option>
                <option value="2">2 - Minor Usability Issues</option>
                <option value="1">1 - Difficult to Use</option>
              </select>
            </div>
          </div>

          <div class="feedback-field">
            <label for="fbComments">Comments, Observations & Suggestions <span class="required">*</span></label>
            <textarea id="fbComments" name="comments" rows="4" placeholder="What did you learn from this simulation? Any suggestions for improvement?" required></textarea>
          </div>

          <div class="feedback-actions">
            <button type="submit" id="fbSubmitBtn" class="feedback-submit-btn">
              <span class="btn-text">Encrypt &amp; Submit Feedback</span>
              <span class="btn-spinner" hidden></span>
            </button>
          </div>

          <div id="fbStatus" class="feedback-status" hidden aria-live="polite"></div>
        </form>
      </div>
    `;

    setupFormInteractivity(slug, title);
  }

  function setupFormInteractivity(slug, title) {
    const starBtns = document.querySelectorAll('#fbStarRating .star-btn');
    const ratingInput = document.getElementById('fbRatingVal');
    const labelSpan = document.getElementById('starRatingLabel');
    const form = document.getElementById('expFeedbackForm');
    const statusDiv = document.getElementById('fbStatus');
    const submitBtn = document.getElementById('fbSubmitBtn');

    const rollInput = document.getElementById('fbRollNo');
    const nameInput = document.getElementById('fbStudentName');
    const verifiedBadge = document.getElementById('fbVerifiedBadge');
    const rollHint = document.getElementById('fbRollHint');

    let verifiedFullRoll = '';

    // Live Roll Number Lookup
    function lookupStudent() {
      const query = rollInput.value.trim();
      if (!query) {
        if (AUTO_FETCH_STUDENTS) {
          nameInput.value = '';
          nameInput.readOnly = true;
        }
        nameInput.classList.remove('input-verified');
        verifiedBadge.hidden = true;
        rollHint.textContent = 'Enter your roll number to auto-fill your verified name';
        rollHint.className = 'feedback-hint';
        verifiedFullRoll = '';
        return;
      }

      const roster = window.STUDENTS_ROSTER;
      const student = (roster && typeof roster.findStudent === 'function')
        ? roster.findStudent(query)
        : null;

      if (student) {
        nameInput.value = student.name;
        nameInput.classList.add('input-verified');
        nameInput.readOnly = true;
        verifiedBadge.hidden = false;
        verifiedBadge.innerHTML = '&#10003; Verified';
        rollHint.innerHTML = `Identified: <strong>${student.name}</strong> (Roll: ${student.fullRoll})`;
        rollHint.className = 'feedback-hint hint-success';
        verifiedFullRoll = student.fullRoll;
      } else {
        if (AUTO_FETCH_STUDENTS) {
          nameInput.value = '';
          nameInput.classList.remove('input-verified');
          nameInput.readOnly = true;
          verifiedBadge.hidden = true;
          verifiedFullRoll = '';

          if (query.length >= 2) {
            rollHint.textContent = 'Roll number not found in class roster. Please check your roll number.';
            rollHint.className = 'feedback-hint hint-error';
          } else {
            rollHint.textContent = 'Enter your roll number to auto-fill your verified name';
            rollHint.className = 'feedback-hint';
          }
        } else {
          nameInput.readOnly = false;
          verifiedBadge.hidden = true;
          rollHint.textContent = '';
        }
      }
    }

    if (rollInput) {
      rollInput.addEventListener('input', lookupStudent);
      rollInput.addEventListener('change', lookupStudent);
    }

    const starLabels = {
      1: '1 - Needs Improvement',
      2: '2 - Fair',
      3: '3 - Good',
      4: '4 - Very Good',
      5: '5 - Excellent'
    };

    function updateStars(val) {
      starBtns.forEach(btn => {
        const btnVal = parseInt(btn.dataset.value, 10);
        btn.classList.toggle('active', btnVal <= val);
      });
      labelSpan.textContent = starLabels[val] || 'Select rating';
    }

    starBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const val = parseInt(btn.dataset.value, 10);
        ratingInput.value = val;
        updateStars(val);
      });

      btn.addEventListener('mouseenter', () => {
        const val = parseInt(btn.dataset.value, 10);
        updateStars(val);
      });
    });

    const starContainer = document.getElementById('fbStarRating');
    if (starContainer) {
      starContainer.addEventListener('mouseleave', () => {
        const currentVal = parseInt(ratingInput.value, 10) || 0;
        updateStars(currentVal);
      });
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      const rollNo = rollInput.value.trim();
      const name = nameInput.value.trim();
      const rating = parseInt(ratingInput.value, 10) || 0;
      const clarity = document.getElementById('fbClarity').value;
      const ease = document.getElementById('fbEase').value;
      const comments = document.getElementById('fbComments').value.trim();

      if (AUTO_FETCH_STUDENTS && !name) {
        showStatus('Please enter a valid class roll number so your name is verified.', 'error');
        rollInput.focus();
        return;
      }

      if (!name || !rollNo || !comments) {
        showStatus('Please fill out all required fields marked with *.', 'error');
        return;
      }

      if (rating < 1 || rating > 5) {
        showStatus('Please select an overall star rating (1 to 5).', 'error');
        return;
      }

      if (typeof CryptoFeedback === 'undefined') {
        showStatus('Encryption module failed to load. Please refresh and try again.', 'error');
        return;
      }

      // Standardize roll number to full 5 digits if verified
      const finalRoll = verifiedFullRoll || rollNo;

      // Prepare feedback object
      const feedbackPayload = {
        experimentSlug: slug,
        experimentTitle: title,
        studentName: name,
        rollNo: finalRoll,
        rating: rating,
        clarityRating: clarity,
        easeRating: ease,
        comments: comments,
        submittedAt: new Date().toISOString(),
        userAgent: navigator.userAgent
      };

      // Set loading state
      submitBtn.disabled = true;
      submitBtn.querySelector('.btn-text').textContent = 'Encrypting & Transmitting...';
      showStatus('Encrypting feedback using RSA-2048 public key...', 'info');

      try {
        await CryptoFeedback.submit(slug, feedbackPayload);
        showStatus(`Thank you, ${name}! Your feedback has been encrypted and successfully recorded.`, 'success');
        form.reset();
        ratingInput.value = '0';
        updateStars(0);
        lookupStudent();
      } catch (err) {
        console.error('Feedback submit error:', err);
        showStatus('Failed to transmit feedback. Please check your internet connection.', 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.querySelector('.btn-text').textContent = 'Encrypt & Submit Feedback';
      }
    });

    function showStatus(msg, type) {
      statusDiv.hidden = false;
      statusDiv.className = `feedback-status ${type}`;
      statusDiv.innerHTML = msg;
    }
  }

  // Auto-init when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFeedbackTab);
  } else {
    initFeedbackTab();
  }
})();
