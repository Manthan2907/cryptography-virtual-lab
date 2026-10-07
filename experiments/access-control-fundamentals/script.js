document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnEvalAccess');
  const identityInput = document.getElementById('subIdentity');
  const output = document.getElementById('accessOutput');
  const auditLog = document.getElementById('auditLog');

  if (btn && output) {
    btn.addEventListener('click', () => {

      const loadingOverlay = document.getElementById('loadingOverlay');
      if (loadingOverlay) loadingOverlay.style.display = 'flex';
      btn.disabled = true;
      btn.textContent = 'Evaluating...';

      setTimeout(() => {
        if (loadingOverlay) loadingOverlay.style.display = 'none';
        btn.disabled = false;
        btn.textContent = 'Evaluate Access Request';

        // XSS prevention
        const escapeHTML = (str) => str.replace(/[&<>'"]/g,
          tag => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[tag] || tag)
        );

        const rawIdentity = identityInput ? identityInput.value.trim() || 'Unknown' : 'Unknown';
        const identity = escapeHTML(rawIdentity);

        const getRadio = (name, fallback) => {
          const el = document.querySelector(`input[name="${name}"]:checked`);
          return el ? el.value : fallback;
        };

        const role = getRadio('subRole', 'student');
        const obj = getRadio('targetObj', 'public_syllabus');
        const op = getRadio('opType', 'read');
        const acModel = getRadio('acModel', 'rbac');

        let granted = false;
        let reason = '';

        if (acModel === 'dac') {
          // Discretionary Access Control (DAC)
          const dacOwners = {
            'public_syllabus': 'alice',
            'lab_assignment': 'bob',
            'system_config': 'admin',
            'system_kernel': 'root'
          };
          const owner = dacOwners[obj];
          const lowerIdentity = identity.toLowerCase();

          if (lowerIdentity === owner) {
            granted = true;
            reason = `DAC: ${identity} is the owner of ${obj}. Full access granted.`;
          } else if (obj === 'public_syllabus' && op === 'read') {
            granted = true;
            reason = `DAC: ACL allows public read access to ${obj}.`;
          } else {
            reason = `DAC: ${identity} is not the owner of ${obj}. Access denied.`;
          }

        } else if (acModel === 'mac') {
          // Mandatory Access Control (MAC)
          const clearanceLevels = { 'admin': 4, 'faculty': 3, 'student': 2, 'guest': 1 };
          const objectLabels = { 'system_kernel': 4, 'system_config': 3, 'lab_assignment': 2, 'public_syllabus': 1 };
          const subjClearance = clearanceLevels[role];
          const objLabel = objectLabels[obj];

          if (op === 'read') {
            granted = subjClearance >= objLabel;
            reason = granted
              ? `MAC: Subject clearance (${role}, Lvl ${subjClearance}) \u2265 Object classification (Lvl ${objLabel}). Read allowed.`
              : `MAC: Subject clearance (${role}, Lvl ${subjClearance}) < Object classification (Lvl ${objLabel}). No Read Up.`;
          } else {
            granted = subjClearance === objLabel;
            reason = granted
              ? `MAC: Subject clearance matches Object classification for ${op}.`
              : `MAC: Exact clearance match required for ${op} (Integrity rule). Lvl ${subjClearance} \u2260 Lvl ${objLabel}.`;
          }

        } else {
          // Role-Based Access Control (RBAC)
          if (role === 'admin') {
            if (obj === 'system_kernel' && op !== 'execute') {
              reason = 'RBAC: Admin can only execute the kernel, not read/write/delete it directly.';
            } else {
              granted = true;
              reason = 'RBAC: Administrator has unrestricted access for this operation.';
            }
          } else if (role === 'faculty') {
            if (obj === 'system_config' || obj === 'system_kernel') {
              granted = (op === 'read' && obj !== 'system_kernel');
              reason = granted
                ? 'RBAC: Faculty allowed read access to configuration.'
                : 'RBAC: Faculty denied access to core system files.';
            } else {
              granted = true;
              reason = 'RBAC: Faculty allowed full access on academic files.';
            }
          } else if (role === 'student') {
            if (obj === 'public_syllabus') {
              granted = (op === 'read');
              reason = granted
                ? 'RBAC: Students can read syllabus.'
                : 'RBAC: Students cannot modify syllabus.';
            } else {
              reason = 'RBAC: Students have no access to restricted resources.';
            }
          } else {
            // guest
            if (obj === 'public_syllabus' && op === 'read') {
              granted = true;
              reason = 'RBAC: Public syllabus accessible to guests.';
            } else {
              reason = 'RBAC: Guests denied access to restricted resources.';
            }
          }
        }

        const timestamp = new Date().toLocaleTimeString();
        const modelName = acModel.toUpperCase();

        // Result output
        const statusIcon = granted ? '\u2705' : '\u274C';
        const statusText = granted ? 'ACCESS GRANTED' : 'ACCESS DENIED';
        const statusColor = granted ? '#4caf50' : '#f44336';

        output.innerHTML = `
          <p style="font-size:1.2rem; margin-bottom:8px;"><span style="color:${statusColor}; font-weight:bold;">${statusIcon} ${statusText}</span></p>
          <p><strong>Model:</strong> ${modelName} &nbsp;|&nbsp; <strong>Subject:</strong> ${identity} (${role.toUpperCase()}) &nbsp;|&nbsp; <strong>Object:</strong> ${obj} &nbsp;|&nbsp; <strong>Op:</strong> ${op.toUpperCase()}</p>
          <p><strong>Policy Reason:</strong> ${reason}</p>
        `;

        // Visualizer
        const visSubjectIcon = document.getElementById('visSubjectIcon');
        const visSubject = document.getElementById('visSubject');
        const visObjectIcon = document.getElementById('visObjectIcon');
        const visObject = document.getElementById('visObject');
        const visOp = document.getElementById('visOp');
        const visLock = document.getElementById('visLock');
        const visLockIcon = document.getElementById('visLockIcon');

        const roleEmojis = { 'guest': '\uD83C\uDF92', 'student': '\uD83C\uDF93', 'faculty': '\uD83D\uDC68\u200D\uD83C\uDFEB', 'admin': '\uD83E\uDDD9\u200D\u2642\uFE0F' };
        const objEmojis = { 'public_syllabus': '\uD83D\uDCDC', 'lab_assignment': '\uD83D\uDCCA', 'system_config': '\u2699\uFE0F', 'system_kernel': '\uD83E\uDDE0' };

        if (visSubjectIcon) visSubjectIcon.textContent = roleEmojis[role] || '\uD83D\uDC64';
        if (visSubject) visSubject.textContent = `${identity} (${role})`;
        if (visObjectIcon) visObjectIcon.textContent = objEmojis[obj] || '\uD83D\uDCC4';
        if (visObject) visObject.textContent = obj;
        if (visOp) visOp.textContent = op.toUpperCase();

        if (visLock && visLockIcon) {
          visLock.style.transform = 'none';
          void visLock.offsetWidth; // force reflow

          if (granted) {
            visLockIcon.textContent = '\uD83D\uDD13';
            visLock.style.color = '#4caf50';
            visLock.style.transform = 'scale(1.2)';
          } else {
            visLockIcon.textContent = '\uD83D\uDD12';
            visLock.style.color = '#f44336';
            visLock.animate([
              { transform: 'translateX(0)' },
              { transform: 'translateX(-12px)' },
              { transform: 'translateX(12px)' },
              { transform: 'translateX(-8px)' },
              { transform: 'translateX(8px)' },
              { transform: 'translateX(0)' }
            ], { duration: 400, easing: 'ease-in-out' });
          }
        }

        // Audit log
        if (auditLog) {
          const logEntry = document.createElement('li');
          logEntry.style.cssText = 'padding: 4px 0; border-bottom: 1px solid var(--color-border, #555); margin-bottom: 4px; color: var(--color-text-muted, #ccc);';
          const logStatus = granted
            ? '<span style="color:#4caf50;">\u2705 GRANTED</span>'
            : '<span style="color:#f44336;">\u274C DENIED</span>';
          logEntry.innerHTML = `[${timestamp}] [${modelName}] ${roleEmojis[role]||''} <strong>${identity}</strong> (${role}) \u2192 ${op.toUpperCase()} on ${objEmojis[obj]||''} <strong>${obj}</strong> \u2192 ${logStatus}`;
          auditLog.prepend(logEntry);
        }
      }, 600);
    });
  }

  // Interactive Quiz Handling
  const quizContainer = document.getElementById('quizContainer');
  if (quizContainer) {
    const questions = quizContainer.querySelectorAll('.quiz-question');
    questions.forEach(q => {
      const options = q.querySelectorAll('.quiz-option-btn');
      const reason = q.querySelector('.quiz-reason');
      const correctIdx = parseInt(q.dataset.correct, 10);
      
      options.forEach(opt => {
        opt.addEventListener('click', () => {
          // disable all options for this question after an answer is selected
          options.forEach(btn => {
            btn.disabled = true;
          });
          
          const chosenIdx = parseInt(opt.dataset.index, 10);
          if (chosenIdx === correctIdx) {
            opt.classList.add('correct');
          } else {
            opt.classList.add('wrong');
            options[correctIdx].classList.add('correct');
          }
          if (reason) reason.hidden = false;
        });
      });
    });
  }
});
