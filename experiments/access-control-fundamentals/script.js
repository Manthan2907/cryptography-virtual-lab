document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnEvalAccess');
  const identityInput = document.getElementById('subIdentity');
  const roleSelect = document.getElementById('subRole');
  const objSelect = document.getElementById('targetObj');
  const opSelect = document.getElementById('opType');
  const output = document.getElementById('accessOutput');
  const auditLog = document.getElementById('auditLog');

  if (btn && roleSelect && objSelect && opSelect && output) {
    btn.addEventListener('click', () => {
      // Security: Escape user inputs to prevent XSS (Cross-Site Scripting)
      const escapeHTML = (str) => str.replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
          }[tag] || tag)
      );

      const rawIdentity = identityInput ? identityInput.value.trim() || 'Unknown' : 'Unknown';
      const identity = escapeHTML(rawIdentity);
      const role = roleSelect.value;
      const obj = objSelect.value;
      const op = opSelect.value;

      const acModelSelect = document.getElementById('acModel');
      const acModel = acModelSelect ? acModelSelect.value : 'rbac';
      
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
          reason = `DAC: Access Control List (ACL) allows public read access to ${obj}.`;
        } else {
          granted = false;
          reason = `DAC: ${identity} is not the owner of ${obj}. Access denied.`;
        }

      } else if (acModel === 'mac') {
        // Mandatory Access Control (MAC)
        const clearanceLevels = { 'admin': 4, 'faculty': 3, 'student': 2, 'guest': 1 };
        const objectLabels = { 'system_kernel': 4, 'system_config': 3, 'lab_assignment': 2, 'public_syllabus': 1 };
        
        const subjClearance = clearanceLevels[role];
        const objLabel = objectLabels[obj];
        
        if (op === 'read') {
          granted = subjClearance >= objLabel; // Read Down
          reason = granted ? `MAC: Subject clearance (${role}) &ge; Object classification.` : `MAC: Subject clearance (${role}) is lower than Object classification.`;
        } else {
          // For simplicity in this lab, modifications require exact clearance match
          granted = subjClearance === objLabel;
          reason = granted ? `MAC: Subject clearance matches Object classification for ${op}.` : `MAC: Exact clearance match required for modification/execution (Integrity rules).`;
        }

      } else {
        // Role-Based Access Control (RBAC)
        if (role === 'admin') {
          if (obj === 'system_kernel' && op !== 'execute') {
             granted = false;
             reason = 'RBAC: Admin can only execute the kernel, not read/write/delete it directly.';
          } else {
             granted = true;
             reason = 'RBAC: Administrator possesses unrestricted access rights for this operation.';
          }
        } else if (role === 'faculty') {
          if (obj === 'system_config' || obj === 'system_kernel') {
            granted = (op === 'read' && obj !== 'system_kernel');
            reason = op === 'read' && obj !== 'system_kernel' ? 'RBAC: Faculty allowed read access to configuration.' : 'RBAC: Faculty denied access to core system files.';
          } else {
            granted = true;
            reason = 'RBAC: Faculty allowed full access on academic files.';
          }
        } else if (role === 'student') {
          if (obj === 'public_syllabus') {
            granted = (op === 'read');
            reason = op === 'read' ? 'RBAC: Students can read syllabus.' : 'RBAC: Students cannot modify syllabus.';
          } else {
            granted = false;
            reason = 'RBAC: Students have no access to restricted resources.';
          }
        } else {
          // guest
          if (obj === 'public_syllabus' && op === 'read') {
            granted = true;
            reason = 'RBAC: Public syllabus accessible to guests.';
          } else {
            granted = false;
            reason = 'RBAC: Guests denied access to restricted resources.';
          }
        }
      }

      const timestamp = new Date().toISOString();
      const statusHtml = granted ? '<span style="color:#15803d; font-weight:bold; font-size:1.1rem;">&#10004; ACCESS GRANTED</span>' : '<span style="color:#b91c1c; font-weight:bold; font-size:1.1rem;">&#10008; ACCESS DENIED</span>';
      const modelName = acModel.toUpperCase();

      output.innerHTML = `
        <p><strong>Evaluation Result:</strong> ${statusHtml}</p>
        <p><strong>Model:</strong> ${modelName} | <strong>Subject:</strong> ${identity} (${role.toUpperCase()})</p>
        <p><strong>Object:</strong> ${obj} | <strong>Operation:</strong> ${op.toUpperCase()}</p>
        <p><strong>Policy Reason:</strong> ${reason}</p>
      `;

      // Update Visualizer
      const visSubject = document.getElementById('visSubject');
      const visObject = document.getElementById('visObject');
      const visOp = document.getElementById('visOp');
      const visLock = document.getElementById('visLock');
      const visLockIcon = document.getElementById('visLockIcon');

      if (visSubject && visObject && visOp && visLock && visLockIcon) {
        visSubject.textContent = `${identity} (${role})`;
        visObject.textContent = obj;
        visOp.textContent = op.toUpperCase();
        
        // Remove animation class to reset
        visLock.style.transform = 'none';
        
        // Force reflow
        void visLock.offsetWidth;

        if (granted) {
          visLockIcon.textContent = '🔓';
          visLock.style.color = '#15803d'; // Green
          visLock.style.transform = 'scale(1.2)';
        } else {
          visLockIcon.textContent = '🔒';
          visLock.style.color = '#b91c1c'; // Red
          visLock.style.transform = 'translateX(-10px)';
          setTimeout(() => {
            visLock.style.transform = 'translateX(10px)';
            setTimeout(() => {
              visLock.style.transform = 'translateX(0)';
            }, 100);
          }, 100);
        }
      }

      if (auditLog) {
        const logEntry = document.createElement('li');
        logEntry.style.paddingBottom = '5px';
        logEntry.style.borderBottom = '1px solid #ccc';
        logEntry.style.marginBottom = '5px';
        const actionStatus = granted ? 'GRANTED' : 'DENIED';
        const color = granted ? 'green' : 'red';
        logEntry.innerHTML = `[${timestamp}] <strong>[${modelName}]</strong> User: <strong>${identity}</strong> (${role}) | Action: <strong>${op.toUpperCase()}</strong> on <strong>${obj}</strong> &rarr; <span style="color:${color};">[${actionStatus}]</span>`;
        auditLog.prepend(logEntry);
      }
    });
  }

  // Quiz Handling
  const btnSubmitQuiz = document.getElementById('btnSubmitQuiz');
  const quizOutput = document.getElementById('quizOutput');
  const quizForm = document.getElementById('quizForm');

  if (btnSubmitQuiz && quizOutput && quizForm) {
    btnSubmitQuiz.addEventListener('click', () => {
      let score = 0;
      let feedback = [];
      
      const q1 = quizForm.elements['q1'].value;
      const q2 = quizForm.elements['q2'].value;
      const q3 = quizForm.elements['q3'].value;

      if (q1 === 'dac') {
        score++;
      } else if (q1) {
        feedback.push("Q1 is incorrect: DAC allows the owner to decide access.");
      }

      if (q2 === 'readup') {
        score++;
      } else if (q2) {
        feedback.push("Q2 is incorrect: The 'No Read Up' principle prevents viewing higher clearance data.");
      }

      if (q3 === 'role') {
        score++;
      } else if (q3) {
        feedback.push("Q3 is incorrect: RBAC assigns permissions to roles, then roles to users.");
      }

      if (q1 && q2 && q3) {
        let resultHtml = `You scored ${score} out of 3. ${score === 3 ? 'Excellent!' : 'Review the theory section.'}`;
        if (feedback.length > 0) {
          resultHtml += `<ul style="color: #b91c1c; font-weight: normal; margin-top: 10px; font-size: 0.9rem;"><li>${feedback.join('</li><li>')}</li></ul>`;
        }
        quizOutput.innerHTML = resultHtml;
        quizOutput.style.color = score === 3 ? '#15803d' : '#b91c1c';
      } else {
        quizOutput.innerHTML = 'Please answer all questions before submitting.';
        quizOutput.style.color = '#b91c1c';
      }
    });
  }
});
