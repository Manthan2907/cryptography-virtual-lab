document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnEvalAccess');
  const roleSelect = document.getElementById('subRole');
  const objSelect = document.getElementById('targetObj');
  const opSelect = document.getElementById('opType');
  const output = document.getElementById('accessOutput');

  if (btn && roleSelect && objSelect && opSelect && output) {
    btn.addEventListener('click', () => {
      const role = roleSelect.value;
      const obj = objSelect.value;
      const op = opSelect.value;

      let granted = false;
      let reason = '';

      if (role === 'admin') {
        granted = true;
        reason = 'Administrator possesses unrestricted access rights.';
      } else if (role === 'faculty') {
        if (obj === 'system_config') {
          granted = (op === 'read');
          reason = op === 'read' ? 'Faculty allowed read access to configuration.' : 'Faculty denied modification to server config.';
        } else {
          granted = true;
          reason = 'Faculty allowed read and write on academic files.';
        }
      } else if (role === 'student') {
        if (obj === 'public_syllabus') {
          granted = (op === 'read');
          reason = op === 'read' ? 'Students can read syllabus.' : 'Students cannot modify syllabus.';
        } else {
          granted = false;
          reason = 'Students have no access to grades or configuration.';
        }
      } else {
        // guest
        if (obj === 'public_syllabus' && op === 'read') {
          granted = true;
          reason = 'Public syllabus accessible to guests.';
        } else {
          granted = false;
          reason = 'Guests denied access to restricted college resources.';
        }
      }

      output.innerHTML = `
        <p><strong>Evaluation Result:</strong> ${granted ? '<span style="color:#15803d; font-weight:bold; font-size:1.1rem;">&#10004; ACCESS GRANTED</span>' : '<span style="color:#b91c1c; font-weight:bold; font-size:1.1rem;">&#10008; ACCESS DENIED</span>'}</p>
        <p><strong>Subject:</strong> ${role.toUpperCase()} | <strong>Object:</strong> ${obj} | <strong>Operation:</strong> ${op.toUpperCase()}</p>
        <p><strong>Policy Reason:</strong> ${reason}</p>
      `;
    });
  }
});
