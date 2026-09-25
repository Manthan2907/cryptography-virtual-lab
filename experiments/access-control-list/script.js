document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnCheckAcl');
  const userSelect = document.getElementById('aclUser');
  const permSelect = document.getElementById('aclPerm');
  const output = document.getElementById('aclOutput');

  // Defined ACL for /secure/database.db
  const aclRules = {
    alice: ['read', 'write', 'execute'],
    bob: ['read', 'write'],
    charlie: ['read'],
    eve: []
  };

  if (btn && userSelect && permSelect && output) {
    btn.addEventListener('click', () => {
      const user = userSelect.value;
      const perm = permSelect.value;
      const userPerms = aclRules[user] || [];
      const allowed = userPerms.includes(perm);

      output.innerHTML = `
        <p><strong>Resource:</strong> <code>/secure/database.db</code></p>
        <p><strong>Subject:</strong> <code>${user}</code></p>
        <p><strong>Configured ACL Permissions:</strong> [${userPerms.map(p => `<code>${p}</code>`).join(', ') || 'NONE'}]</p>
        <p><strong>Requested Operation:</strong> <code>${perm.toUpperCase()}</code></p>
        <p><strong>Decision:</strong> ${allowed ? '<span style="color:#15803d; font-weight:bold; font-size:1.15rem;">&#10004; ALLOWED</span>' : '<span style="color:#b91c1c; font-weight:bold; font-size:1.15rem;">&#10008; DENIED</span>'}</p>
      `;
    });
  }
});
