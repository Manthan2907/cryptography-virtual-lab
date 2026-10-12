document.addEventListener('DOMContentLoaded', () => {
  // --- Simulation State Data ---

  // Simulated System Users and their group memberships
  const sysUsers = {
    rahul: { groups: ['comp_eng'] },
    alice: { groups: ['admins', 'comp_eng', 'hr'] },
    bob: { groups: ['devs'] },
    charlie: { groups: ['devs', 'hr'] },
    eve: { groups: ['guests'] },
    root: { groups: ['root', 'admins'] }
  };

  // Simulated Directories with Top-Down Authority and Default ACLs
  const sysDirectories = {
    comp_eng_dir: {
      path: '/departments/comp_eng/',
      owner: 'alice',
      group: 'comp_eng',
      defaultAcl: [
        { id: 'comp_eng', type: 'group', perms: ['r', 'x'] },
        { id: '', type: 'other', perms: [] }
      ],
      description: 'Computer Engineering Department directory managed by Alice (Admin).'
    },
    finance_dir: {
      path: '/finance/',
      owner: 'alice',
      group: 'hr',
      defaultAcl: [
        { id: 'hr', type: 'group', perms: ['r', 'w'] },
        { id: '', type: 'other', perms: [] }
      ],
      description: 'Finance & Payroll directory managed by Alice.'
    },
    dev_dir: {
      path: '/home/bob/',
      owner: 'bob',
      group: 'devs',
      defaultAcl: [
        { id: 'devs', type: 'group', perms: ['r', 'x'] },
        { id: '', type: 'other', perms: [] }
      ],
      description: 'Bob home directory for developer projects.'
    },
    web_dir: {
      path: '/var/www/',
      owner: 'root',
      group: 'devs',
      defaultAcl: [
        { id: 'devs', type: 'group', perms: ['r'] },
        { id: '', type: 'other', perms: ['r'] }
      ],
      description: 'Web server root directory managed by Root.'
    }
  };

  // Simulated Files with Creator, Owner, and Explicit ACLs
  const fileSystem = {
    secret: {
      path: '/departments/comp_eng/secret.txt',
      dirKey: 'comp_eng_dir',
      creator: 'rahul',
      owner: 'alice',
      group: 'comp_eng',
      inheritDefault: true,
      acl: [
        { id: 'alice', type: 'user', perms: ['r', 'w'] },
        { id: 'rahul', type: 'user', perms: ['r'] },
        { id: 'comp_eng', type: 'group', perms: ['r'] },
        { id: '', type: 'other', perms: [] }
      ]
    },
    lab1: {
      path: '/departments/comp_eng/lab_manual.c',
      dirKey: 'comp_eng_dir',
      creator: 'alice',
      owner: 'alice',
      group: 'comp_eng',
      inheritDefault: true,
      acl: [
        { id: 'alice', type: 'user', perms: ['r', 'w', 'x'] },
        { id: '', type: 'other', perms: [] }
      ]
    },
    payroll: {
      path: '/finance/payroll.csv',
      dirKey: 'finance_dir',
      creator: 'alice',
      owner: 'alice',
      group: 'hr',
      inheritDefault: true,
      acl: [
        { id: 'alice', type: 'user', perms: ['r', 'w', 'x'] },
        { id: 'hr', type: 'group', perms: ['r', 'w'] },
        { id: 'eve', type: 'user', perms: [] },
        { id: '', type: 'other', perms: [] }
      ]
    },
    project: {
      path: '/home/bob/project.sh',
      dirKey: 'dev_dir',
      creator: 'bob',
      owner: 'bob',
      group: 'devs',
      inheritDefault: true,
      acl: [
        { id: 'bob', type: 'user', perms: ['r', 'w', 'x'] },
        { id: 'devs', type: 'group', perms: ['r', 'x'] },
        { id: 'alice', type: 'user', perms: ['r'] },
        { id: '', type: 'other', perms: [] }
      ]
    },
    www: {
      path: '/var/www/index.html',
      dirKey: 'web_dir',
      creator: 'root',
      owner: 'root',
      group: 'devs',
      inheritDefault: true,
      acl: [
        { id: 'root', type: 'user', perms: ['r', 'w', 'x'] },
        { id: 'devs', type: 'group', perms: ['r', 'w'] },
        { id: '', type: 'other', perms: ['r'] }
      ]
    }
  };

  // --- UI Element Selectors ---
  const resourceSelect = document.getElementById('resourceSelect');
  const metadataContainer = document.getElementById('metadataContainer');
  const aclTableContainer = document.getElementById('aclTableContainer');
  const cliOutput = document.getElementById('cliOutput');
  const inheritToggle = document.getElementById('inheritToggle');

  const ruleType = document.getElementById('ruleType');
  const ruleName = document.getElementById('ruleName');
  const permRead = document.getElementById('permRead');
  const permWrite = document.getElementById('permWrite');
  const permExec = document.getElementById('permExec');
  const btnAddRule = document.getElementById('btnAddRule');

  const sysUserName = document.getElementById('sysUserName');
  const sysUserGroups = document.getElementById('sysUserGroups');
  const btnSaveUser = document.getElementById('btnSaveUser');

  const simSubject = document.getElementById('simSubject');
  const simOperation = document.getElementById('simOperation');
  const btnEvaluate = document.getElementById('btnEvaluate');
  const traceOutput = document.getElementById('traceOutput');

  // Helper getters
  function getActiveFile() {
    return fileSystem[resourceSelect.value];
  }

  function getActiveDirectory() {
    const file = getActiveFile();
    return sysDirectories[file.dirKey];
  }

  // --- Rendering UI State ---
  function renderMetadata() {
    const file = getActiveFile();
    const dir = getActiveDirectory();
    if (!metadataContainer) return;

    metadataContainer.innerHTML = `
      <div class="metadata-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 15px; font-size: 13px;">
        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--color-border); border-radius: 6px; padding: 10px;">
          <div style="color: var(--color-text-muted); font-size: 11px; text-transform: uppercase;">Parent Directory (Authority)</div>
          <strong style="color: #60a5fa;">${dir ? dir.path : 'None'}</strong>
        </div>
        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--color-border); border-radius: 6px; padding: 10px;">
          <div style="color: var(--color-text-muted); font-size: 11px; text-transform: uppercase;">Creator</div>
          <strong style="color: #34d399;">${file.creator}</strong> <span style="font-size:10px; opacity:0.8;">(Created file)</span>
        </div>
        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--color-border); border-radius: 6px; padding: 10px;">
          <div style="color: var(--color-text-muted); font-size: 11px; text-transform: uppercase;">Current Owner</div>
          <strong style="color: #fbbf24;">${file.owner}</strong> <span style="font-size:10px; opacity:0.8;">(Controls ACL)</span>
        </div>
        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--color-border); border-radius: 6px; padding: 10px;">
          <div style="color: var(--color-text-muted); font-size: 11px; text-transform: uppercase;">Owning Group</div>
          <strong style="color: #c084fc;">${file.group}</strong>
        </div>
      </div>
    `;

    if (inheritToggle) {
      inheritToggle.checked = !!file.inheritDefault;
    }
  }

  function renderAclTable() {
    const file = getActiveFile();
    const dir = getActiveDirectory();
    renderMetadata();

    const isInheriting = inheritToggle ? inheritToggle.checked : true;
    file.inheritDefault = isInheriting;

    const effectiveAcl = mergeEffectiveAcl(file, dir, isInheriting);

    let html = `<table class="acl-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>Identity</th>
          <th>Origin / Source</th>
          <th>Permissions</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>`;

    const sortedAcl = [...effectiveAcl].sort((a, b) => {
      const order = { 'user': 1, 'group': 2, 'mask': 3, 'other': 4 };
      if (a.type !== b.type) return order[a.type] - order[b.type];
      if (a.id === file.owner) return -1;
      if (b.id === file.owner) return 1;
      if (a.id === file.group) return -1;
      if (b.id === file.group) return 1;
      return (a.id || '').localeCompare(b.id || '');
    });

    sortedAcl.forEach((ace) => {
      const typeLabel = ace.type === 'user' ? 'User' : (ace.type === 'group' ? 'Group' : (ace.type === 'mask' ? 'Mask' : 'Other'));
      let idLabel = ace.id === '' && ace.type !== 'mask' ? '*' : ace.id;
      if (ace.type === 'mask') idLabel = 'Maximum Allowed';

      let isBase = false;
      if (ace.type === 'user' && ace.id === file.owner) { idLabel += ' (owner)'; isBase = true; }
      if (ace.type === 'group' && ace.id === file.group) { idLabel += ' (owning group)'; isBase = true; }
      if (ace.type === 'other') isBase = true;

      const originBadge = ace.isInherited
        ? `<span class="badge" style="background: rgba(96, 165, 250, 0.15); color: #60a5fa; border: 1px solid #3b82f6;">Inherited (Dir Default)</span>`
        : `<span class="badge" style="background: rgba(255, 255, 255, 0.08); color: #d4d4d8;">Explicit File ACE</span>`;

      html += `<tr>
        <td>${typeLabel}</td>
        <td><strong>${idLabel}</strong></td>
        <td>${originBadge}</td>
        <td>${getPermissionsMarkup(ace.perms)}</td>
        <td>
          ${(!isBase && !ace.isInherited)
            ? `<button class="acl-btn btn-danger btn-small" data-id="${ace.id}" data-type="${ace.type}">Remove</button>`
            : (ace.isInherited ? '<em style="font-size:11px; color:#60a5fa;">Dir Default</em>' : '<em>Base</em>')}
        </td>
      </tr>`;
    });

    html += `</tbody></table>`;
    aclTableContainer.innerHTML = html;

    // Update POSIX CLI representation
    cliOutput.textContent = formatCliAcl(file, dir, isInheriting);

    // Attach remove listeners for explicit ACEs
    document.querySelectorAll('.btn-danger').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const idToRemove = e.target.getAttribute('data-id');
        const typeToRemove = e.target.getAttribute('data-type');
        file.acl = file.acl.filter(ace => !(ace.id === idToRemove && ace.type === typeToRemove));
        renderAclTable();
      });
    });
  }

  // --- Event Listeners ---
  resourceSelect.addEventListener('change', () => {
    const file = getActiveFile();
    if (inheritToggle) inheritToggle.checked = !!file.inheritDefault;
    renderAclTable();
  });

  if (inheritToggle) {
    inheritToggle.addEventListener('change', () => {
      const file = getActiveFile();
      file.inheritDefault = inheritToggle.checked;
      renderAclTable();
    });
  }

  ruleType.addEventListener('change', () => {
    if (['mask', 'other', 'owner'].includes(ruleType.value)) {
      ruleName.value = '';
      ruleName.disabled = true;
      ruleName.placeholder = 'N/A';
    } else {
      ruleName.disabled = false;
      ruleName.placeholder = 'e.g. rahul, comp_eng';
    }
  });

  btnAddRule.addEventListener('click', () => {
    const file = getActiveFile();
    const type = ruleType.value;
    let actualType = type;
    let name = ruleName.value.trim().toLowerCase();

    if (type === 'owner') {
      actualType = 'user';
      name = file.owner;
    } else if (['mask', 'other'].includes(type)) {
      name = '';
    }

    if (!name && !['mask', 'other'].includes(actualType)) {
      alert('Please enter a user or group name.');
      return;
    }

    const perms = [];
    if (permRead.checked) perms.push('r');
    if (permWrite.checked) perms.push('w');
    if (permExec.checked) perms.push('x');

    // Remove existing explicit ACE if exists for this type & id
    file.acl = file.acl.filter(ace => !(ace.id === name && ace.type === actualType));
    file.acl.push({ type: actualType, id: name, perms });

    // If new user added, register to sysUsers and dropdown
    if (type === 'user' && !sysUsers[name] && name !== '') {
      sysUsers[name] = { groups: [] };
      const newOption = document.createElement('option');
      newOption.value = name;
      newOption.textContent = `${name.charAt(0).toUpperCase() + name.slice(1)} (Groups: none)`;
      simSubject.appendChild(newOption);
    }

    renderAclTable();
    ruleName.value = '';
    permRead.checked = false;
    permWrite.checked = false;
    permExec.checked = false;
  });

  btnSaveUser.addEventListener('click', () => {
    const name = sysUserName.value.trim().toLowerCase();
    if (!name) { alert('Please enter a username.'); return; }
    const groups = sysUserGroups.value.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

    if (!sysUsers[name]) {
      sysUsers[name] = { groups };
      const newOption = document.createElement('option');
      newOption.value = name;
      simSubject.appendChild(newOption);
    } else {
      sysUsers[name].groups = groups;
    }

    const option = Array.from(simSubject.options).find(opt => opt.value === name);
    if (option) {
      const capitalized = name.charAt(0).toUpperCase() + name.slice(1);
      const groupStr = sysUsers[name].groups.join(', ') || 'none';
      option.textContent = `${capitalized} (Groups: ${groupStr})`;
    }

    alert(`User '${name}' saved with groups: [${groups.join(', ')}]`);
    sysUserName.value = '';
    sysUserGroups.value = '';
  });

  btnEvaluate.addEventListener('click', () => {
    const file = getActiveFile();
    const dir = getActiveDirectory();
    const user = simSubject.value;
    const operation = simOperation.value;
    const isInheriting = inheritToggle ? inheritToggle.checked : true;

    const result = evaluateAccess(file, dir, user, operation, sysUsers, isInheriting);

    let outputHtml = `<pre style="white-space: pre-wrap; margin: 0; font-family: monospace;">${result.trace}</pre>`;
    if (result.allowed) {
      outputHtml += `<div style="margin-top:14px; padding: 12px; background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; border-radius: 6px; color:#10b981; font-weight:bold; font-size:1.15rem;">&#10004; ACCESS GRANTED (${result.ruleOrigin})</div>`;
    } else {
      outputHtml += `<div style="margin-top:14px; padding: 12px; background: rgba(248, 113, 113, 0.1); border: 1px solid #f87171; border-radius: 6px; color:#f87171; font-weight:bold; font-size:1.15rem;">&#10008; ACCESS DENIED (${result.ruleOrigin})</div>`;
    }

    traceOutput.innerHTML = outputHtml;
  });

  // --- Quiz Logic (10 Questions) ---
  const correctAnswers = {
    q1: { ans: 'A', text: 'An authorized registry of rules attached directly to a resource specifying who can access it.' },
    q2: { ans: 'B', text: 'The Owner/Administrator controls access rules; Creator is the user who initially created the file but may not retain ownership.' },
    q3: { ans: 'C', text: 'Top-down approach (↓): Permissions flow from Owner/Admin -> Group -> Users/Files, with directory default ACLs inherited downward.' },
    q4: { ans: 'A', text: 'Only Read (an explicit User ACE takes precedence over group or inherited permissions).' },
    q5: { ans: 'D', text: 'The file inherits the directory default ACLs unless an explicit file rule overrides it.' },
    q6: { ans: 'B', text: 'The ACL Mask defines the maximum allowed permission ceiling filtering effective rights for Named Users and Groups.' },
    q7: { ans: 'C', text: 'Union of permissions: Read and Write (rw-), combining all matching group entries.' },
    q8: { ans: 'A', text: 'Root automatically bypasses DAC permission checks for Read and Write, receiving Execute if at least one execute bit exists.' },
    q9: { ans: 'D', text: 'When the requesting subject does not match the owner, has no named user ACE, and belongs to no matching groups.' },
    q10: { ans: 'C', text: 'Users and processes should only receive the minimum permissions necessary for their duties, minimizing security risks.' }
  };

  document.getElementById('btnSubmitQuiz').addEventListener('click', () => {
    let score = 0;
    const form = document.getElementById('quizForm');
    const formData = new FormData(form);

    for (const [qId, correctData] of Object.entries(correctAnswers)) {
      const userVal = formData.get(qId);
      const feedbackDiv = document.getElementById(`feedback-${qId}`);
      if (!feedbackDiv) continue;

      if (!userVal) {
        feedbackDiv.innerHTML = `<strong>Not answered.</strong> Correct answer: ${correctData.text}`;
        feedbackDiv.className = 'quiz-feedback incorrect';
      } else if (userVal === correctData.ans) {
        score++;
        feedbackDiv.innerHTML = `<strong>Correct!</strong> Well done.`;
        feedbackDiv.className = 'quiz-feedback correct';
      } else {
        feedbackDiv.innerHTML = `<strong>Incorrect.</strong> Correct answer: ${correctData.text}`;
        feedbackDiv.className = 'quiz-feedback incorrect';
      }
    }

    const scoreDiv = document.getElementById('quizScore');
    if (scoreDiv) {
      scoreDiv.textContent = `You scored ${score} out of 10.`;
      scoreDiv.style.color = score >= 8 ? '#10b981' : (score >= 5 ? '#f59e0b' : '#ef4444');
    }
  });

  // Initial UI Render
  renderAclTable();
});
