document.addEventListener('DOMContentLoaded', () => {
  // --- Simulation State Data ---
  
  // Simulated Users and their group memberships
  const sysUsers = {
    alice: { groups: ['admins', 'hr'] },
    bob: { groups: ['devs'] },
    charlie: { groups: ['devs', 'hr'] },
    eve: { groups: ['guests'] },
    root: { groups: ['root', 'admins'] }
  };

  // Simulated Files with standard POSIX extended ACL structures
  const fileSystem = {
    payroll: {
      path: '/finance/payroll.csv',
      owner: 'alice',
      group: 'hr',
      acl: [
        { id: 'alice', type: 'user', perms: ['r', 'w', 'x'] },
        { id: 'hr', type: 'group', perms: ['r', 'w'] },
        { id: 'eve', type: 'user', perms: [] }, 
        { id: '', type: 'other', perms: [] }
      ]
    },
    www: {
      path: '/var/www/index.html',
      owner: 'root',
      group: 'devs',
      acl: [
        { id: 'root', type: 'user', perms: ['r', 'w', 'x'] },
        { id: 'devs', type: 'group', perms: ['r', 'w'] },
        { id: '', type: 'other', perms: ['r'] }
      ]
    },
    project: {
      path: '/home/bob/project.sh',
      owner: 'bob',
      group: 'devs',
      acl: [
        { id: 'bob', type: 'user', perms: ['r', 'w', 'x'] },
        { id: 'devs', type: 'group', perms: ['r', 'x'] },
        { id: 'alice', type: 'user', perms: ['r'] },
        { id: '', type: 'other', perms: [] }
      ]
    }
  };

  // --- UI Elements ---
  const resourceSelect = document.getElementById('resourceSelect');
  const aclTableContainer = document.getElementById('aclTableContainer');
  const cliOutput = document.getElementById('cliOutput');
  
  const ruleType = document.getElementById('ruleType');
  const ruleName = document.getElementById('ruleName');
  const permRead = document.getElementById('permRead');
  const permWrite = document.getElementById('permWrite');
  const permExec = document.getElementById('permExec');
  const btnAddRule = document.getElementById('btnAddRule');

  const simSubject = document.getElementById('simSubject');
  const simOperation = document.getElementById('simOperation');
  const btnEvaluate = document.getElementById('btnEvaluate');
  const traceOutput = document.getElementById('traceOutput');

  // --- Functions ---

  function renderBadge(perm) {
    if (perm === 'r') return '<span class="badge badge-r">r</span>';
    if (perm === 'w') return '<span class="badge badge-w">w</span>';
    if (perm === 'x') return '<span class="badge badge-x">x</span>';
    return '';
  }

  function getPermissionsMarkup(perms) {
    if (!perms || perms.length === 0) return '<span class="badge badge-none">-</span>';
    const sorted = ['r', 'w', 'x'].filter(p => perms.includes(p));
    return sorted.map(renderBadge).join('');
  }

  function getActiveFile() {
    return fileSystem[resourceSelect.value];
  }

  function renderAclTable() {
    const file = getActiveFile();
    let html = `<table class="acl-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>Identity</th>
          <th>Permissions</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>`;
    
    // Sort ACL: owner first, then specific users, then group owner, then specific groups, then other
    const sortedAcl = [...file.acl].sort((a, b) => {
      const order = { 'user': 1, 'group': 2, 'other': 3 };
      if (a.type !== b.type) return order[a.type] - order[b.type];
      if (a.id === file.owner) return -1;
      if (b.id === file.owner) return 1;
      if (a.id === file.group) return -1;
      if (b.id === file.group) return 1;
      return a.id.localeCompare(b.id);
    });

    sortedAcl.forEach((ace, index) => {
      let typeLabel = ace.type === 'user' ? 'User' : (ace.type === 'group' ? 'Group' : 'Other');
      let idLabel = ace.id === '' ? '*' : ace.id;
      
      let isBase = false;
      if (ace.type === 'user' && ace.id === file.owner) { idLabel += ' (owner)'; isBase = true; }
      if (ace.type === 'group' && ace.id === file.group) { idLabel += ' (owning group)'; isBase = true; }
      if (ace.type === 'other') isBase = true;

      html += `<tr>
        <td>${typeLabel}</td>
        <td><strong>${idLabel}</strong></td>
        <td>${getPermissionsMarkup(ace.perms)}</td>
        <td>
          ${!isBase ? `<button class="acl-btn btn-danger btn-small" data-id="${ace.id}" data-type="${ace.type}">Remove</button>` : '<em>Base</em>'}
        </td>
      </tr>`;
    });

    html += `</tbody></table>`;
    aclTableContainer.innerHTML = html;
    updateCliOutput(file, sortedAcl);

    // Attach remove listeners
    document.querySelectorAll('.btn-danger').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const idToRemove = e.target.getAttribute('data-id');
        const typeToRemove = e.target.getAttribute('data-type');
        file.acl = file.acl.filter(ace => !(ace.id === idToRemove && ace.type === typeToRemove));
        renderAclTable();
      });
    });
  }

  function updateCliOutput(file, sortedAcl) {
    let cli = `# file: ${file.path}\n# owner: ${file.owner}\n# group: ${file.group}\n`;
    sortedAcl.forEach(ace => {
      let r = ace.perms.includes('r') ? 'r' : '-';
      let w = ace.perms.includes('w') ? 'w' : '-';
      let x = ace.perms.includes('x') ? 'x' : '-';
      let pStr = r + w + x;

      if (ace.type === 'user' && ace.id === file.owner) cli += `user::${pStr}\n`;
      else if (ace.type === 'user') cli += `user:${ace.id}:${pStr}\n`;
      else if (ace.type === 'group' && ace.id === file.group) cli += `group::${pStr}\n`;
      else if (ace.type === 'group') cli += `group:${ace.id}:${pStr}\n`;
      else if (ace.type === 'other') cli += `other::${pStr}\n`;
    });
    cliOutput.textContent = cli;
  }

  // --- Event Listeners ---
  resourceSelect.addEventListener('change', renderAclTable);

  btnAddRule.addEventListener('click', () => {
    const file = getActiveFile();
    const type = ruleType.value;
    const name = ruleName.value.trim().toLowerCase();
    
    if (!name) { alert("Please enter a user or group name."); return; }
    
    let perms = [];
    if (permRead.checked) perms.push('r');
    if (permWrite.checked) perms.push('w');
    if (permExec.checked) perms.push('x');

    // Remove existing ACE if exists for this type & id
    file.acl = file.acl.filter(ace => !(ace.id === name && ace.type === type));
    
    // Add new ACE
    file.acl.push({ type, id: name, perms });
    
    renderAclTable();
    ruleName.value = '';
    permRead.checked = false; permWrite.checked = false; permExec.checked = false;
  });

  btnEvaluate.addEventListener('click', () => {
    const file = getActiveFile();
    const user = simSubject.value;
    const operation = simOperation.value;
    const userInfo = sysUsers[user];
    
    let trace = `[EVALUATION START] Initiating access request...\n`;
    trace += `Resource: ${file.path}\n`;
    trace += `Subject: User '${user}' (Groups: ${userInfo.groups.join(', ') || 'none'})\n`;
    trace += `Requested Operation: ${operation.toUpperCase()}\n\n`;

    let grantedPerms = [];
    let matchedRule = false;

    // RULE 1: Root user bypass
    if (user === 'root') {
      trace += `[SUPERUSER BYPASS] User is root. Automatic full access granted.\n`;
      grantedPerms = ['r', 'w', 'x'];
      matchedRule = true;
    } 
    // RULE 2: Owner match
    else if (user === file.owner) {
      trace += `[MATCH] Subject '${user}' is the OWNER of the file.\n`;
      const ownerAce = file.acl.find(a => a.type === 'user' && a.id === file.owner);
      grantedPerms = ownerAce ? ownerAce.perms : [];
      trace += `  -> Applying Owner Permissions: [${grantedPerms.join(',') || 'NONE'}]\n`;
      matchedRule = true;
    } 
    // RULE 3: Specific User ACE match
    else {
      const userAce = file.acl.find(a => a.type === 'user' && a.id === user);
      if (userAce) {
        trace += `[MATCH] Found explicit Named User ACE for '${user}'.\n`;
        grantedPerms = userAce.perms;
        trace += `  -> Applying User ACE Permissions: [${grantedPerms.join(',') || 'NONE'}]\n`;
        matchedRule = true;
      }
    }

    // RULE 4: Group match (Owning group or Named group ACEs)
    if (!matchedRule) {
      // Find all matching group ACEs
      const groupAces = file.acl.filter(a => a.type === 'group' && userInfo.groups.includes(a.id));
      if (groupAces.length > 0) {
        trace += `[MATCH] Subject belongs to one or more matched Groups.\n`;
        let unionPerms = new Set();
        groupAces.forEach(ace => {
          trace += `  -> Matched Group ACE '${ace.id}': [${ace.perms.join(',') || 'NONE'}]\n`;
          ace.perms.forEach(p => unionPerms.add(p));
        });
        grantedPerms = Array.from(unionPerms);
        trace += `  -> Applying Union of Group Permissions: [${grantedPerms.join(',') || 'NONE'}]\n`;
        matchedRule = true;
      }
    }

    // RULE 5: Other (World) match
    if (!matchedRule) {
      trace += `[FALLBACK] No specific user or group matches found.\n`;
      const otherAce = file.acl.find(a => a.type === 'other');
      grantedPerms = otherAce ? otherAce.perms : [];
      trace += `  -> Applying 'Other' (World) Permissions: [${grantedPerms.join(',') || 'NONE'}]\n`;
    }

    // Final Decision
    trace += `\n[DECISION PHASE]\n`;
    trace += `Requested: '${operation}', Granted Set: [${grantedPerms.join(',') || 'NONE'}]\n`;
    
    if (grantedPerms.includes(operation)) {
      trace += `\n>>> RESULT: ALLOWED <<<\n`;
      traceOutput.innerHTML = trace + `<div style="margin-top:10px; color:#10b981; font-weight:bold; font-size:1.2rem;">&#10004; ACCESS GRANTED</div>`;
    } else {
      trace += `\n>>> RESULT: DENIED <<<\n`;
      traceOutput.innerHTML = trace + `<div style="margin-top:10px; color:#f87171; font-weight:bold; font-size:1.2rem;">&#10008; ACCESS DENIED</div>`;
    }
  });

  // --- Quiz Logic ---
  const correctAnswers = {
    q1: 'A', // ACLs attached to objects
    q2: 'C', // Owner evaluated first
    q3: 'D', // Fallback to Other
    q4: 'B', // Specific user takes precedence over group
    q5: 'C'  // Minimum privileges
  };

  document.getElementById('btnSubmitQuiz').addEventListener('click', () => {
    let score = 0;
    const form = document.getElementById('quizForm');
    const formData = new FormData(form);

    for (const [qId, correctVal] of Object.entries(correctAnswers)) {
      const userVal = formData.get(qId);
      const feedbackDiv = document.getElementById(`feedback-${qId}`);
      
      if (userVal === correctVal) {
        score++;
        feedbackDiv.textContent = `Correct!`;
        feedbackDiv.className = 'quiz-feedback correct';
      } else {
        feedbackDiv.textContent = `Incorrect. The correct answer is ${correctVal}.`;
        feedbackDiv.className = 'quiz-feedback incorrect';
      }
    }

    const scoreDiv = document.getElementById('quizScore');
    scoreDiv.textContent = `You scored ${score} out of 5.`;
    scoreDiv.style.color = score === 5 ? '#15803d' : '#b45309';
  });

  // --- Feedback Logic ---
  document.getElementById('feedbackForm').addEventListener('submit', (e) => {
    e.preventDefault();
    document.getElementById('feedbackThanks').style.display = 'block';
    setTimeout(() => {
      document.getElementById('feedbackThanks').style.display = 'none';
      e.target.reset();
    }, 3000);
  });

  // Initial render
  renderAclTable();
});
