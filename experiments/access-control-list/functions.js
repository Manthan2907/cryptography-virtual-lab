/**
 * @file functions.js
 * @description Pure functions for POSIX Access Control List (ACL) evaluation,
 * directory inheritance (Top-Down approach), and CLI/UI formatting.
 */

/**
 * Returns an HTML badge for a single permission character ('r', 'w', 'x').
 * @param {string} perm - The permission character ('r', 'w', 'x').
 * @returns {string} HTML string representing the badge.
 */
function renderBadge(perm) {
  if (perm === 'r') return '<span class="badge badge-r">r</span>';
  if (perm === 'w') return '<span class="badge badge-w">w</span>';
  if (perm === 'x') return '<span class="badge badge-x">x</span>';
  return '';
}

/**
 * Converts an array of permissions into sorted HTML badge markup.
 * @param {string[]} perms - Array of permissions (e.g. ['r', 'w']).
 * @returns {string} Formatted HTML badge string.
 */
function getPermissionsMarkup(perms) {
  if (!perms || perms.length === 0) return '<span class="badge badge-none">-</span>';
  const sorted = ['r', 'w', 'x'].filter(p => perms.includes(p));
  return sorted.map(renderBadge).join('');
}

/**
 * Merges parent directory default ACLs with a file's explicit ACLs.
 * Implements the Top-Down inheritance model:
 * Directory Default ACLs flow downward to child files, but explicit file ACEs take precedence.
 * 
 * @param {Object} file - The file object containing base properties and explicit ACL.
 * @param {Object} [directory] - The parent directory containing default ACL rules.
 * @param {boolean} [inheritDefault=true] - Whether inheritance is currently enabled.
 * @returns {Array<Object>} List of merged Access Control Entries with origin metadata.
 */
function mergeEffectiveAcl(file, directory, inheritDefault = true) {
  const effectiveAcl = [];
  const fileAcl = file.acl || [];

  // Start with file's explicit ACEs
  fileAcl.forEach(ace => {
    effectiveAcl.push({
      ...ace,
      perms: [...ace.perms],
      isInherited: false,
      source: 'file'
    });
  });

  // If inheritance is enabled and directory has default ACLs, merge them in
  if (inheritDefault && directory && Array.isArray(directory.defaultAcl)) {
    directory.defaultAcl.forEach(dirAce => {
      // Check if file already has an explicit ACE of the same type and id
      const existingIndex = effectiveAcl.findIndex(
        fAce => fAce.type === dirAce.type && fAce.id === dirAce.id
      );

      if (existingIndex === -1) {
        // Inherit rule downward from directory
        effectiveAcl.push({
          type: dirAce.type,
          id: dirAce.id,
          perms: [...dirAce.perms],
          isInherited: true,
          source: `dir:${directory.path}`
        });
      }
    });
  }

  return effectiveAcl;
}

/**
 * Generates POSIX getfacl command-line output for the given file and directory context.
 * 
 * @param {Object} file - File object.
 * @param {Object} [directory] - Parent directory object.
 * @param {boolean} [inheritDefault=true] - Whether directory inheritance is enabled.
 * @returns {string} Formatted getfacl output string.
 */
function formatCliAcl(file, directory, inheritDefault = true) {
  let cli = `# file: ${file.path}\n`;
  if (directory) {
    cli += `# parent-directory: ${directory.path}\n`;
  }
  cli += `# creator: ${file.creator || 'unknown'}\n`;
  cli += `# owner: ${file.owner}\n`;
  cli += `# group: ${file.group}\n`;
  cli += `# inheritance (top-down): ${inheritDefault ? 'ENABLED' : 'DISABLED'}\n`;

  const effective = mergeEffectiveAcl(file, directory, inheritDefault);

  // Sort: owner user, named users, owning group, named groups, mask, other
  const sorted = [...effective].sort((a, b) => {
    const order = { 'user': 1, 'group': 2, 'mask': 3, 'other': 4 };
    if (a.type !== b.type) return order[a.type] - order[b.type];
    if (a.id === file.owner) return -1;
    if (b.id === file.owner) return 1;
    if (a.id === file.group) return -1;
    if (b.id === file.group) return 1;
    return (a.id || '').localeCompare(b.id || '');
  });

  sorted.forEach(ace => {
    const r = ace.perms.includes('r') ? 'r' : '-';
    const w = ace.perms.includes('w') ? 'w' : '-';
    const x = ace.perms.includes('x') ? 'x' : '-';
    const pStr = r + w + x;
    const inheritedTag = ace.isInherited ? ' # [inherited from dir default]' : '';

    if (ace.type === 'user' && ace.id === file.owner) {
      cli += `user::${pStr}\n`;
    } else if (ace.type === 'user') {
      cli += `user:${ace.id}:${pStr}${inheritedTag}\n`;
    } else if (ace.type === 'group' && ace.id === file.group) {
      cli += `group::${pStr}${inheritedTag}\n`;
    } else if (ace.type === 'group') {
      cli += `group:${ace.id}:${pStr}${inheritedTag}\n`;
    } else if (ace.type === 'mask') {
      cli += `mask::${pStr}\n`;
    } else if (ace.type === 'other') {
      cli += `other::${pStr}\n`;
    }
  });

  return cli;
}

/**
 * Evaluates an access request against a file using the Top-Down Hierarchical model
 * and standard POSIX precedence rules.
 * 
 * Flow:
 * 1. Top-Down Context Analysis:
 *    - Directory Authority (Admin / Directory owner)
 *    - Entity Classification: Creator vs. Owner vs. Group Member vs. Other
 *    - Inheritance Assessment: Merging parent directory default ACLs if active.
 * 2. Precedence Evaluation:
 *    - Step 0: Superuser (root) bypass
 *    - Step 1: Owner match (primary owner permissions apply; creator is noted)
 *    - Step 2: Named user match (explicit file ACE > inherited directory ACE, filtered by mask)
 *    - Step 3: Group membership union (explicit & inherited group ACEs, filtered by mask)
 *    - Step 4: Other (World) fallback
 * 3. Decision Determination: Compare granted permissions against requested operation.
 * 
 * @param {Object} file - Target file object.
 * @param {Object} [directory] - Parent directory object.
 * @param {string} username - Name of the requesting user.
 * @param {string} operation - Requested operation ('r', 'w', or 'x').
 * @param {Object} sysUsers - Registry of system users and their groups.
 * @param {boolean} [inheritDefault=true] - Whether directory default ACL inheritance is active.
 * @returns {Object} Result object containing allowed (boolean), grantedPerms, and detailed trace.
 */
function evaluateAccess(file, directory, username, operation, sysUsers, inheritDefault = true) {
  const userInfo = sysUsers[username] || { groups: [] };
  const effectiveAcl = mergeEffectiveAcl(file, directory, inheritDefault);

  let trace = `========================================================\n`;
  trace += `[PHASE 1: TOP-DOWN HIERARCHY & ENTITY IDENTIFICATION (↓)]\n`;
  trace += `========================================================\n`;
  trace += `Target File: ${file.path}\n`;
  if (directory) {
    trace += `Parent Directory: ${directory.path} (Admin/Owner: ${directory.owner}, Group: ${directory.group})\n`;
  }
  trace += `Creator: '${file.creator || 'unknown'}' (Initial creator of the file)\n`;
  trace += `Current Owner: '${file.owner}' (Holds primary administrative control)\n`;
  trace += `Owning Group: '${file.group}'\n`;
  trace += `Requesting Subject: '${username}'\n`;
  trace += `Subject Groups: [${userInfo.groups.join(', ') || 'none'}]\n`;
  trace += `Requested Operation: ${operation.toUpperCase()} (${operation === 'r' ? 'Read' : operation === 'w' ? 'Write' : 'Execute'})\n\n`;

  // Entity category classification
  trace += `Entity Classification:\n`;
  if (username === file.owner) {
    trace += `  * Role: OWNER. '${username}' owns this file and dictates its ACLs.\n`;
  } else if (username === file.creator) {
    trace += `  * Role: CREATOR. '${username}' created this file, but current owner is '${file.owner}'.\n`;
    trace += `    Note: In system security, Owner/Administrator rules govern access, not creator status alone.\n`;
  } else if (userInfo.groups.includes(file.group)) {
    trace += `  * Role: OWNING GROUP MEMBER. Belongs to '${file.group}'.\n`;
  } else if (userInfo.groups.some(g => effectiveAcl.some(a => a.type === 'group' && a.id === g))) {
    trace += `  * Role: NAMED GROUP MEMBER. Belongs to a group with explicit/inherited ACL permissions.\n`;
  } else {
    trace += `  * Role: OTHER (World). Outside owner and group categories.\n`;
  }

  // Top-down inheritance notice
  if (inheritDefault && directory && Array.isArray(directory.defaultAcl)) {
    trace += `\nTop-Down Inheritance: ACTIVE\n`;
    trace += `  -> Parent directory '${directory.path}' propagates default ACL rules to '${file.path}'.\n`;
    directory.defaultAcl.forEach(dAce => {
      trace += `     • Inherited [${dAce.type}:${dAce.id || '*'}] -> [${dAce.perms.join(',') || 'none'}]\n`;
    });
  } else {
    trace += `\nTop-Down Inheritance: ${inheritDefault ? 'NONE (No parent defaults)' : 'DISABLED (File isolated from parent directory rules)'}\n`;
  }

  trace += `\n========================================================\n`;
  trace += `[PHASE 2: SEQUENTIAL PRECEDENCE EVALUATION]\n`;
  trace += `========================================================\n`;

  let grantedPerms = [];
  let matchedRule = false;
  let ruleOrigin = '';

  const maskAce = effectiveAcl.find(a => a.type === 'mask');
  const anyExecute = effectiveAcl.some(ace => ace.perms.includes('x'));

  // RULE 0: Superuser (Root) Bypass
  if (username === 'root') {
    trace += `[STEP 0: SUPERUSER BYPASS]\n`;
    trace += `Subject is 'root'. Root bypasses DAC permissions.\n`;
    trace += `  -> Read and Write unconditionally GRANTED.\n`;
    grantedPerms = ['r', 'w'];
    if (anyExecute) {
      trace += `  -> At least one execute bit exists on file/ACL. Execute GRANTED.\n`;
      grantedPerms.push('x');
    } else {
      trace += `  -> No execute bit exists in ACL. Execute bit not active.\n`;
    }
    matchedRule = true;
    ruleOrigin = 'Superuser Bypass';
  }
  // RULE 1: Resource Owner Match
  else if (username === file.owner) {
    trace += `[STEP 1: OWNER MATCH]\n`;
    trace += `Subject '${username}' is the OWNER of the file.\n`;
    const ownerAce = effectiveAcl.find(a => a.type === 'user' && a.id === file.owner);
    grantedPerms = ownerAce ? [...ownerAce.perms] : [];
    trace += `  -> Applying Owner Base Permissions: [${grantedPerms.join(',') || 'NONE'}]\n`;
    trace += `  -> Evaluation stops here (Owner permissions cannot be masked or overridden by group).\n`;
    matchedRule = true;
    ruleOrigin = 'File Owner Entry';
  }
  // RULE 2: Specific Named User Entry Match
  else {
    const userAce = effectiveAcl.find(a => a.type === 'user' && a.id === username);
    if (userAce) {
      trace += `[STEP 2: NAMED USER MATCH]\n`;
      trace += `Found matching User ACE for '${username}' (${userAce.isInherited ? 'inherited from parent directory' : 'explicit file rule'}).\n`;
      grantedPerms = [...userAce.perms];

      if (maskAce) {
        const preMask = [...grantedPerms];
        grantedPerms = grantedPerms.filter(p => maskAce.perms.includes(p));
        trace += `  -> Pre-mask permissions: [${preMask.join(',') || 'NONE'}]\n`;
        trace += `  -> Applying ACL MASK [${maskAce.perms.join(',') || 'NONE'}]: Effective perms = [${grantedPerms.join(',') || 'NONE'}]\n`;
      } else {
        trace += `  -> Applying Effective Permissions: [${grantedPerms.join(',') || 'NONE'}]\n`;
      }
      matchedRule = true;
      ruleOrigin = userAce.isInherited ? 'Inherited User ACE' : 'Explicit Named User ACE';
    }
  }

  // RULE 3: Group Match (Owning group and Named group entries)
  if (!matchedRule) {
    const groupAces = effectiveAcl.filter(
      a => a.type === 'group' && userInfo.groups.includes(a.id)
    );

    if (groupAces.length > 0) {
      trace += `[STEP 3: GROUP MATCH (UNION)]\n`;
      trace += `Subject belongs to matching group(s):\n`;
      const unionPerms = new Set();
      groupAces.forEach(ace => {
        const sourceLabel = ace.isInherited ? 'inherited from parent directory' : 'explicit file rule';
        trace += `  • Group '${ace.id}' (${sourceLabel}): grants [${ace.perms.join(',') || 'NONE'}]\n`;
        ace.perms.forEach(p => unionPerms.add(p));
      });

      grantedPerms = Array.from(unionPerms);
      trace += `  -> Union of all matched group permissions: [${grantedPerms.join(',') || 'NONE'}]\n`;

      if (maskAce) {
        const preMask = [...grantedPerms];
        grantedPerms = grantedPerms.filter(p => maskAce.perms.includes(p));
        trace += `  -> Applying ACL MASK [${maskAce.perms.join(',') || 'NONE'}]: Effective perms = [${grantedPerms.join(',') || 'NONE'}]\n`;
      }

      matchedRule = true;
      ruleOrigin = 'Group ACE Union';
    }
  }

  // RULE 4: Other (World) Fallback
  if (!matchedRule) {
    trace += `[STEP 4: OTHER (WORLD) FALLBACK]\n`;
    trace += `Subject does not match owner, specific user ACE, or any group ACE.\n`;
    const otherAce = effectiveAcl.find(a => a.type === 'other');
    grantedPerms = otherAce ? [...otherAce.perms] : [];
    trace += `  -> Applying 'Other' (World) Permissions: [${grantedPerms.join(',') || 'NONE'}]\n`;
    ruleOrigin = 'Other (World) Fallback';
  }

  // Final Decision
  trace += `\n========================================================\n`;
  trace += `[PHASE 3: DECISION PHASE]\n`;
  trace += `========================================================\n`;
  trace += `Requested: ${operation.toUpperCase()} | Effective Granted Set: [${grantedPerms.join(',') || 'NONE'}]\n`;
  trace += `Decision Basis: ${ruleOrigin}\n`;

  const allowed = grantedPerms.includes(operation);
  if (allowed) {
    trace += `\n>>> RESULT: ACCESS ALLOWED <<<\n`;
  } else {
    trace += `\n>>> RESULT: ACCESS DENIED <<<\n`;
  }

  return {
    allowed,
    grantedPerms,
    trace,
    ruleOrigin,
    effectiveAcl
  };
}
