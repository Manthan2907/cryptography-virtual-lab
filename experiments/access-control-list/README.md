# Access Control List (ACL)

**Experiment ID:** EXP-ACL
**Group Members:** Daksh Gurav (10734), Rahul Kewat (10742)

## Overview
This module implements an interactive Access Control List (ACL) Virtual Lab. It demonstrates object-centric authorization based on assigned permissions by simulating a Discretionary Access Control (DAC) system with extended POSIX ACL rules.

## Features
- **Virtual File System:** Test authorization across different simulated resources (`/finance/payroll.csv`, `/var/www/index.html`, `/home/bob/project.sh`).
- **Interactive ACL Editor:** Add, modify, and delete Access Control Entries (ACEs) for users and groups.
- **Authorization Engine:** Real-time permission checking applying POSIX evaluation precedence rules:
  1. Root / Superuser bypass
  2. Owner Match
  3. Named User Match
  4. Owning / Named Group Match (with permission union)
  5. Other (World) permissions
- **Execution Trace Log:** A visual, step-by-step trace of the authorization engine's decision-making process.
- **CLI Representation:** Real-time generation of corresponding POSIX `getfacl` shell commands.
- **Interactive Assessment:** 5-question multiple-choice quiz with immediate feedback and scoring.

## Technical Specifications

### Inputs
- **Resource Selection:** Target object in the virtual file system.
- **ACL Rule Management:**
  - Entity Type: User or Group
  - Entity Identity (String)
  - Permissions: Read (`r`), Write (`w`), Execute (`x`)
- **Authorization Tester:**
  - Subject User: Alice, Bob, Charlie, Eve, Root (each having predefined group memberships)
  - Requested Operation: Read (`r`), Write (`w`), Execute (`x`)

### Outputs
- **ACL Table Display:** Live representation of active ACL rules on the selected resource.
- **CLI Commands:** Equivalent Linux `setfacl` / `getfacl` commands reflecting current ACL state.
- **Decision Engine Output:** Detailed trace showing the exact traversal of precedence rules and the final `ALLOW` or `DENY` result.

### Test Cases

| Scenario | Input state | Expected Output |
| :--- | :--- | :--- |
| **Owner Override** | User = `alice`, File = `payroll.csv` | ALLOW (Alice is owner with `rwx`) |
| **Named User Precedence** | User = `bob`, File = `payroll.csv`, Bob added specifically with `r--` | ALLOW Read, DENY Write (Specific user ACE overrides groups) |
| **Group Match Union** | User = `charlie`, File = `payroll.csv` | ALLOW `rw-` (Charlie is in `hr` group, which has `rw-`) |
| **Fallback to Other** | User = `eve`, File = `www` | ALLOW `r--`, DENY `w--` (Eve relies on 'other' permissions) |
| **Root Bypass** | User = `root`, File = `payroll.csv` | ALLOW (Root automatically gets `rwx` regardless of ACL) |

## Limitations & Educational Notes
- This simulation does not implement the POSIX ACL "mask" entry feature for simplicity. It strictly unions matching group permissions without applying an effective rights mask.
- Group hierarchies and nested groups are not implemented.
- Default ACLs (inherited for new files in a directory) are discussed in the theory but not dynamically simulated.

## Local Testing
From the repository root, start the local server:
```bash
python3 -m http.server 8000
```
Navigate to:
`http://localhost:8000/experiments/access-control-list/index.html`
