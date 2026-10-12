# Access Control List (ACL)

**Experiment ID:** EXP-ACL  
**Group Members:** Daksh Gurav (10734), Rahul Kewat (10742)

## Overview
This module implements an interactive Access Control List (ACL) Virtual Lab. It demonstrates object-centric authorization based on assigned permissions by simulating a Discretionary Access Control (DAC) system with extended POSIX ACL rules, entity role distinctions, and the **Top-Down Approach (&darr;)** featuring Directory Default ACL inheritance.

## Core Security Concepts

### 1. File Access Control Roles & Entities
In a system, every file has an owner, and access is controlled through users, groups, and permissions:
- **Owner:** The user who currently owns the file and holds primary administrative control over its ACL.
- **Creator:** The user who initially created the file; may or may not remain its owner if ownership is reassigned (e.g., Rahul creates `secret.txt`; Alice is assigned as current Owner/Admin).
- **Group:** A collection of users sharing departmental permissions (e.g., `comp_eng`, `devs`, `hr`).
- **User:** An individual account requesting access to the file.
- **Others:** Users outside the owner/group categories (World).

### 2. The Top-Down Approach (&darr;)
Access permissions are determined from a higher-level authority or parent directory downward toward files and users beneath it:
1. **Level 1 (Owner / Administrator):** Sets high-level organizational rules and directory default ACLs (e.g., `/departments/comp_eng/`).
2. **Level 2 (Group):** Grants shared permissions for department members (e.g., `comp_eng` department members receive `r-x`).
3. **Level 3 (Users & Files):** Child files dynamically inherit directory-level default ACLs. Users access resources according to inherited and explicit rules.

## Features
- **Hierarchical Virtual File System:** Resources organized under parent directories (`/departments/comp_eng/secret.txt`, `/departments/comp_eng/lab_manual.c`, `/finance/payroll.csv`, `/home/bob/project.sh`, `/var/www/index.html`).
- **Top-Down Directory Inheritance:** Toggleable propagation of Parent Directory Default ACLs (`default:group:comp_eng:r-x`) to child files.
- **Interactive ACL Editor:** Add, modify, and delete Access Control Entries (ACEs) for users, groups, ACL Mask, and base permissions.
- **Sequential Authorization Engine:** Real-time permission checking applying POSIX evaluation precedence rules:
  0. Superuser (Root) bypass
  1. Resource Owner match (controls rules; creator noted in audit metadata)
  2. Named User match (explicit file ACE overrides inherited directory default, filtered by Mask)
  3. Group union (combines explicit and inherited group permissions, filtered by Mask)
  4. Other (World) fallback / Default Deny
- **Execution Trace Log:** Comprehensive multi-phase trace illustrating the Top-Down hierarchy check, entity classification, precedence traversal, and final decision.
- **POSIX Equivalent Output:** Real-time generation of `getfacl` output with directory defaults, creator/owner metadata, and active ACEs.
- **Interactive Assessment:** 5-question multiple-choice quiz covering ACL fundamentals, the Top-Down model, inheritance, and entity roles.

## Technical Specifications

### Inputs
- **Resource Selection:** Target file organized by directory hierarchy.
- **Inheritance Toggle:** Enable/disable downward propagation of parent directory default ACLs.
- **ACL Rule Management:**
  - Entity Type: Named User, Named Group, ACL Mask, Other (World), File Owner
  - Entity Identity (String)
  - Permissions: Read (`r`), Write (`w`), Execute (`x`)
- **System User Manager:** Add users and assign departmental groups.
- **Authorization Tester:**
  - Requesting Subject: Rahul (`comp_eng`), Alice (`admins, comp_eng, hr`), Bob (`devs`), Charlie (`devs, hr`), Eve (`guests`), Root (`root, admins`)
  - Requested Operation: Read (`r`), Write (`w`), Execute (`x`)

### Outputs
- **Resource Metadata Card:** Displays Parent Directory, Creator, Current Owner, and Owning Group.
- **Active ACL Table:** Badges distinguishing *Inherited (Dir Default)* vs *Explicit File ACE*.
- **CLI Commands:** Formatted POSIX `getfacl` output.
- **Execution Engine Trace:** Step-by-step audit showing Top-Down authority, inheritance, and precedence.

## Test Cases

| Scenario | Input state | Expected Output |
| :--- | :--- | :--- |
| **Top-Down Inheritance** | User = `rahul` (in `comp_eng`), File = `secret.txt`, Inheritance = ON | ALLOW Read/Execute (Inherited from `/departments/comp_eng/` default ACL) |
| **Creator vs Owner** | User = `rahul` (Creator), File = `secret.txt` | Read ALLOW, Write DENY (Owner Alice controls ACL; Rahul has explicit `r--` ACE) |
| **Explicit Override** | File has explicit `user:bob:r--`, Group has `rw-` | ALLOW Read, DENY Write (Explicit User ACE takes precedence over group) |
| **Mask Limitation** | Group has `rw-`, ACL Mask set to `r--` | ALLOW Read, DENY Write (Effective rights capped by Mask) |
| **Root Bypass** | User = `root`, File = `payroll.csv` | ALLOW (Root superuser bypass) |

## Local Testing
From the repository root, start the local server:
```bash
python -m http.server 8080
```
Navigate to:
`http://localhost:8080/experiments/access-control-list/index.html`
