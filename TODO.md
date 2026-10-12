# TODO: Top-Down Approach (↓) and File Access Control Roles Implementation

## 1. Domain & Evaluation Logic (`experiments/access-control-list/functions.js`)
- [x] Create `functions.js` for pure functions with detailed JSDoc docstrings (keeping code modular & <350 lines).
- [x] Implement `mergeEffectiveAcl(file, directory, inheritDefault)` to compute effective ACEs from parent directory default rules and explicit file ACEs.
- [x] Implement `evaluateAccess(file, directory, user, operation, sysUsers, inheritDefault)` returning structured decision, granted set, and detailed top-down trace steps.
- [x] Implement `formatCliAcl(file, directory, inheritDefault)` generating POSIX `getfacl` syntax with `# creator:`, `# owner:`, `# group:`, and `default:` entries.
- [x] Implement `renderBadge(perm)` and `getPermissionsMarkup(perms)` pure UI helper functions.

## 2. Simulation State & Event Handling (`experiments/access-control-list/script.js`)
- [x] Import/load `functions.js` helper functions.
- [x] Update `sysUsers` to include `rahul` (Groups: `comp_eng`), `alice` (Groups: `admins`, `comp_eng`, `hr`), `bob` (Groups: `devs`), `charlie` (Groups: `devs`, `hr`), `eve` (Groups: `guests`), `root` (Groups: `root`, `admins`).
- [x] Structure `directories` and `fileSystem` to model hierarchical containers:
  - Directory: `/departments/comp_eng/` (Owner: `alice`, Group: `comp_eng`, Default ACL: `default:group:comp_eng:r-x`, `default:other::---`)
    - File: `/departments/comp_eng/secret.txt` (Creator: `rahul`, Owner: `alice`, Owning Group: `comp_eng`, inherits from directory)
    - File: `/departments/comp_eng/lab_manual.c` (Creator: `alice`, Owner: `alice`, Owning Group: `comp_eng`)
  - Directory: `/finance/`
    - File: `/finance/payroll.csv` (Creator: `alice`, Owner: `alice`, Group: `hr`)
  - Directory: `/home/bob/`
    - File: `/home/bob/project.sh` (Creator: `bob`, Owner: `bob`, Group: `devs`)
  - Directory: `/var/www/`
    - File: `/var/www/index.html` (Creator: `root`, Owner: `root`, Group: `devs`)
- [x] Add directory inheritance toggle (`inheritDirectoryAcl`) state and event handlers.
- [x] Update Active ACL Rules table to visually distinguish between:
  - Base rules (Owner, Owning Group, Other)
  - Inherited rules (from Parent Directory Default ACL)
  - Explicit File ACEs
- [x] Add UI controls to toggle inheritance and demonstrate Creator vs Owner access.
- [x] Connect `btnEvaluate` to `evaluateAccess()` and display the multi-phase Top-Down trace.

## 3. UI & Content Update (`experiments/access-control-list/index.html`)
- [x] Include `<script src="functions.js"></script>` before `script.js`.
- [x] **Theory Tab**:
  - [x] Add "File Access Control Roles & Entities" card with the complete table: Owner, Creator, Group, User, Others (featuring Rahul creating `secret.txt`).
  - [x] Add "Top-Down Approach (↓)" card with authority hierarchy: Administrator/Owner $\rightarrow$ Group $\rightarrow$ Users/Files.
  - [x] Add "Directory Default ACLs & Inheritance" card explaining how child files inherit parent rules and how explicit ACEs override them.
  - [x] Update sequential evaluation flow diagram to reflect the Top-Down Directory & Inheritance check.
- [x] **Procedure Tab**:
  - [x] Add step-by-step guidance on testing Top-Down Directory Inheritance and Creator vs. Owner distinction.
- [x] **Simulation Tab**:
  - [x] Add Resource Metadata card showing: Directory, File, Creator, Owner, Owning Group, and an interactive "Inherit from Parent Directory" switch.
  - [x] Update target resource dropdown with categorized optgroups (`/departments/comp_eng/`, `/finance/`, etc.).
  - [x] Ensure requesting subjects include `rahul` (in `comp_eng`).
- [x] **Quiz Tab**:
  - [x] Add questions testing the Top-Down Approach (↓), directory default ACL inheritance, and Creator vs. Owner concept.
  - [x] Align score calculation and feedback.

## 4. Verification & Testing
- [x] Test access evaluation for Rahul on `secret.txt` (Creator vs Owner Alice).
- [x] Test group member in `comp_eng` inheriting `r-x` from directory `/departments/comp_eng/`.
- [x] Test disabling inheritance and observing immediate fallback/explicit behavior.
- [x] Verify Quiz answers and score calculator.
- [x] Verify clean layout, mobile responsiveness, and dark mocha theme tokens.
