# Bcrypt Password Hashing & Security Analysis

**Group:** Bcrypt (branch `group-bcrypt`)  
**Members (per faculty allotment):** Shwet Shigwan, Daksh Shetty  
**Experiment ID:** Group 11 (Module 11)  
**Experiment Name:** Bcrypt Password Hashing & Security Analysis  
**Folder:** `/experiments/bcrypt/`  
**Entry File:** `index.html`  
**Navigation Title:** Bcrypt  
**Expected Navigation Link:** `/experiments/bcrypt/`  
**Short Description:** Implement bcrypt password hashing and verification, analyze the effect of the cost factor on computational complexity, test non-deterministic salt generation, and evaluate the 72-byte key truncation limit.

---

## Aim
To study, implement, and analyze the **Bcrypt adaptive password hashing algorithm**. This includes evaluating the function of cryptographic salts, verifying passwords, formulating the exponential work factor ($2^{\text{Cost}}$), parsing modular hash formatting (`$2b$cost$salt+digest`), inspecting internal pipeline stages, and demonstrating the 72-byte truncation boundary.

---

## Required Libraries
Bundled in repository `js/vendor/`, no extra installation needed:
- `bcrypt.min.js` (Bcrypt adaptive hashing and verification compiled from C sources)
- `../../js/common.js` (Virtual laboratory tab routing controller)

---

## Run Locally
From the repository root:
```bash
python -m http.server 8000
```
Open [http://localhost:8000/experiments/bcrypt/index.html](http://localhost:8000/experiments/bcrypt/index.html) in your browser.

---

## Experiment Sections (Tabs)
1. **Aim & Objectives:** Core concepts, learning outcomes, and group allocation.
2. **Theory (8 In-depth Sections & Active Recall):**
   - Hashing vs. Encryption mathematical distinction.
   - Why Bcrypt? (Fast vs Slow algorithms & GPU/ASIC resistance).
   - Salt entropy & $2^C$ exponential work factor scaling table.
   - 60-character modular hash anatomy breakdown ($2b$, cost, 22-char salt, 31-char digest).
   - The 72-byte password limitation in Eksblowfish and SHA-256 pre-hashing workaround.
   - Eksblowfish Architecture (P-Arrays, S-Boxes, and 4KB L1 Cache Footprint).
   - Evolution of Revisions ($2, $2a, $2x, $2y, $2b$) and bug history.
   - Modern Password Security: Bcrypt vs. Argon2id vs. PBKDF2, Pepper vs Salt architecture, and dynamic re-hashing on login.
   - **Interactive Flashcards:** 6 active-recall flip cards for rapid self-testing.
3. **Procedure:** 8 guided procedural steps.
4. **Simulation (10 Interactive Workbench Tools & Guided Popups):**
   - **Guided Tour & Concept Glossary Popups:** Beginner-friendly walk-through and glossary modal dialogs.
   - **Tool 1: Bcrypt Hash Generator** with cost factor selection, dynamic cost advisor, live latency measurement (ms), calculated work rounds ($2^C$), byte counter progress bar, and 72-byte truncation warnings.
   - **Tool 2: Password Match Verifier** with step-by-step verification flow modal.
   - **Tool 3: Random Salt Demonstration** proving non-deterministic hashing with 128-bit CSPRNG salts.
   - **Tool 4: Modular Hash Inspector** with clickable token popup modals for deep disassembly.
   - **Tool 5: 5-Stage Eksblowfish Pipeline Stepper** with automated step-by-step playback.
   - **Tool 6: 72-Byte Truncation Exploit & SHA-256 Mitigation Workbench** demonstrating real hash collisions on truncated passwords.
   - **Tool 7: Hash Race (MD5 vs SHA-256 vs Bcrypt)** visual benchmark proving GPU speed vulnerability.
   - **Tool 8: Hardware Sizing Benchmark** simulating authentication latency across microcontrollers, smartphones, and servers.
   - **Tool 9: GPU Cracking Time Estimator** computing cracking durations across work factors $2^4$ to $2^{16}$.
   - **Tool 10: Rainbow Table Attack Simulator** demonstrating precomputed hash lookups and salt immunity.
5. **Assessment / Quiz:** 5 multiple-choice questions with instant scoring and detailed explanations.
6. **References:** Standardized reference cards (USENIX Provos-Mazières 1999 paper, RFC 7914, OWASP Cheat Sheet, Solar Designer crypt_blowfish advisory).
7. **Feedback:** Universal RSA-2048 encrypted feedback submission system.

---

## Test Cases

| # | Action | Expected Output |
|---|---|---|
| 1 | Generate hash with Cost = 10 | 60-character hash starting with `$2b$10$`, ~100 ms execution time, 1,024 rounds |
| 2 | Increase Cost from 10 to 12 | Work rounds quadruple ($2^{12} = 4,096$), execution time scales accordingly (~400 ms) |
| 3 | Enter password exceeding 72 bytes | Byte counter turns red, silent truncation warning banner appears |
| 4 | Send hash to Verifier and verify matching password | Status banner displays green: "PASSWORD MATCH CONFIRMED" |
| 5 | Verify hash with modified password character | Status banner displays red: "VERIFICATION FAILED (NO MATCH)" |
| 6 | Run Random Salt Test on identical password | Three distinct hashes generated, all verify TRUE against the single password |
| 7 | Paste generated hash into Modular Inspector | Disassembles accurately into Version, Cost, 22-char Salt, and 31-char Digest |
