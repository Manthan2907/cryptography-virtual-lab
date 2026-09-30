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
2. **Theory:**
   - Hashing vs. Encryption comparison.
   - Why Bcrypt? (GPU vulnerability vs. intentional CPU/memory hardness).
   - Salt entropy & $2^C$ exponential work factor scaling table.
   - 60-character modular hash anatomy breakdown ($2b$, cost, 22-char salt, 31-char digest).
   - The 72-byte password limitation in Eksblowfish and the SHA-256 pre-hashing workaround.
3. **Procedure:** 8 guided procedural steps.
4. **Simulation (5 Interactive Tools):**
   - **Tool 1: Bcrypt Hash Generator** with cost factor selection (4, 8, 10, 12), live execution time measurement (ms), calculated work rounds ($2^C$), byte counter progress bar, and 72-byte truncation warnings.
   - **Tool 2: Password Match Verifier** performing client-side verification against stored hash strings.
   - **Tool 3: Random Salt Demonstration** proving that hashing the exact same password three times generates three completely different hashes, all of which successfully verify.
   - **Tool 4: Modular Hash Inspector** disassembling 60-character hashes into interactive subcomponents.
   - **Tool 5: 5-Stage Eksblowfish Pipeline Stepper** tracing the cryptographic progression from plaintext bytes to modular Radix-64 formatting.
5. **Assessment / Quiz:** 5 multiple-choice questions with instant scoring and detailed explanations.
6. **References:** USENIX Provos-Mazières 1999 paper, RFC specifications, and OWASP recommendations.
7. **Feedback:** Interactive star rating and suggestion submission form.

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
