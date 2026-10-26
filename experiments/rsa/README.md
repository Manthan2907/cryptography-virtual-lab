# RSA as a Digital Signature — Virtual Lab Module

## Module Information

- **Group:** RSA
- **Experiment ID:** EXP-RSA
- **Experiment Name:** RSA as a Digital Signature
- **Team Members:** Arnav Potale, Joel Wilson, Omkar Patil, Rahul Senapati
- **Branch:** `group-rsa`
- **Folder:** `/experiments/rsa/`
- **Entry File:** `index.html`
- **Navigation Title:** RSA as a Digital Signature
- **Short Description:** Generate an RSA digital signature for a given message with integrated MD5/SHA-1 hashing and verify the signature using the corresponding public key.

---

## 1. Inputs and Outputs

### Inputs:
- `p` (Integer): Prime number entered manually or generated randomly (e.g., 7).
- `q` (Integer): Distinct prime number entered manually or generated randomly (e.g., 23).
- `e` (Integer): Public exponent satisfying $1 < e < \phi(n)$ and $\gcd(e, \phi(n)) = 1$ (e.g., 5).
- `message (m)` (Integer): Plaintext numerical message satisfying $0 < m < n$ (e.g., 23).
- `hash algorithm`: Cryptographic hash function selected by user: **MD5** (128-bit) or **SHA-1** (160-bit).
- `signature (s)` (Integer): Received signature presented for verification (e.g., 46).

### Outputs:
- `n` (Integer): Modulus $n = p \times q$ (e.g., 161).
- `phi(n)` (Integer): Euler's totient $\phi(n) = (p - 1)(q - 1)$ (e.g., 132).
- `d` (Integer): Private exponent $d = e^{-1} \bmod \phi(n)$ (e.g., 53).
- `message digest H(m)`: 32 hex characters for MD5, 40 hex characters for SHA-1.
- `digital signature (s)`: Computed signature $s = m^d \bmod n$ (e.g., 46).
- `recovered message (m')`: Decrypted value $m' = s^e \bmod n$ (e.g., 23).
- `verification status`: `VALID` when digests match under the identical hash algorithm; `INVALID` upon tampering, hash mismatch, or outdated key state.

---

## 2. Core Educational Architecture & Features

### Pipeline Flow:
```
KEY GENERATION (p, q → n, phi(n), e, gcd, d)
      ↓
MESSAGE (m)
      ↓
HASH MESSAGE (MD5 / SHA-1 via CryptoJS)
      ↓
MESSAGE DIGEST (128-bit / 160-bit hexadecimal)
      ↓
RSA SIGNING (s = m^d mod n)
      ↓
DIGITAL SIGNATURE (s)
      ↓
HASH MESSAGE AGAIN (Receiver computes H(m))
      ↓
RSA VERIFICATION (m' = s^e mod n → Recovered Digest)
      ↓
COMPARE DIGESTS (Calculated H(m) vs Recovered Digest)
      ↓
VALID / INVALID VERDICT
```

1. **State Synchronization & Outdated Key Invalidation:**
   - Single source of truth: Editing $p, q$, or $e$ immediately marks keys as **Outdated** (`(Keys Outdated — Click Generate Keys)`).
   - Stale keys cannot be silently used for signing or verification; keys must be regenerated via `[ Generate Keys ]`.
2. **Coprimality & Explicit GCD Derivation:**
   - Checks $1 < e < \phi(n)$ and $\gcd(e, \phi(n)) = 1$.
   - When $\gcd(e, \phi(n)) \neq 1$ (e.g., $p=7, q=23 \implies \phi(n)=132$ and $e=6 \implies \gcd(6, 132) = 6$):
     - Displays actual $\gcd$ calculation: $\gcd(6, 132) = 6$.
     - Explicitly reports: *"✕ Invalid public exponent — Reason: e must be coprime with phi(n) so that its modular inverse exists."*
     - Halts calculation with: *"d cannot be calculated because e has no modular inverse modulo phi(n)."*
3. **Cryptographic Hashing Integration (MD5 & SHA-1):**
   - Direct integration with `js/vendor/crypto-js.min.js` (`CryptoJS.MD5()` and `CryptoJS.SHA1()`).
   - Generates authentic, live cryptographic digests from the message (no hardcoded digests).
   - Visualizes exact digest lengths:
     - **MD5:** 128 bits / 32 hexadecimal characters.
     - **SHA-1:** 160 bits / 40 hexadecimal characters.
   - Highlights educational context: *"MD5 and SHA-1 are included for educational purposes. Both are considered unsuitable for modern secure digital-signature systems."*
   - Explicit node reference: *"Detailed MD5 and SHA-1 hashing algorithms are covered in the subsequent Virtual Lab node."*
4. **Educational Scope & RSA Distinction:**
   - Explicitly distinguishes educational arithmetic ($s = m^d \bmod n$ over small modulus $n$) from production-grade standardized schemes (such as PKCS#1 v1.5 or RSA-PSS with 2048-bit modulus and EMSA padding).
   - Prevents student misconception of feeding raw 128/160-bit digests into small educational moduli without formal padding.
5. **Hashed Verification & Mismatch Protection:**
   - Verifier hashes received message using the selected hash algorithm and compares with the signature-side digest representation.
   - If signer used SHA-1 and verifier switches to MD5, the signature is marked incompatible and verification reports **INVALID SIGNATURE**.
   - If message changes (e.g., $23 \to 24$), signature is invalidated as outdated.
6. **Detailed Mathematical Working:**
   - Full Euclidean division steps and Extended Euclidean back-substitution equations.
   - Modular repeated squaring breakdown with binary decomposition ($53 = 110101_2$) and dynamic powers-of-2 multiplication tables.
7. **Interactive Interception / Tampering Simulation:**
   - Simulates attacker modifying message $23 \to 24$ in transit while signature remains 46.
   - Visually demonstrates hash avalanche effect and verification failure.
8. **Assessment Quiz:**
   - 10 multiple-choice questions covering coprimality, hashing rationale, MD5/SHA-1 output bit lengths, tamper detection, and asymmetric authentication.

---

## 3. Test Cases and Formal Verification

The implementation is verified against the following formal test cases:

### TEST 1 — Valid Public Exponent e
- **Input:** $p = 7, q = 23, e = 5, m = 23$
- **Calculation:** $n = 161, \phi(n) = 132, \gcd(5, 132) = 1, d = 53$
- **Expected:** Keys generated successfully: Public $(5, 161)$, Private $(53, 161)$.
- **Status:** **PASS**

### TEST 2 — Invalid Public Exponent e ($\gcd \neq 1$)
- **Input:** $p = 7, q = 23, e = 6$
- **Calculation:** $\phi(n) = 132, \gcd(6, 132) = 6 \neq 1$
- **Expected:** No keys generated. Clear mathematical error: *"gcd(6, 132) = 6 ✕ Invalid public exponent"*, with notice that $d$ cannot be calculated.
- **Status:** **PASS**

### TEST 3 — MD5 Message Digest Generation
- **Input:** Message $m = 23$, Algorithm = MD5
- **Expected:** 128-bit / 32-character hexadecimal digest: `37693cfc748049e45d87b8c7d8b9aacd`.
- **Status:** **PASS**

### TEST 4 — SHA-1 Message Digest Generation
- **Input:** Message $m = 23$, Algorithm = SHA-1
- **Expected:** 160-bit / 40-character hexadecimal digest: `d435a6cdd786300dff204ee7c2ef942d3e9034e2`.
- **Status:** **PASS**

### TEST 5 — Same Algorithm Sign & Verify
- **Action:** Sign message 23 with MD5; verify message 23 with MD5.
- **Expected:** Digests match; verification verdict is **VALID SIGNATURE**.
- **Status:** **PASS**

### TEST 6 — Different Algorithm Incompatibility
- **Action:** Sign message 23 with SHA-1; switch verifier algorithm to MD5.
- **Expected:** Signature marked incompatible; warning displayed: *"Signature was generated using SHA-1. Generate a new signature using MD5."*; verdict is **INVALID SIGNATURE**.
- **Status:** **PASS**

### TEST 7 — Message Change / Tampering
- **Action:** Sign message 23 ($s = 46$); alter received message to 24.
- **Expected:** Calculated digest changes; digest mismatch detected; verification verdict is **INVALID SIGNATURE**.
- **Status:** **PASS**

### TEST 8 — Public Exponent Invalidation
- **Action:** Generate keys with $e = 5$. Change input to $e = 6$.
- **Expected:** Key badges immediately indicate *"Keys Outdated — Click Generate Keys"*; signing blocked until keys are regenerated.
- **Status:** **PASS**

---

## 4. Dependencies

- **CryptoJS:** `js/vendor/crypto-js.min.js` (provides `CryptoJS.MD5` and `CryptoJS.SHA1`).
- **Shared Assets:**
  - `../../css/variables.css`
  - `../../css/experiment.css`
  - `../../js/common.js`
  - `../../assets/logos/crce-header-banner.png`
- **Local Module Files:**
  - `style.css` (local to `/experiments/rsa/`)
  - `script.js` (local to `/experiments/rsa/`)
  - `index.html` (local to `/experiments/rsa/`)

---

## 5. Educational Scope & Limitations

1. **Educational Nature:** The RSA modular exponentiation demonstrations ($s = m^d \bmod n$ and $m' = s^e \bmod n$) operate on small pedagogical numbers to keep intermediate modular arithmetic transparent.
2. **Standardization Disclaimer:** This module explicitly does not implement production RSA padding standards (PKCS#1 v1.5 / RSA-PSS) or 2048-bit BigInt encoding.
3. **Subsequent Lab Nodes:** Complete algorithmic internal details of MD5 rounds and SHA-1 compression schedules are covered in the subsequent Virtual Lab experiments (`experiments/md5` and `experiments/sha1`).
