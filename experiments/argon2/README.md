# Experiment: Argon2 Password Hashing

> **Course:** Cryptography and System Security (CSS TH ISE)  
> **Institution:** Department of Computer Engineering, Fr. Conceicao Rodrigues College of Engineering (Fr. CRCE), Bandra, Mumbai  
> **Group:** Group 12 &bull; Advanced Track &bull; Branch: `group-argon2`  
> **Team Members:** Aarya Sawant, Disha Shetty, Chris Pereira, Lebron Pereira  

---

## 1. Overview & Objectives

This experiment provides an interactive, client-side virtual laboratory for studying the **Argon2** password hashing algorithm—the winner of the international Password Hashing Competition (PHC) and standardized under **RFC 9106**.

### Primary Objectives:
- **Understand Memory-Hard Functions (MHF):** Analyze how memory-hardness deters GPU and ASIC password-cracking attacks by forcing attackers to allocate dedicated physical memory per concurrent guess.
- **Compare Algorithm Variants:** Contrast **Argon2i** (data-independent memory access, side-channel timing attack resistant), **Argon2d** (data-dependent memory access, maximizing TMTO and GPU resistance), and **Argon2id** (hybrid mode recommended by RFC 9106 and OWASP).
- **Interactive Execution:** Generate client-side salted password hashes using WebAssembly, evaluate constant-time password verification, and benchmark parameter scaling.
- **Automated Verification:** Execute an in-browser digital verification suite covering boundary conditions, memory scaling, iteration passes, and knowledge checks.

---

## 2. Input Specifications

The simulation accepts the following user and system inputs:

| Input Parameter | Identifier | Type | Range / Options | Default | Description |
|---|---|---|---|---|---|
| **Candidate Password** | `password` | String | $1$ to $256$ UTF-8 characters | `VirtualLabPassword123` | Plaintext user password to be hashed. |
| **Verification Password** | `verifyPassword` | String | UTF-8 String | Blank | Password entered during authentication testing. |
| **Memory Cost ($m$)** | `memory` | Integer | $16384$, $32768$, $65536$, $131072$ KiB | $65536$ KiB ($64$ MiB) | Physical RAM allocated for the 2D memory matrix. |
| **Time Cost ($t$)** | `time` | Integer | $1$, $2$, $3$, $4$, $5$ passes | $3$ passes | Number of complete iteration passes across memory blocks. |
| **Parallelism ($p$)** | `parallelism` | Integer | $1$, $2$, $3$, $4$ lanes | $1$ lane | Number of independent computational threads/lanes. |
| **Cryptographic Salt** | System Generated | Bytes | 16 bytes (128 bits) | `crypto.getRandomValues(16)` | Cryptographically secure random salt generated fresh per trial. |
| **Output Tag Length** | System Generated | Integer | 32 bytes (256 bits) | 32 bytes | Length of the final derived authentication digest. |

---

## 3. Output Specifications

The laboratory generates standardized cryptographic outputs adhering to **RFC 9106** and **PHC** formats:

| Output | Element ID | Format | Example / Format Description |
|---|---|---|---|
| **Argon2i PHC String** | `argon2iOutput` | RFC 9106 Serialized | `$argon2i$v=19$m=65536,t=3,p=1$<salt-b64>$<tag-b64>` |
| **Argon2d PHC String** | `argon2dOutput` | RFC 9106 Serialized | `$argon2d$v=19$m=65536,t=3,p=1$<salt-b64>$<tag-b64>` |
| **Argon2id PHC String** | `argon2idOutput` | RFC 9106 Serialized | `$argon2id$v=19$m=65536,t=3,p=1$<salt-b64>$<tag-b64>` |
| **Execution Latencies** | `*Time` | Float (ms) | Real-time millisecond execution times (e.g., `42.50 ms`). |
| **Verification Result** | `verifyResult` | Status Badge | `✓ Password Verified` (match) or `✗ Verification Failed` (mismatch). |
| **Benchmark Telemetry** | `resultsTable` | Tabular row | Trial index, RAM (MB), passes ($t$), parallelism ($p$), elapsed time (ms). |

### Encoded Hash Format Anatomy:
```text
$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0MTY$aGFzaGhhc2hoYXNoMzJieXRlcw...
   │       │   └──────┬──────┘ └──────┬───────┘ └───────────┬───────────┘
   │       │          │               │                     └─ Derived 32-byte Base64 Tag
   │       │          │               └─ 16-byte Cryptographic Salt (Base64)
   │       │          └─ Cost Parameters: m (RAM in KiB), t (passes), p (lanes)
   │       └─ Argon2 Version: v=19 (0x13)
   └─ Algorithm Variant: argon2i, argon2d, or argon2id
```

---

## 4. Dependencies & Technical Stack

- **HTML5 & CSS3:** Responsive UI using modern Flexbox, CSS Grid, and custom themed components adhering to the Virtual Cryptography Laboratory shell.
- **Vanilla JavaScript (ES6+):** Pure client-side logic for DOM interaction, telemetry benchmarking, quiz evaluation, and digital test suite execution.
- **WebAssembly Engine:** [`argon2-browser`](https://github.com/antelle/argon2-browser) v1.18.0 bundled via CDN (`dist/argon2-bundled.min.js`), compiling optimized C Argon2 code to WASM for near-native in-browser performance.
- **Cryptographic Entropy:** Browser-native Web Cryptography API (`window.crypto.getRandomValues`) for cryptographically secure pseudo-random salt generation.

---

## 5. Documented Test Cases

The experiment includes an automated 12-test digital verification suite accessible in the **Test Cases** tab.

| Test Case ID | Category | Test Scenario | Input Data | Expected Output | Actual Result |
|---|---|---|---|---|---|
| **TC01** | Validation | Empty Password Guard | `password = ""` | Validation error prompts user; hash generation halted | Pass |
| **TC02** | Security | Triple-Variant Generation | `password = "VirtualLabPassword123"`, $m=64\text{MB}$, $t=3$, $p=1$ | Valid Argon2i, Argon2d, and Argon2id RFC 9106 strings generated with execution times $>0\text{ ms}$ | Pass |
| **TC03** | Validation | Password Visibility Toggle | Toggle `#showPassword` | Field input type toggles between `password` and `text` | Pass |
| **TC04** | Verification | Authentic Password Match | Matching `password` and stored Argon2i hash | Verification succeeds with `✓ Password Verified` confirmation | Pass |
| **TC05** | Verification | Mismatched Password Rejection | Corrupted/wrong password against stored hash | Verification fails securely with `✗ Verification Failed` | Pass |
| **TC06** | Verification | Pre-Hash Guard Integrity | Attempt verification with `generatedHash = ""` | Error prompts user to generate hash first; uninitialized state safely guarded | Pass |
| **TC07** | Security | Memory Hardness Scaling | Scale memory from $64\text{ MB}$ to $128\text{ MB}$ ($t=1, p=1$) | RAM doubles; both hashes successfully computed with memory footprint logged | Pass |
| **TC08** | Security | Time Cost Pass Scaling | Compare $t=1$ pass vs $t=3$ passes ($m=16\text{MB}, p=1$) | Execution latency scales upward monotonically ($T_{t=1} < T_{t=3}$) | Pass |
| **TC09** | Parameters | Benchmark Telemetry | Run benchmark trial ($16\text{ MB}, t=1, p=1$) | New record appended to observation table with trial number and timings | Pass |
| **TC10** | Quiz | Empty Quiz Submission Guard | Submit quiz with 0 radio buttons checked | 10 warning badges displayed for unselected questions; score evaluates to `0/10` | Pass |
| **TC11** | Quiz | Perfect Quiz Evaluation | Submit quiz with all 10 correct answers | Final score evaluates to `10/10 (100%)` with "Excellent!" banner | Pass |
| **TC12** | Quiz | Assessment State Reset | Click `Retake Quiz` button after completion | All radio inputs unchecked, all feedback alerts removed, score banner cleared | Pass |

---

## 6. Known Limitations & Scope Note

1. **Browser Memory Caps:** WebAssembly memory allocation is constrained by browser heap limits (typically $2\text{ to }4\text{ GB}$). High memory costs ($>512\text{ MB}$) may fail on memory-constrained mobile devices.
2. **Single-Threaded WASM Fallback:** While parallelism ($p$) is configurable, standard in-browser WebAssembly execution without SharedArrayBuffer Web Workers processes lanes sequentially on a single core. In production backend environments, lanes execute concurrently across CPU cores.
3. **Production Recommendation:** For production authentication servers, Argon2id with at least $64\text{ MiB}$ RAM, $t=3$ passes, and $p=4$ lanes is recommended per RFC 9106 and OWASP. This virtual lab is designed for educational exploration and parameter analysis.
