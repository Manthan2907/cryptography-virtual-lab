# Argon2id Password Hashing

**Group:** Argon2id (branch `group-argon2id`)
**Members (per faculty allotment):** Ephraim T Philip (10752), Shaaunak Pitale (10753)
**Experiment ID:** To be confirmed by the integration team (portal lists this as Group 13)
**Experiment Name:** Argon2id Password Hashing
**Folder:** `/experiments/argon2id/`
**Entry File:** `index.html`
**Navigation Title:** Argon2id
**Expected Navigation Link:** `/experiments/argon2id/`
**Short Description:** Implement Argon2id for password hashing and compare its output and computational parameters with conventional hash functions.

## Aim
Implement Argon2id password hashing and verification, and compare its output and cost parameters with MD5, SHA-1, SHA-256 and PBKDF2-SHA256.

## Required Libraries
Bundled in `js/vendor/`, no installation needed:
- `hash-wasm.min.js` (Argon2id hashing and verification)
- `crypto-js.min.js` (MD5 only)
- Browser Web Crypto API (SHA-1, SHA-256, PBKDF2-SHA256, random salt). Requires `http://localhost` or HTTPS.

## Run Locally
From the repository root:
```
python3 -m http.server 8000
```
Open `http://localhost:8000/experiments/argon2id/index.html`. Stop the server with Ctrl+C.

## Inputs
| Input | Rule |
|---|---|
| Password | Required, not empty |
| Salt | UTF-8 text, at least 8 bytes (Random salt button gives 16 random bytes as hex text) |
| Memory cost m | Whole number, 8 x p to 65536 KiB |
| Time cost t | Whole number, 1 to 10 |
| Parallelism p | Whole number, 1 to 4 |
| Verify: stored hash, password | Hash must start with `$argon2id$` and have 6 parts |

## Outputs
- Argon2id encoded hash `$argon2id$v=19$m=..,t=..,p=..$salt$hash` with parsed fields (version, m, t, p, salt, 32-byte digest in hex)
- Measured elapsed time in the browser
- Verification result: MATCH or NO MATCH
- Observation table of previous runs
- Memory fill visualizer (schematic of the lane/slice/pass schedule, blue = data-independent first half of pass 1, orange = data-dependent), presets, copy button and avalanche bit-difference view
- Comparison table: MD5, SHA-1, SHA-256, PBKDF2-SHA256 (600000 iterations), Argon2id with output length, cost parameters, measured time and suitability

## Test Cases
Expected hash values are not listed for Argon2id because they depend on the salt and library; check the properties instead.

| # | Action | Expected |
|---|---|---|
| 1 | Default inputs, Generate | Hash starting `$argon2id$v=19$m=19456,t=2,p=1$` and a time is shown |
| 2 | Generate twice with Random salt in between | Different salts and different hashes |
| 3 | Generate twice with the same password and salt | Identical hash |
| 4 | Change one character of the password | Different digest |
| 5 | Verify with the correct password | MATCH |
| 6 | Verify with a wrong password | NO MATCH |
| 7 | Set m = 4096, then m = 65536 (same t, p) | Encoded m changes; measured time is normally higher at 65536 |
| 8 | Set t = 1, then t = 6 | Encoded t changes; measured time is normally higher |
| 9 | Set p = 4 | Encoded string shows p=4 |
| 10 | Empty password | Error message, no hash |
| 11 | Salt shorter than 8 characters, or m > 65536, or t = 0 | Error message, no hash |
| 12 | Verify with text that is not an Argon2id hash | Error message |
| 13 | Password `abc`, Run comparison | MD5 `900150983cd24fb0d6963f7d28e17f72`, SHA-1 `a9993e364706816aba3e25717850c26c9cd0d89d`, SHA-256 `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| 14 | Quiz: answer all, Submit | Score and per-question feedback; Try again resets |
| 15 | Click a preset (Light / OWASP minimum / Heavy) | m, t, p fields update and the visualizer replays |
| 16 | Generate twice with different passwords | Bit-difference line shows roughly 50% of 256 bits differ, changed hex highlighted |
| 17 | Run comparison | Guesses-per-second column and the SHA-256 vs Argon2id speed gap line appear |

## Known Limitations
- Timings are measured in the browser, vary between devices and runs, and are not a benchmark. Fast hashes are averaged over 200 runs; PBKDF2 and Argon2id are single runs.
- Memory use of Argon2id is the configured m value; browsers do not report per-call memory.
- Parallelism sets the number of lanes in the hash; hash-wasm runs in a single thread, so p may not reduce time.
- Salt is typed as UTF-8 text; real systems store random bytes.
- bcrypt and scrypt are not in the comparison (bcrypt has its own experiment; scrypt is not bundled).
- Educational tool: do not enter real passwords.