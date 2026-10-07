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
Implement Argon2id password hashing and verification, and compare its output and cost parameters with MD5, SHA-1, SHA-256 and PBKDF2-SHA256. Demonstrate with a simulated dictionary attack why salting and memory cost slow an attacker.

## Files
| File | Purpose |
|---|---|
| `index.html` | Page: Theory (with algorithm explorer), Procedure, Simulation and Quiz tabs |
| `script.js` | Argon2id hashing (Web Worker with main-thread fallback), verification, A/B and algorithm comparison, process diagram, memory visualizer, algorithm explorer and quiz |
| `attack-lab.js` | Attack lab (dictionary attack on SHA-256 vs Argon2id) and GPU memory calculator. Loaded after `script.js` (optional add-on) |
| `README.md` | This file |

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
| Memory cost m | Whole number, 8 x p to 65536 KiB (number box, -/+ buttons or slider) |
| Time cost t | Whole number, 1 to 10 |
| Parallelism p | Whole number, 1 to 4 |
| Verify: stored hash, password | Hash must start with `$argon2id$` and have 6 parts |
| Comparison: Configuration A and B | m, t, p with the same limits as above ("Use current inputs" copies the main controls) |
| Attack lab: GPU memory (GiB), GPU cores | Positive numbers; illustrative assumptions (defaults 24 GiB, 10000 cores) |
| Quiz | 10 questions, all compulsory |

## Outputs
- Argon2id encoded hash `$argon2id$v=19$m=..,t=..,p=..$salt$hash` with parsed fields (version, m, t, p, salt, 32-byte digest in hex)
- Measured elapsed time in the browser
- Verification result: MATCH or NO MATCH
- Observation table of previous runs
- Theory tab: animated 7-step Argon2id algorithm visualizer (H0 seed, memory matrix, first blocks, compression function G with the 8x8 permutation, reference-block choice in data-independent vs data-dependent mode, lanes/slices/passes with barriers, final tag). Controls: step chips, Previous/Next, Play/Pause, timeline scrubber, speed, lanes p and passes t
- Procedure tab: interactive checklist with progress bar; steps tick themselves when you perform them, and "Show me" jumps to and highlights the right control
- Animated process diagram (Password, Salt, m/t/p, Argon2id, Encoded hash, Verify) that plays on hashing and verification
- Memory visualizer (canvas schematic, lanes = p, passes = t, phases: allocating, data-independent, data-dependent, later passes) with Play/Pause/Replay, speed slider, live stats, a "What is happening?" panel and a block inspector (hover or tap a square). It is a visualization, not real cryptographic progress
- Parameter cards with -/+ buttons, sliders and hints, live configuration summary, "?" tooltips, live password strength estimate
- Configuration comparison (A vs B, editable m, t, p) with animated bars, plus the algorithm comparison; copy button and avalanche view
- Comparison table: MD5, SHA-1, SHA-256, PBKDF2-SHA256 (600000 iterations), Argon2id with output length, cost parameters, measured time and suitability
- Attack lab: a stolen-database table for four users (SHA-256 unsalted vs Argon2id salted), which users were cracked by a 10-word dictionary, guesses per second and time for 1 billion guesses in this browser
- GPU calculator: how many Argon2id guesses fit in the entered GPU memory at the current m, and a rough time estimate
- Quiz: 10 compulsory questions with a live progress bar; submitting is blocked until every question is answered, then score out of 10 with per-question feedback

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
| 14 | Quiz: click Submit with some questions unanswered, then answer all 10 and Submit | First attempt is blocked and unanswered questions are highlighted; then score out of 10 and per-question feedback; Try again resets |
| 15 | Theory tab: let the algorithm animation play, click step chips, drag the timeline, change p and t | Each of the 7 steps shows its own animation; the matrix reshapes with p; the passes in step 6 follow t |
| 16 | Generate twice with different passwords | Bit-difference line shows roughly 50% of 256 bits differ, changed hex highlighted |
| 17 | Run comparison | Guesses-per-second column and the SHA-256 vs Argon2id speed gap line appear |
| 18 | Attack lab: Launch dictionary attack (defaults) | alice, dave and bob CRACKED under both; carol safe under both; alice and dave SHA-256 hashes identical, Argon2id hashes different |
| 19 | Attack lab: launch with m = 4096, then m = 65536 | Argon2id guesses per second is lower at 65536; the GPU calculator shows fewer parallel guesses |
| 20 | Attack lab: change GPU memory (GiB) | Parallel guesses and time estimate update |
| 21 | Generate | Diagram nodes light in order, button shows Hashing then Hash generated, hash text is revealed, Copy hash shows Copied |
| 22 | Set p = 1, 2, 4 | Visualizer shows 1, 2 or 4 lanes |
| 23 | Pause mid-run, then Play | Stats freeze while paused; the animation resumes from the same point |
| 24 | Use - / + buttons and sliders | Values, summary card and visualizer update live; m stays between 8 x p and 65536 |
| 25 | Verify right, then wrong password | Animated tick with "Password verified"; then warning with shake and "Password does not match" |
| 26 | Compare A vs B | Animated bars for memory, t, p and measured time, with the timing disclaimer |
| 27 | Click a "?" | Themed tooltip opens; Escape or a click elsewhere closes it |
| 28 | Hover or tap a memory square | Text shows its lane, slice, state and phase |
| 29 | Type different passwords | Strength bar and text update live |
| 30 | Comparison: edit A and B or click Use current inputs, then Compare A vs B; try an invalid value | Bars animate; invalid values show an error |
| 31 | Procedure tab: click Show me, then perform the step | The tab switches, the control pulses, and the step ticks itself with an animated check |
| 32 | Procedure tab: finish all 10 steps, then Reset | Progress bar fills and shows "All steps complete"; Reset clears it |

## Known Limitations
- Timings are measured in the browser, vary between devices and runs, and are not a benchmark. Fast hashes are averaged over 200 runs; PBKDF2 and Argon2id are single runs.
- Memory use of Argon2id is the configured m value; browsers do not report per-call memory.
- Parallelism sets the number of lanes in the hash; hash-wasm runs in a single thread, so p may not reduce time.
- Salt is typed as UTF-8 text; real systems store random bytes.
- bcrypt and scrypt are not in the comparison (bcrypt has its own experiment; scrypt is not bundled).
- The password strength bar is a rough upper-bound estimate, not a real strength checker.
- The Attack lab uses a 10-word wordlist and 4 fixed users. It runs real hashes in the browser, but the GPU calculator uses illustrative hardware numbers and is not a benchmark of real attackers.
- The memory visualizer is a schematic. Its progress is not tied to the real computation: it waits near the end until the real hash finishes, then completes.
- The real hash runs in a Web Worker so the page stays responsive; if a worker cannot start, it falls back to the main thread and the animation may stutter.
- `attack-lab.js` is an optional add-on and can be deleted with its script tag.
- Educational tool: do not enter real passwords.