# Brute Force Attack: Virtual Lab Experiment

An educational, browser-only demonstration of how a brute-force password attack works and why password length matters. The simulation runs locally. It does not connect to any account, server or real system.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | One page with six tabs: Theory, Procedure, Simulation, Quiz, References, Feedback |
| `script.js` | Simulation logic, 10-question quiz and tab helper |
| `style.css` | Styles for this experiment only (scoped under `.bf`) |

Shared files (`../../css/`, `../../js/`, `../../assets/`) belong to the main lab and are not modified.

## How to run

Open `experiments/brute-force/index.html` in Chrome, Firefox or Safari from inside the full repository, so the shared CSS and JS load.

## Simulation: inputs

| Input | Allowed values |
| --- | --- |
| Sample target password | 1 to 4 characters, all from the selected character set |
| Character set | Lowercase (26), Uppercase (26), Digits (10), Lowercase + digits (36), Lowercase + uppercase + digits + symbols (70) |
| Slow mode | On: one guess every 0.7 s. Off: normal speed |

Controls: **Start**, **Pause / Resume**, **Reset**.

## Simulation: outputs

| Output | Meaning |
| --- | --- |
| Current guess | The candidate checked most recently |
| Attempts | Number of candidates checked so far |
| Total combinations | Search space = C^L (C = characters in the set, L = length) |
| Progress | Attempts divided by total combinations |
| Elapsed time | Time spent in this browser demo (not a real-world cracking estimate) |
| Status message | Ready, running, paused, match found, or an error |

Guesses are generated in counting order, with the last character changing fastest (for example `aa`, `ab`, `ac` ...). The simulation stops as soon as the target is found.

## Test cases

| # | Input (target, character set) | Expected output |
| --- | --- | --- |
| 1 | `a`, lowercase | Total 26. Match found at attempt 1 |
| 2 | `z`, lowercase | Total 26. Match found at attempt 26 |
| 3 | `ab`, lowercase | Total 676. Match found at attempt 2 |
| 4 | `aba`, lowercase | Total 17,576. Match found at attempt 27 (same as the Theory example) |
| 5 | `zzz`, lowercase | Total 17,576. Match found at attempt 17,576 (the last candidate), progress 100% |
| 6 | `AB`, uppercase | Total 676. Match found at attempt 2 |
| 7 | `12`, digits | Total 100. Match found at attempt 13 |
| 8 | `a1`, lowercase + digits | Total 1,296. Match found at attempt 28 |
| 9 | `ab1`, lowercase only | Not run. Error: enter a valid 1-4 character target that matches the selected character set |
| 10 | Empty target, press Start | Not run. Error message shown |
| 11 | Press Start, then Pause, then Resume | Attempts and elapsed time stop while paused and continue after Resume |
| 12 | Press Reset during or after a run | All results return to zero and the input is unlocked |
| 13 | Try to type a 5th character | Not accepted (maximum length is 4) |

## Quiz

- 10 multiple-choice questions, 1 mark each.
- All questions must be answered before submitting.
- After submitting, the page shows the score out of 10, whether each answer was correct, the correct answer and a short explanation.
- **Retake quiz** clears the answers and the result.

## Limitations

- Targets are limited to 4 characters so the demo finishes quickly.
- The target is typed into a password-style field, so the characters are hidden.
- Elapsed time depends on the browser and device. It is not a real attack speed.
- The Feedback tab is provided by the shared `js/feedback.js`.

## For education only

Use only made-up sample passwords. Never enter a real password.