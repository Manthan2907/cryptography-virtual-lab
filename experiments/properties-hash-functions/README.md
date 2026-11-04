# Properties of Secure Hash Function

Analyze the properties of a secure cryptographic hash function, including preimage resistance, second-preimage resistance, collision resistance, and avalanche effect.

## Simulation Pipeline Architecture

The Simulation tab provides an automated 4-step sequential evaluation pipeline:

1. **Step 1: Pre-image Resistance (One-Way Property)**
   - Demonstrates the computational infeasibility of inverting target digest `h = H(m)` through an interactive brute-force inversion attack.
   - Evaluates exhaustive search space complexity ($\mathcal{O}(2^n) = 2^{256}$).

2. **Step 2: Second Pre-image Resistance (Weak Collision Resistance)**
   - Demonstrates targeted tampering tests on fixed message `m1` attempting to find `m2 != m1` such that `H(m2) == H(m1)`.
   - Confirms document/transaction integrity guarantees with $\mathcal{O}(2^n) = 2^{256}$ security bounds.

3. **Step 3: Collision Resistance (Birthday Attack Demonstration)**
   - Demonstrates the Birthday Paradox by detecting an authentic collision on a 16-bit prefix in real-time ($\approx 320$ trials).
   - Contrasts the reduced slice with the full 256-bit SHA-256 bound of $2^{128}$ operations ($\approx 3.4 \times 10^{38}$).

4. **Step 4: Avalanche Effect (Strict Avalanche Criterion - SAC)**
   - Evaluates diffusion metrics between Message 1 and Message 2.
   - Calculates Hamming distance, bit variation percentage (ideal: $\approx 50\%$), visual gauge, and detailed 8-word (32-bit each) bitwise XOR comparison.

## Inputs
- **Message 1:** The primary message string.
- **Message 2:** The perturbed message string (ideally with a single character or bit variation). An **Auto ±1** button is provided to instantly generate a 1-character difference.

## Automation & Interactivity
- **Sequential Auto-Progression:** Starting the pipeline automatically executes Step 1, transitions to Step 2, transitions to Step 3, and transitions to Step 4 with live visual feedback and progress tracking.
- **Manual Tab Navigation:** Students can click any of the 4 step tabs at any time to pause or inspect individual steps.
- **Step Re-test:** Each step includes a dedicated rerun button to test that specific attack/simulation independently.

## Dependencies
- `crypto-js.min.js`: Used to compute the SHA-256 hashes of the inputs within the browser.
- Browser support for ES6+ JavaScript.

## Test Cases
- **Test Case 1 (Avalanche Effect):**
  - Input 1: `Cryptography Lab 2026`
  - Input 2: `Cryptography Lab 2027`
  - Expected Outcome: The avalanche percentage should be close to 50% (around 128 bit flips).
- **Test Case 2 (Identical Input):**
  - Input 1: `Same Message`
  - Input 2: `Same Message`
  - Expected Outcome: 0 flipped bits, 0% avalanche percentage (demonstrating determinism).
- **Test Case 3 (Quiz):**
  - Correct answers: Q1: `b`, Q2: `c`, Q3: `a`, Q4: `c`, Q5: `c`, Q6: `b`, Q7: `b`.
  - Expected Outcome: Shows "7/7 Correct! Excellent job." in green.
