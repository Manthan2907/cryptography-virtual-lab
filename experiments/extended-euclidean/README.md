# Extended Euclidean Algorithm

**Experiment Name:** Extended Euclidean Algorithm
**Student:** Nemi Gada
**Roll No:** 10729
**Folder:** experiments/extended-euclidean/
**Entry File:** index.html
**Navigation Title:** Extended Euclidean Algorithm

## Short Description
Calculate the GCD of two integers and determine the Bézout coefficients using the Extended Euclidean Algorithm.

## Required Libraries
None. Uses only standard JavaScript and shared CSS/JS from the repository:
- `../../css/variables.css`
- `../../css/experiment.css`
- `theory.css` (experiment-scoped styles for the interactive Theory tab)
- `simulation.css` (experiment-scoped styles for the Steps table arrows and GCD ring)
- `../../js/common.js` (tab navigation)
- `theory.js` (experiment-scoped Theory tab steppers and knowledge checks)
- `../../js/students-roster.js` (roll-number lookup used by the feedback form)
- `../../js/crypto-feedback.js` (RSA-2048 encryption)
- `../../js/feedback.js` (standardized encrypted feedback form)

## Input
Two integers a and b (positive, negative, or zero)

## Output
- GCD(a, b)
- Bézout coefficients x and y
- Step-by-step Euclidean Algorithm division table
- Bézout coefficients tracking table
- Bézout identity verification (a×x + b×y = gcd(a,b))
- Modular multiplicative inverse, shown only when gcd(a,b) = 1 **and** the relevant modulus is greater than 1. A modulus of 0 is never evaluated (reported as "not defined"); modulus 1 is treated as the trivial ring.

---

## Aim
Implement the Extended Euclidean Algorithm to compute the greatest common divisor (GCD) of two integers and find the Bézout coefficients that satisfy Bézout's identity: a×x + b×y = gcd(a, b).

## Objectives
- Understand the Euclidean Algorithm for computing GCD of two integers
- Extend the algorithm to compute Bézout coefficients (x, y) such that a×x + b×y = gcd(a, b)
- Visualize the step-by-step division process of the Euclidean Algorithm
- Verify Bézout's identity for given input values
- Understand the relationship between Bézout coefficients and modular multiplicative inverses
- Apply the algorithm to cryptographic contexts (RSA key generation, modular inverses)

## Theory Summary

### Euclidean Algorithm
The Euclidean Algorithm finds the GCD of two integers a and b by repeated division:
```
a = b × q₁ + r₁    (0 ≤ r₁ < b)
b = r₁ × q₂ + r₂   (0 ≤ r₂ < r₁)
r₁ = r₂ × q₃ + r₃  (0 ≤ r₃ < r₂)
...
rₙ₋₂ = rₙ₋₁ × qₙ + rₙ
rₙ₋₁ = rₙ × qₙ₊₁ + 0
```
The last non-zero remainder rₙ is the GCD of a and b.

### Extended Euclidean Algorithm
Computes integers x and y (Bézout coefficients) such that:
```
a × x + b × y = gcd(a, b)
```
This is Bézout's identity. The coefficients are not unique; if (x, y) is one solution, all solutions are:
```
x' = x + k·(b/gcd),  y' = y - k·(a/gcd)  for any integer k
```

### Modular Inverse Relationship
When gcd(a, b) = 1, we have a×x + b×y = 1, which means a×x ≡ 1 (mod b).
Thus x (mod b) is the modular multiplicative inverse of a modulo b.
This is crucial in RSA key generation where we find d such that e×d ≡ 1 (mod φ(n)).

A modular inverse is only meaningful for a modulus greater than 1. A modulus of 0 is
undefined, and modulus 1 is the trivial ring. The simulation therefore shows the
inverse only when the relevant modulus is greater than 1; otherwise it explicitly
reports that the inverse is not defined (it never evaluates a zero modulus, which
would produce `NaN`).

### Complexity
- **Time:** O(log min(a, b)) - number of division steps ≤ 5×digits of smaller number (Lamé's theorem)
- **Space:** O(1) iterative, O(log min(a, b)) recursive

## Algorithm
1. Initialize: (old_r, r) = (|a|, |b|), (old_x, x) = (1, 0), (old_y, y) = (0, 1)
2. While r ≠ 0:
   - quotient = old_r ÷ r
   - (old_r, r) = (r, old_r - quotient × r)
   - (old_x, x) = (x, old_x - quotient × x)
   - (old_y, y) = (y, old_y - quotient × y)
3. Result: gcd = old_r, x = old_x, y = old_y
4. Adjust signs: if a < 0, x = -x; if b < 0, y = -y

## Procedure
1. Enter the first integer **a** in the input field
2. Enter the second integer **b** in the input field
3. Click **Calculate** to start the Extended Euclidean Algorithm
4. Observe the step-by-step table showing each division step with dividend, divisor, quotient, and remainder
5. View the computed Bézout coefficients x and y
6. Verify Bézout's identity: a×x + b×y = gcd(a, b) with actual substituted values
7. If gcd(a, b) = 1, examine the **Modular Inverse** section. Each inverse is shown for a modulus greater than 1; a zero or trivial (1) modulus is reported as "not defined"
8. Click **Clear** to reset the simulation and enter new values

## Simulation Description
The simulation provides:
- Two input fields for integers a and b with validation
- **Calculate** and **Clear** buttons
- Dynamic results display including:
  - GCD result
  - Bézout coefficients x and y
  - Step-by-step Euclidean division table (Step, Dividend, Divisor, Quotient, Remainder)
  - Bézout coefficients tracking table showing evolution of (x, y) at each step
  - Bézout identity proof card with substituted values and a verified / not-verified badge
  - Modular inverse section (shown when gcd = 1, with each inverse shown only for a modulus greater than 1; zero and trivial moduli are reported as not defined)
- Step-table visualization:
  - Diagonal transition arrows (divisor → next dividend, remainder → next divisor)
  - A green GCD ring around the divisor of the final step (the GCD, which equals the last non-zero remainder)
  - A legend naming the arrow colors, the GCD ring, and the Bézout result circle
- Bézout proof card with a circle around the evaluated a×x + b×y result (green when it equals the GCD, red otherwise)
- Interactive Theory tab:
  - Progressive steppers for the worked examples
  - Bézout verification buttons (valid and deliberately invalid coefficient pairs)
  - Modular-inverse checks, including a non-coprime example
  - Quick knowledge-check questions with immediate explanations
- 10-question Assessment / Quiz with per-question feedback and a final score

## Test Cases

These cases are exercised by the simulation and by the algorithm test harness. All
non-zero cases satisfy `a×x + b×y = gcd(a, b)` with the displayed coefficients.

| Case | a | b | Expected GCD | Notes |
|------|---|---|--------------|-------|
| 1 | 240 | 46 | 2 | Non-coprime; x = −9, y = 47 |
| 2 | 99 | 78 | 3 | Non-coprime; x = −11, y = 14 |
| 3 | 17 | 5 | 1 | Coprime; a⁻¹ mod 5 = 3, b⁻¹ mod 17 = 7 |
| 4 | 5 | 17 | 1 | Coprime (order swapped); a⁻¹ mod 17 = 7, b⁻¹ mod 5 = 3 |
| 5 | 12 | 8 | 4 | Non-coprime; no modular inverse |
| 6 | 1 | 1 | 1 | gcd = 1 but both moduli are 1; inverses reported "not defined" |
| 7 | 0 | 15 | 15 | One zero; x = 0, y = 1; no inverse (gcd ≠ 1) |
| 8 | 15 | 0 | 15 | One zero; x = 1, y = 0; no inverse (gcd ≠ 1) |
| 9 | 0 | 1 | 1 | gcd = 1 but both moduli ≤ 1; no inverse displayed |
| 10 | 1 | 0 | 1 | gcd = 1 but both moduli ≤ 1; no inverse displayed |
| 11 | 0 | 0 | undefined | Both zero; error message, no results |
| 12 | −240 | 46 | 2 | Negative a; x = 9, y = 47 |
| 13 | 240 | −46 | 2 | Negative b; x = −9, y = −47 |
| 14 | −17 | 5 | 1 | Negative a; inverse verification normalised to ≡ 1 (mod 5) |
| 15 | 17 | −5 | 1 | Negative b; inverse verification normalised to ≡ 1 (mod 17) |
| 16 | −17 | −5 | 1 | Both negative; identity still holds |

## Expected Outputs

### Case 1: a = 240, b = 46
```
gcd(240, 46) = 2
Bézout coefficients: x = -9, y = 47
Verification: 240×(-9) + 46×47 = -2160 + 2162 = 2 ✓
Modular inverse: not shown (gcd ≠ 1)
```

### Case 3: a = 17, b = 5
```
gcd(17, 5) = 1
Bézout coefficients: x = -2, y = 7
Verification: 17×(-2) + 5×7 = -34 + 35 = 1 ✓
Modular inverses: 17⁻¹ mod 5 = 3, 5⁻¹ mod 17 = 7
Verification lines: 17×3 ≡ 1 (mod 5), 5×7 ≡ 1 (mod 17)
```

### Case 7: a = 0, b = 15
```
gcd(0, 15) = 15
Bézout coefficients: x = 0, y = 1
Verification: 0×0 + 15×1 = 15 ✓
Modular inverse: not shown (gcd ≠ 1)
```

### Zero-modulus inverse cases (0, 1), (1, 0) and (1, 1)
```
gcd = 1, but neither modulus is greater than 1.
The Modular Inverse section reports each direction as "not defined"
(modulus is 0, or modulus 1 is the trivial ring). No NaN is displayed.
```

### Negative input: a = -17, b = 5
```
gcd(-17, 5) = 1
Bézout coefficients: x = 2, y = 7
Verification: -17×2 + 5×7 = -34 + 35 = 1 ✓
Modular inverse of a modulo |b|: (-17)⁻¹ mod 5 = 2
Verification: -17×2 ≡ 1 (mod 5)   (remainder normalised into [0, 5))
```

### Case 11: a = 0, b = 0
```
GCD(0, 0) is undefined - handled with error message
```

## Edge Cases Handled
- **Empty inputs:** Clear error message
- **Non-numeric inputs:** Rejected with validation message
- **Decimal values:** Rejected (integers only)
- **Both zero:** Special case - GCD undefined, error shown
- **One zero:** GCD = |non-zero|, coefficients (1, 0) or (0, 1)
- **Zero modulus for inverses:** a⁻¹ mod 0 and b⁻¹ mod 0 are never evaluated; the UI reports "not defined" instead of `NaN`
- **Trivial modulus 1:** Reported as "not defined" (the trivial ring) rather than printing a misleading inverse
- **Negative integers:** Absolute values used for computation, signs adjusted on coefficients
- **Negative moduli:** The modulus shown and used for the inverse is `|b|` or `|a|`
- **Negative verification remainders:** Normalised into `[0, modulus)` so the check reads `≡ 1`, not a negative remainder
- **Large integers:** Within JavaScript safe integer range (±9,007,199,254,740,991)
- **Non-coprime pairs:** Modular inverse section explains why inverse doesn't exist

## Quiz / Evaluation Information
The experiment includes 10 multiple-choice questions covering:
1. Purpose of the Euclidean Algorithm
2. Extended Euclidean Algorithm output (Bézout coefficients)
3. Modular inverse when gcd = 1
4. Numerical computation (gcd(240, 46))
5. Termination condition (remainder = 0)
6. Modular inverse existence condition (exists iff gcd = 1 / coprime)
7. Numerical computation (gcd(17, 5))
8. First division step for 240 and 46 (quotient 5, remainder 10)
9. Numerical Bézout verification (240×(−9) + 46×47 = 2)
10. Numerical modular inverse (3 modulo 11 = 4)

Each question has 4 options, immediate feedback with an explanation, and a final score display out of 10.

## References
1. Cormen, Leiserson, Rivest, Stein - *Introduction to Algorithms*, 3rd Ed., MIT Press, Ch. 31
2. William Stallings - *Cryptography and Network Security*, 7th Ed., Pearson, Ch. 4
3. Kenneth H. Rosen - *Elementary Number Theory and Its Applications*, 6th Ed., Addison-Wesley
4. NIST FIPS 186-4: Digital Signature Standard, Appendix B.3.1
5. RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2, Appendix C

## Integration Notes
- Self-contained module in `experiments/extended-euclidean/`
- Uses shared CSS: `../../css/variables.css`, `../../css/experiment.css`
- Uses experiment-scoped `theory.css` and `theory.js` for the interactive Theory tab; the shared stylesheet is not modified by this experiment
- Uses shared JS: `../../js/common.js` (tab navigation), `../../js/students-roster.js` (roll-number lookup), `../../js/feedback.js` and `../../js/crypto-feedback.js` (standardized encrypted feedback)
- Shared `css/experiment.css`, `js/feedback.js`, `js/crypto-feedback.js` and `js/students-roster.js` are kept identical to `origin/main`; this branch does not fork shared code
- No modifications to main application or other experiments required
- Follows the 7-tab template: Aim & Objectives, Theory, Procedure, Simulation, Assessment/Quiz, References, Feedback
- UI features: interactive Theory (steppers, Bézout verification, modular-inverse checks, knowledge checks), diagonal step-table arrows, GCD ring on the final step's divisor, Bézout result ring, legend, and a 10-question quiz
- Compatible with the Virtual Cryptography Laboratory portal (index.html experiment browser)
- UI synced with current main branch design conventions (feedback-card, reference-card, star-rating, etc.)