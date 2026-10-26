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
- Modular multiplicative inverse (when gcd(a,b) = 1)

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
7. If gcd(a, b) = 1, examine the **Modular Inverse** section showing a⁻¹ mod b and b⁻¹ mod a
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
  - Bézout identity verification with substituted values and pass/fail indicator
  - Modular inverse section (shown only when gcd = 1) with positive modular equivalents and verification

## Test Cases

| Case | a | b | Expected GCD | Notes |
|------|---|---|--------------|-------|
| 1 | 240 | 46 | 2 | Classic example; x = -9, y = 47 |
| 2 | 99 | 78 | 3 | x = -11, y = 14 |
| 3 | 17 | 5 | 1 | Coprime; modular inverses exist |
| 4 | 12 | 8 | 4 | x = 1, y = -1 |
| 5 | 1 | 1 | 1 | Edge case |
| 6 | 0 | 15 | 15 | One zero; x = 0, y = 1 |
| 7 | 15 | 0 | 15 | One zero; x = 1, y = 0 |
| 8 | 0 | 0 | 0 (undefined) | Both zero; handled gracefully |
| 9 | -240 | 46 | 2 | Negative a; sign adjustment |
| 10 | 240 | -46 | 2 | Negative b; sign adjustment |
| 11 | -17 | -5 | 1 | Both negative |

## Expected Outputs

### Case 1: a = 240, b = 46
```
gcd(240, 46) = 2
Bézout coefficients: x = -9, y = 47
Verification: 240×(-9) + 46×47 = -2160 + 2162 = 2 ✓
```

### Case 3: a = 17, b = 5
```
gcd(17, 5) = 1
Bézout coefficients: x = -2, y = 7
Verification: 17×(-2) + 5×7 = -34 + 35 = 1 ✓
Modular inverses: 17⁻¹ mod 5 = 3, 5⁻¹ mod 17 = 7
```

### Case 8: a = 0, b = 0
```
GCD(0, 0) is undefined - handled with error message
```

## Edge Cases Handled
- **Empty inputs:** Clear error message
- **Non-numeric inputs:** Rejected with validation message
- **Decimal values:** Rejected (integers only)
- **Both zero:** Special case - GCD undefined, error shown
- **One zero:** GCD = |non-zero|, coefficients (1, 0) or (0, 1)
- **Negative integers:** Absolute values used for computation, signs adjusted on coefficients
- **Large integers:** Within JavaScript safe integer range (±9,007,199,254,740,991)
- **Non-coprime pairs:** Modular inverse section explains why inverse doesn't exist

## Quiz / Evaluation Information
The experiment includes 7 multiple-choice questions covering:
1. Purpose of Euclidean Algorithm
2. Extended Euclidean Algorithm output (Bézout coefficients)
3. Modular inverse when gcd = 1
4. Numerical computation (gcd(240, 46))
5. Termination condition (remainder = 0)
6. Modular inverse existence condition (gcd ≠ 1)
7. Numerical computation (gcd(17, 5))

Each question has 4 options, immediate feedback with explanation, and final score display.

## References
1. Cormen, Leiserson, Rivest, Stein - *Introduction to Algorithms*, 3rd Ed., MIT Press, Ch. 31
2. William Stallings - *Cryptography and Network Security*, 7th Ed., Pearson, Ch. 4
3. Kenneth H. Rosen - *Elementary Number Theory and Its Applications*, 6th Ed., Addison-Wesley
4. NIST FIPS 186-4: Digital Signature Standard, Appendix B.3.1
5. RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2, Appendix C

## Integration Notes
- Self-contained module in `experiments/extended-euclidean/`
- Uses shared CSS: `../../css/variables.css`, `../../css/experiment.css`
- Uses experiment-scoped `theory.css` and `theory.js` for the interactive Theory tab; the shared stylesheet is not modified
- Uses shared JS: `../../js/common.js` (tab navigation), `../../js/feedback.js` and `../../js/crypto-feedback.js` (standardized encrypted feedback)
- No modifications to main application or other experiments required
- Follows the 7-tab template: Aim & Objectives, Theory, Procedure, Simulation, Assessment/Quiz, References, Feedback
- Compatible with the Virtual Cryptography Laboratory portal (index.html experiment browser)
- UI synced with current main branch design conventions (feedback-card, reference-card, star-rating, etc.)