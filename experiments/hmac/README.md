# HMAC Authentication and Verification (EXP-HMAC)

## Integration Information

```text
Group: HMAC
Experiment ID: EXP-HMAC
Experiment Name: HMAC Authentication and Verification
Folder: /experiments/hmac/
Entry File: index.html
Navigation Title: HMAC
Short Description: Generate and verify HMAC values using a secret key and analyze the effect of modifying the message or key.
Required Libraries: None
Cryptographic API: Web Crypto API
Algorithm: HMAC-SHA-256
Input: Message, Secret Key, HMAC for verification
Output: HMAC value and verification result
Expected Navigation Link: /experiments/hmac/
```

---

## 1. Group Information

* **Department:** Information Science & Engineering (ISE)
* **Course:** Cryptographic Security Systems (CSS TH ISE)
* **Module Group:** HMAC Cryptography Experiments
* **Module Identifier:** EXP-HMAC

---

## 2. Experiment ID

* **Experiment ID:** `EXP-HMAC`

---

## 3. Experiment Name

* **Experiment Name:** HMAC Authentication and Verification

---

## 4. Objective

1. To understand the mathematical and structural design of Keyed-Hash Message Authentication Codes (HMAC) standardized in RFC 2104 and FIPS PUB 198-1.
2. To generate cryptographic HMAC digests using a shared secret key and the HMAC-SHA-256 algorithm via the native browser Web Crypto API.
3. To verify data integrity and message authenticity by recalculating HMAC values and performing validation against received digests.
4. To observe, quantify, and analyze the **Avalanche Effect** and message tampering detection when either the plaintext message or the shared secret key is altered.
5. To understand why simple unkeyed hashing (e.g., standard SHA-256) and naive concatenation $H(K \parallel m)$ are insufficient for authentication due to spoofing and length extension attacks.

---

## 5. Theory

### What is HMAC?

An **HMAC (Hash-based Message Authentication Code)** is a specific type of Message Authentication Code (MAC) that combines a cryptographic hash function (such as SHA-256) with a shared secret key. It was published in 1996 by Mihir Bellare, Ran Canetti, and Hugo Krawczyk, and formally standardized in IETF **RFC 2104** and NIST **FIPS PUB 198-1**.

### The Need for a Secret Key

A standard cryptographic hash function (such as SHA-256) is a deterministic one-way mathematical function. It produces a fixed-size digest from arbitrary input data. However, anyone can compute a standard SHA-256 hash. 

In a network environment subject to active attacks (Man-in-the-Middle), an adversary who intercepts and tampers with a message can simply recalculate the standard hash of the altered message and transmit both. The receiver would verify the hash successfully and fail to detect the tampering.

HMAC solves this by incorporating a **symmetric secret key** shared exclusively between the communicating parties (Alice and Bob). An attacker who does not possess the secret key cannot generate a valid HMAC for a modified or fabricated message.

### Mathematical Formulation of HMAC

The HMAC construction is defined as:

$$\text{HMAC}(K, m) = H\Big((K' \oplus \text{opad}) \parallel H\big((K' \oplus \text{ipad}) \parallel m\big)\Big)$$

Where:
* $H$: The underlying cryptographic hash function (e.g., SHA-256).
* $m$: The input plaintext message.
* $K$: The shared secret key.
* $B$: The byte block length of the hash function's compression function ($B = 64$ bytes for SHA-256).
* $L$: The byte output length of the hash function ($L = 32$ bytes / 256 bits for SHA-256).
* $K'$: A key conditioned to be exactly $B$ bytes in length:
  * If $K$ is longer than $B$ bytes: $K' = H(K)$, then right-padded with zeros to length $B$.
  * If $K$ is shorter than $B$ bytes: $K' = K$, right-padded with zero bytes (`0x00`) to length $B$.
* $\text{ipad}$ (Inner Pad): The byte constant `0x36` repeated $B$ times (`0x3636...36`).
* $\text{opad}$ (Outer Pad): The byte constant `0x5C` repeated $B$ times (`0x5c5c...5c`).
* $\oplus$: Bitwise Exclusive-OR (XOR) operation.
* $\parallel$: Concatenation operation.

### Why Not $H(\text{Key} \parallel \text{Message})$? (Length Extension Attack Immunity)

A naive attempt to authenticate a message by prefixing the secret key:

$$\text{MAC}_{\text{naive}} = H(K \parallel m)$$

is vulnerable to **Length Extension Attacks** on Merkle-Damgård hash functions (such as MD5, SHA-1, SHA-256, and SHA-512). In these hash algorithms, the output hash represents the internal state after processing the final padded block. An attacker who knows $m$ and $H(K \parallel m)$ can append arbitrary malicious data $m_{\text{extra}}$ and compute $H(K \parallel m \parallel \text{padding} \parallel m_{\text{extra}})$ without knowing $K$.

HMAC eliminates length extension attacks completely through its **nested two-pass hashing construction**: the inner hash output $H((K' \oplus \text{ipad}) \parallel m)$ is hashed a second time with the outer key pad $(K' \oplus \text{opad})$, preventing an attacker from continuing the hash state.

### Can HMAC Be Decrypted? (Integrity vs. Confidentiality & Encrypt-then-MAC)

A fundamental principle in security architecture:
1. **HMAC is NOT Encryption:** HMAC is a one-way mathematical function. It compresses arbitrary data into a fixed 256-bit digest. It permanently discards input entropy and is mathematically impossible to invert or decrypt.
2. **Confidentiality Requires Encryption:** If secrecy (confidentiality) is needed alongside authentication, systems use **Authenticated Encryption (AE)**, specifically the **Encrypt-then-MAC** paradigm (RFC 7366):
   - **Sender:**
     1. Encrypts plaintext $m$ using AES-256-CBC to produce ciphertext $c$ and IV.
     2. Computes authentication tag $t = \text{HMAC}(K, \text{IV} \parallel c)$.
     3. Transmits $( \text{IV} \parallel c \parallel t )$.
   - **Receiver:**
     1. Verifies authentication tag $t$ first. If invalid, **aborts immediately** to protect against Chosen-Ciphertext and Padding Oracle attacks.
     2. If verified, decrypts ciphertext $c$ using AES-256-CBC to recover original plaintext $m$.

---

## 6. Algorithm

### HMAC-SHA-256 Computation Algorithm

```text
Algorithm HMAC_SHA256(Key K, Message m):
  1. Determine block size B = 64 bytes.
  2. If length(K) > B:
       K_prime = SHA256(K)
     Else:
       K_prime = K
  3. Pad K_prime with 0x00 on the right until length is exactly B bytes.
  4. Compute inner_key = K_prime XOR ipad (where ipad = 0x36 repeated 64 times).
  5. Compute inner_data = inner_key || m.
  6. Compute inner_hash = SHA256(inner_data) (32 bytes).
  7. Compute outer_key = K_prime XOR opad (where opad = 0x5C repeated 64 times).
  8. Compute outer_data = outer_key || inner_hash.
  9. Compute final_digest = SHA256(outer_data) (32 bytes).
 10. Convert final_digest to a 64-character hexadecimal string.
 11. Return final_digest.
```

### Web Crypto API Implementation

The experiment uses the modern W3C standard Web Crypto API (`window.crypto.subtle`):

```javascript
// 1. Encode text strings into Uint8Arrays
const encoder = new TextEncoder();
const keyData = encoder.encode(secretKey);
const messageData = encoder.encode(message);

// 2. Import raw key as an HMAC CryptoKey object
const cryptoKey = await window.crypto.subtle.importKey(
  'raw',
  keyData,
  {
    name: 'HMAC',
    hash: { name: 'SHA-256' }
  },
  false, // Non-extractable
  ['sign', 'verify']
);

// 3. Sign the message with the imported key
const signatureBuffer = await window.crypto.subtle.sign(
  'HMAC',
  cryptoKey,
  messageData
);

// 4. Format into lowercase hexadecimal string (64 characters)
const hashArray = Array.from(new Uint8Array(signatureBuffer));
const hmacHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
```

---

## 7. Input

1. **Plaintext Message ($m$):**
   * Format: UTF-8 plain text string or binary data.
   * Default test value: `Hello World`
2. **Secret Key ($K$):**
   * Format: UTF-8 secret passphrase or random byte sequence.
   * Default test value: `mysecretkey`
3. **Cryptographic Hash Algorithm:**
   * Default: `HMAC-SHA-256`
   * Additional supported: `HMAC-SHA-384`, `HMAC-SHA-512`
4. **Supplied HMAC for Verification:**
   * 64-character hexadecimal digest string.

---

## 8. Output

1. **Generated HMAC:**
   * 64 hexadecimal characters representing a 256-bit authentication tag.
   * Example: `a3f5...`
2. **Verification Verdict:**
   * **Success:** `✓ HMAC Verified — Message integrity and authentication are valid.`
   * **Failure:** `✗ HMAC Verification Failed — The message or secret key may have been modified.`
3. **Modification Analysis Metrics:**
   * Character-by-character diff displaying matching and mismatched nibbles.
   * Number of hex characters altered ($X / 64$).
   * Hamming Distance (number of flipped bits: $Y / 256$).
   * Avalanche Effect percentage ($\approx 50\%$).

---

## 9. Experiment Procedure

Follow these steps within the virtual laboratory:

1. **Accessing the Simulation:**
   * Open `/experiments/hmac/index.html` in any modern web browser.
   * Click on the **Simulation** tab.
2. **Generating an HMAC:**
   * In the **1. HMAC Generator** card, enter the plaintext message: `Hello World`.
   * Enter the secret key: `mysecretkey`.
   * Verify that **HMAC-SHA-256** is selected.
   * Click **Generate HMAC**.
   * Observe the 64-character hexadecimal output in the **Simulation Output** section.
3. **Verifying Authenticity & Integrity:**
   * Click **Send to Verifier** to transfer the parameters and HMAC to the verification form.
   * Click **Verify HMAC**.
   * Notice that the system recalculates the HMAC and displays:
     ```text
     ✓ HMAC Verified
     Message integrity and authentication are valid.
     ```
4. **Analyzing Message Modification:**
   * In the **Modification Analysis** card, under **A. Modify Message**, change the modified message input from `Hello World` to `Hello world` (lowercase 'w').
   * Observe how the red highlighted characters indicate that almost every hex character has changed.
   * Check the Avalanche metric ($\approx 50\%$ bit flip).
5. **Analyzing Key Modification:**
   * Switch to **B. Modify Secret Key**.
   * Change the key from `mysecretkey` to `mysecretKey`.
   * Confirm that an identical plaintext message with an altered secret key results in verification failure.
6. **Self-Assessment:**
   * Click the **Quiz** tab to complete the 6 multiple-choice questions.

---

## 10. Message Modification Analysis

When an active attacker alters a message in transit, the calculated HMAC changes drastically:

```text
Original Message:
Hello World

Modified Message:
Hello world

Shared Key:
mysecretkey

Original HMAC:
56e6d0... (64 hex characters)

New HMAC:
e84b1f... (64 hex characters)

Result:
✗ HMAC mismatch
Message modification detected.
```

### Explanation

Even a 1-bit variation in the input message completely alters the intermediate compression function states in SHA-256 across all 64 rounds. Because HMAC nests two passes of hashing ($H(\dots H(\dots m))$), altering any character in the message produces an uncorrelated, pseudorandom 256-bit digest. This demonstrates **integrity protection**.

---

## 11. Key Modification Analysis

When an attacker attempts to verify an HMAC with an incorrect or guessed secret key:

```text
Message:
Hello World

Original Key:
mysecretkey

Modified Key:
mysecretKey

Original HMAC:
56e6d0...

New HMAC:
89a1c4...

Result:
✗ HMAC mismatch
Secret key modification detected.
```

### Explanation

HMAC depends cryptographically on both the message and the secret key. If an entity does not possess the exact symmetric secret key used by the sender, any tag they generate will mismatch. This demonstrates **origin authentication and non-repudiation** between key-sharing parties.

---

## 12. Test Cases

| Test Case | Message | Secret Key | Supplied HMAC | Expected Status | Description |
|:---|:---|:---|:---|:---|:---|
| **Case 1: Normal Verification** | `Hello World` | `mysecretkey` | Matching calculated HMAC | ✓ HMAC Verified | Valid message and secret key yield identical HMAC. |
| **Case 2: Modified Message** | `Hello World!` | `mysecretkey` | Original HMAC of `Hello World` | ✗ Verification Failed | Trailing exclamation mark alters HMAC; tampering detected. |
| **Case 3: Modified Key** | `Hello World` | `mysecretKey` | Original HMAC of `mysecretkey` | ✗ Verification Failed | Casing change in key alters HMAC; unauthorized key detected. |
| **Case 4: Incorrect HMAC** | `Hello World` | `mysecretkey` | `ffff` + rest of digest | ✗ Verification Failed | Deliberately corrupted digest fails verification. |
| **Case 5: Empty Input** | ` ` (empty) | ` ` (empty) | N/A | Validation Warning | Validation prevents execution without required parameters. |

---

## 13. Expected Outputs

### Case 1 Expected Output

```text
Generated HMAC:
<64 hex characters>

Verification Result:
✓ HMAC Verified
Message integrity and authentication are valid.
```

### Case 2 Expected Output

```text
Verification Result:
✗ HMAC Verification Failed
The message or secret key may have been modified.
```

### Case 5 Expected Output

```text
⚠️ Test Case 5: Empty input detected. Please provide both message and secret key.
```

---

## 14. Evaluation Questions with Answers

### 1. What is HMAC?
**Answer:** HMAC (Hash-based Message Authentication Code) is a keyed cryptographic message authentication code defined in RFC 2104. It utilizes a cryptographic hash function (e.g., SHA-256) combined with a secret cryptographic key to provide both data integrity and message authenticity.

### 2. What is the purpose of the secret key in HMAC?
**Answer:** The secret key ensures origin authentication. Without a secret key, anyone can compute a hash. With a shared secret key, only an authorized party possessing the key can generate a valid HMAC tag, preventing unauthorized parties from forging tags for modified messages.

### 3. How does HMAC provide message integrity?
**Answer:** The HMAC digest is computed over the entire message. Any alteration to the message (even a single flipped bit) produces a completely different HMAC. When the recipient recalculates the HMAC using the shared key, the mismatch immediately reveals that the message was modified.

### 4. What happens when a single character in the message is changed?
**Answer:** Due to the **Avalanche Effect** in cryptographic hash functions, changing a single character or bit in the message causes approximately 50% of the bits in the resulting HMAC to flip in an unpredictable, pseudorandom manner, completely changing the output digest.

### 5. What happens when the secret key is changed?
**Answer:** Changing the secret key alters the inner and outer key pads ($K' \oplus \text{ipad}$ and $K' \oplus \text{opad}$). This yields a completely different intermediate and final hash value, causing verification to fail.

### 6. Why is HMAC different from a normal hash such as SHA-256?
**Answer:** A normal hash takes only a message as input and is public and deterministic—anyone can compute it. HMAC takes both a message and a secret key as inputs. Therefore, HMAC provides authentication (proving who generated it) and integrity, whereas a standard hash only provides integrity against accidental modification.

### 7. Can a user verify an HMAC without knowing the secret key? Explain.
**Answer:** No. Verification requires recalculating the HMAC tag over the received message using the shared secret key. Because the secret key is required for both the inner and outer hash passes, an entity without the secret key cannot recalculate or verify the HMAC.

### 8. Why is SHA-256 commonly used with HMAC?
**Answer:** SHA-256 provides a 256-bit digest, offering 128-bit security against collision attacks and 256-bit security against pre-image attacks. It is computationally efficient, resistant to known cryptanalytic attacks, and standardized worldwide by NIST and FIPS.

### 9. What security properties does HMAC provide?
**Answer:** HMAC provides:
1. **Data Integrity:** Detection of any unauthorized modifications to the message.
2. **Message Authentication:** Confirmation that the message originated from a party holding the secret key.
3. **Immunity to Length Extension Attacks:** Unlike naive concatenation $H(K \parallel m)$, HMAC's nested design prevents attackers from appending extra data.
*(Note: HMAC does not provide confidentiality/encryption; the message remains plaintext unless encrypted separately).*

### 10. What happens if the HMAC value is modified before verification?
**Answer:** If an attacker modifies even a single hexadecimal character of the transmitted HMAC tag, the recalculation check will fail. The recalculated HMAC will not match the received corrupted HMAC, and the receiver will reject the message.

---

## 15. Quiz Questions with Answers

### Q1. What does HMAC primarily provide?
* A. Data compression
* B. Message authentication and integrity
* C. Encryption
* D. Key generation
* **Correct Answer:** **B**
* *Explanation:* HMAC provides message authentication and integrity using a symmetric secret key.

### Q2. Which two inputs are required to generate an HMAC?
* A. Message and public key
* B. Message and secret key
* C. Password and certificate
* D. Ciphertext and IV
* **Correct Answer:** **B**
* *Explanation:* HMAC requires a plaintext message and a shared symmetric secret key.

### Q3. What happens if the message is modified after an HMAC is generated?
* A. HMAC remains unchanged
* B. HMAC becomes invalid
* C. Message is automatically restored
* D. Key changes automatically
* **Correct Answer:** **B**
* *Explanation:* Modifying the message changes the recalculated HMAC, causing verification to fail.

### Q4. Which algorithm should this experiment use?
* A. RSA
* B. AES
* C. HMAC-SHA-256
* D. Diffie-Hellman
* **Correct Answer:** **C**
* *Explanation:* The laboratory module uses HMAC-SHA-256 as its standard cryptographic primitive.

### Q5. What happens if the secret key used for verification is incorrect?
* A. Verification succeeds
* B. Verification fails
* C. Message is decrypted
* D. A new key is generated automatically
* **Correct Answer:** **B**
* *Explanation:* Using an incorrect secret key produces a completely different digest, causing verification to fail.

### Q6. Why is simple concatenation $H(\text{Key} \parallel \text{Message})$ vulnerable, whereas HMAC is secure?
* A. Simple hash cannot process keys longer than 8 bytes
* B. Simple hash reveals the private key directly in plaintext
* C. Merkle-Damgård hashes are vulnerable to length extension attacks; HMAC's nested two-pass structure prevents this
* D. Simple hash is symmetric while HMAC is asymmetric
* **Correct Answer:** **C**
* *Explanation:* Merkle-Damgård hashes allow an attacker to compute $H(K \parallel m \parallel \text{padding} \parallel \text{extra})$ without knowing $K$. HMAC's outer hash pass wraps the inner state, preventing extension.

---

## 16. Learning Outcomes

Upon completing this virtual laboratory experiment, students will be able to:
1. Explain the inner workings of HMAC and write the mathematical formula for RFC 2104 HMAC.
2. Distinguish between unkeyed hashing, symmetric encryption, and keyed MAC authentication.
3. Utilize the standard W3C Web Crypto API (`crypto.subtle`) to import keys and sign messages.
4. Execute verification workflows and troubleshoot mismatch conditions.
5. Quantify the Avalanche Effect using Hamming distance calculations.

---

## 17. Browser and API Requirements

* **HTML5 & CSS3:** Modern Flexbox and CSS Grid layout support.
* **JavaScript:** ECMAScript 2020+ (Async/Await, Promise, Array methods).
* **Web Crypto API:** `window.crypto.subtle` support (Available in all modern browsers: Chrome, Firefox, Safari, Edge).
* *Note:* Web Crypto API requires a secure context (`https://` or `http://localhost` or `file:///`).

---

## 18. Integration Instructions

To integrate the HMAC module into the main Virtual Cryptography Laboratory:

1. **Verify Folder Placement:**
   Ensure this directory is located at:
   ```text
   /experiments/hmac/
   ```
2. **Main Navigation Entry:**
   Add a link to `/experiments/hmac/index.html` in the main lab index catalog:
   ```html
   <a href="experiments/hmac/index.html" class="experiment-card">
     <h3>HMAC Authentication and Verification</h3>
     <p>Generate, verify, and analyze HMAC values using a secret key.</p>
   </a>
   ```
3. **No External Dependencies:**
   The module requires no npm packages, no CDN script tags, and no backend servers. It runs entirely client-side.

---

## 19. GitHub Branch and Pull-Request Instructions

Follow these git commands to submit the completed experiment module:

```bash
# 1. Create and switch to the recommended feature branch
git checkout -b feature/hmac-experiment

# 2. Add all files in the hmac module
git add experiments/hmac/

# 3. Commit with a descriptive message
git commit -m "Add HMAC cryptography experiment module with verification and modification analysis"

# 4. Push the branch to the remote repository
git push origin feature/hmac-experiment
```

### Pull Request Guidelines

* **Target Branch:** `main`
* **Source Branch:** `feature/hmac-experiment`
* **Title:** `Add HMAC Authentication and Verification Experiment (EXP-HMAC)`
* **Description:** Includes complete self-contained implementation with Web Crypto API, interactive verification, message and key tampering analysis, 5 test cases, and quiz assessment.
