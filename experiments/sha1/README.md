# Experiment 04: SHA-1 Secure Hash Algorithm (Virtual Cryptography Laboratory)

## Experiment Metadata
- **Experiment ID:** EXP04
- **Experiment Title:** SHA-1 Secure Hash Algorithm
- **Course / Module:** Cryptographic Security Systems (CSS TH ISE) &middot; Module 3: Cryptographic Hashes & Message Authentication
- **Assigned Group:** Group 4 &bull; *group-sha1*
- **Collaborative Contributors:**
  - **Member 1 (Swar &bull; Roll 10713):** UI Architecture, RFC 3174 Preprocessing, Message Padding Inspector, color-coded byte representation, and layout styling.
  - **Member 2 (Tanush Chavan &bull; Roll 10710):** SHA-1 Core Algorithmic Engine, 80-Word Message Schedule Expansion ($W_0 \dots W_{79}$), Initial Chaining Variables (IV), and Merkle&ndash;Damg&aring;rd accumulation.
  - **Member 3 (Aaron Deniz &bull; Roll 10719):** Interactive Simulation Interface, 4-Stage Rounds Breakdown, Step-by-Step Compression Explorer ($t = 0 \dots 79$), and intermediate register transitions.
  - **Member 4 (Asher &bull; Roll 10715):** Sensitivity Analysis, Strict Avalanche Criterion (SAC) verification, 160-Bit Visual Heatmap Grid Diagram, 10-Question Diagnostic Assessment Quiz, and documentation.

---

## 1. Aim & Objectives

### Aim
To implement, trace, and analyze the **SHA-1 (Secure Hash Algorithm 1)** cryptographic hashing algorithm; to examine its preprocessing stages, 512-bit block parsing, 80-word message schedule expansion ($W_0 \dots W_{79}$), and 80-step four-stage non-linear compression rounds; and to evaluate its **Avalanche Effect** diffusion characteristics and cryptanalytic security boundaries through interactive simulation.

### Objectives
1. **Message Preprocessing & Padding:** Understand how arbitrary-length plaintext messages are encoded in UTF-8, suffixed with a single '1' bit (`0x80`), padded with zero bits to $448 \pmod{512}$, and terminated with a 64-bit big-endian length descriptor according to **RFC 3174** and **FIPS PUB 180-1**.
2. **Message Schedule Expansion:** Trace how sixteen 32-bit block words ($W_0 \dots W_{15}$) are expanded into eighty 32-bit words ($W_{16} \dots W_{79}$) via bitwise XOR and 1-bit left circular rotation:  
   $$W_t = \text{ROTL}^1(W_{t-3} \oplus W_{t-8} \oplus W_{t-14} \oplus W_{t-16})$$
3. **80-Round Non-Linear Compression:** Observe 4 distinct stages of 20 steps each utilizing auxiliary Boolean functions (`Ch, Parity, Maj, Parity`), additive constants derived from square roots of primes ($K_t = \lfloor 2^{30} \times \sqrt{2, 3, 5, 10} \rfloor$), and circular rotations on five 32-bit working registers ($A, B, C, D, E$).
4. **Register State Transitions & Digest Assembly:** Observe the evolution of five 32-bit registers across Merkle&ndash;Damg&aring;rd iterations and verify final 160-bit (40-hex character) big-endian digest assembly.
5. **Avalanche Effect & SAC Demonstration:** Compute bitwise Hamming distances and verify the Strict Avalanche Criterion (SAC) showing that a single flipped bit in the input induces an average 50% bit flip ($\approx 80 \pm 8$ bits out of 160) across a 160-bit register heatmap diagram.
6. **Security & Cryptanalysis:** Analyze the vulnerability of SHA-1 to theoretical differential attacks (Wang et al., 2005) and practical collision forgery (SHAttered, 2017), understanding why SHA-1 has been deprecated in favor of SHA-256 and SHA-3.

---

## 2. Theory & Mathematical Formulation

### 2.1 Overview & History
Published in 1995 by the United States **National Institute of Standards and Technology (NIST)** as **FIPS PUB 180-1** and designed by the **National Security Agency (NSA)**, SHA-1 was created to replace the earlier SHA-0. The critical modification in SHA-1 was the addition of a 1-bit left circular rotation in the message schedule recurrence, which corrected a subtle linear flaw in SHA-0.

SHA-1 produces a fixed **160-bit (20-byte)** digest from an arbitrary-length message of up to $2^{64}-1$ bits, represented as 40 lowercase hexadecimal characters.

### 2.2 Algorithm Pipeline & Step-by-Step Architecture

```
+-------------------------------------------------------+
|                Plaintext Input Message                |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|         UTF-8 Encoding & Byte Conversion (L bits)     |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| Padding: Append '1' bit (0x80) + '0' bits to 448 mod 512|
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| Append 64-bit Big-Endian Length Field (Total: N x 512b)|
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| Split into 512-bit Blocks (M_0 ... M_{N-1})           |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| Message Schedule Expansion: W[0..15] -> W[0..79]       |
| W[t] = ROTL1(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])     |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| 80-Step Compression Loop (4 Stages x 20 Steps)        |
| Stage 1: Ch(B,C,D)    | K = 0x5A827999                |
| Stage 2: Parity(B,C,D)| K = 0x6ED9EBA1                |
| Stage 3: Maj(B,C,D)   | K = 0x8F1BBCDC                |
| Stage 4: Parity(B,C,D)| K = 0xCA62C1D6                |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| Merkle–Damgård Feed-Forward Chaining Update           |
| H0 += A, H1 += B, H2 += C, H3 += D, H4 += E (mod 2^32)|
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| 160-bit Hex Digest Assembly (H0 || H1 || H2 || H3 || H4)|
+-------------------------------------------------------+
```

### 2.3 Mathematical Equations

#### 1. Initial Values (IV):
```text
H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476
H4 = 0xC3D2E1F0
```

#### 2. Non-linear Functions & Constants:
| Stage | Step Range ($t$) | Function $f_t(B, C, D)$ | Name | Constant $K_t$ | Derivation |
|:---:|:---:|:---|:---:|:---:|:---:|
| 1 | 0 &ndash; 19 | $(B \land C) \lor (\neg B \land D)$ | Ch | `0x5A827999` | $\lfloor 2^{30} \times \sqrt{2} \rfloor$ |
| 2 | 20 &ndash; 39 | $B \oplus C \oplus D$ | Parity | `0x6ED9EBA1` | $\lfloor 2^{30} \times \sqrt{3} \rfloor$ |
| 3 | 40 &ndash; 59 | $(B \land C) \lor (B \land D) \lor (C \land D)$ | Maj | `0x8F1BBCDC` | $\lfloor 2^{30} \times \sqrt{5} \rfloor$ |
| 4 | 60 &ndash; 79 | $B \oplus C \oplus D$ | Parity | `0xCA62C1D6` | $\lfloor 2^{30} \times \sqrt{10} \rfloor$ |

#### 3. Per-Step State Evolution:
$$\text{TEMP} = (\text{ROTL}^5(A) + f_t(B, C, D) + E + W_t + K_t) \bmod 2^{32}$$
$$E = D$$
$$D = C$$
$$C = \text{ROTL}^{30}(B)$$
$$B = A$$
$$A = \text{TEMP}$$

---

## 3. Module Features

1. **Deterministic & Dynamic Nonce / Salt Mode:**
   Allows testing pure deterministic output as well as simulating unique nonce addition to avoid rainbow table attacks.
2. **RFC 3174 Message Padding Inspector:**
   Interactive byte-level visualizer separating original message bytes, the `0x80` byte, zero-fill bytes, and the 64-bit big-endian length descriptor.
3. **80-Word Expansion Schedule Table ($W_0 \dots W_{79}$):**
   Full multi-block schedule inspection showing each word's 32-bit hex value and mathematical derivation.
4. **80-Round Compression & Step Explorer:**
   Round-end register values and live step slider ($t = 0 \dots 79$) displaying $f(B,C,D)$, $K_t$, $W_t$, and working registers $a, b, c, d, e$.
5. **Avalanche Effect Visualizer & 160-Bit Heatmap Diagram:**
   Interactive sensitivity engine comparing two inputs with character-level difference highlighting, Hamming distance, percentage difference, and a 160-cell interactive heatmap (5 rows for registers A, B, C, D, E $\times$ 32 bits) with hover inspection.
6. **Diagnostic Knowledge Assessment Quiz:**
   10 comprehensive questions covering SHA-1 specifications, padding, schedule expansion, and cryptanalysis with instant feedback and score banner.

---

## 4. Test Vectors & Known Answers

| Input Message | Expected SHA-1 Digest (Hexadecimal) |
|:---|:---|
| `""` (Empty string) | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| `"abc"` | `a9993e364706816aba3e25717850c26c9cd0d89d` |
| `"message digest"` | `c12252ceda8be9b4000803f7f26a3514022b7b5d` |
| `"The quick brown fox jumps over the lazy dog"` | `2fd4e1c67a2d28fced849ee1bb76e7391b93eb12` |
| `"The quick brown fox jumps over the lazy cog"` | `de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3` |

---

## 5. References & Authoritative Literature

1. **NIST FIPS PUB 180-1 (1995):** *Secure Hash Standard.* National Institute of Standards and Technology.
2. **RFC 3174 (2001):** Eastlake, D., & Jones, P. *US Secure Hash Algorithm 1 (SHA1).* IETF.
3. **Stevens, M. et al. (CRYPTO 2017):** *The First Collision for Full SHA-1 (SHAttered).*
4. **Wang, X., Yin, Y. L., & Yu, H. (CRYPTO 2005):** *Finding Collisions in the Full SHA-1.*
5. **Stallings, W. (2017):** *Cryptography and Network Security: Principles and Practice* (7th Edition), Pearson.
6. **NIST SP 800-131A Rev. 2 (2019):** *Transitioning the Use of Cryptographic Algorithms and Key Lengths.*

