# Experiment 03: MD5 Hash Algorithm (Virtual Cryptography Laboratory)

## Experiment Metadata
- **Experiment ID:** EXP03
- **Experiment Title:** MD5 Hash Algorithm
- **Course / Module:** Cryptographic Security Systems (CSS TH ISE) &middot; Module 3: Cryptographic Hashes & Message Authentication
- **Assigned Group:** Group 3 &bull; *group-md5*
- **Collaborative Contributors:**
  - **Member 1 (Nicole Dabre &bull; `member-1`):** UTF-8 message encoding, MD5 padding algorithm (`0x80` byte and zero padding), 64-bit little-endian message length encoding, and 512-bit block decomposition into sixteen 32-bit words.
  - **Member 2 (Alciya Dodti &bull; `member-2`):** MD5 shift schedules $S[0..63]$, per-step sine-derived constants $K[0..63]$, non-linear auxiliary Boolean functions ($F, G, H, I$), and 32-bit unsigned left circular rotation.
  - **Member 3 (Larissa Dabreo &bull; `member-3`):** Initial chaining variable state ($A, B, C, D$), 64-step four-round compression engine, Merkle–Damgård feed-forward state accumulation, little-endian word-to-hex serializer, and core `md5` pipeline.
  - **Member 4 (Ruth Dmello &bull; `member-4`):** Interactive simulation interface, real-time diagnostic output analysis, Avalanche Effect visualizer with 128-bit heatmap diagram, 10-question assessment quiz system, and documentation.

---

## 1. Aim & Objectives

### Aim
To implement, trace, and analyze the **MD5 (Message-Digest Algorithm 5)** cryptographic hashing algorithm; to examine its preprocessing stages, 512-bit block parsing, and 64-step non-linear compression rounds; and to evaluate its **Avalanche Effect** diffusion characteristics and cryptographic security boundaries through interactive simulation.

### Objectives
1. **Message Preprocessing:** Understand how arbitrary-length plaintext messages are encoded in UTF-8, padded with a single '1' bit (`0x80`) and zeros to $448 \pmod{512}$, and appended with a 64-bit little-endian length descriptor.
2. **64-Round Non-Linear Compression:** Trace the 4 distinct operational rounds using non-linear auxiliary functions ($F, G, H, I$), trigonometric constants ($K[i] = \lfloor 2^{32} \times |\sin(i + 1)| \rfloor$), and left circular shifts ($S[i]$).
3. **Register State Transitions & Digest Assembly:** Observe the evolution of four 32-bit registers ($A, B, C, D$) across Merkle–Damgård iterations and verify final 128-bit lowercase hexadecimal digest serialization.
4. **Avalanche Effect Demonstration:** Compute bitwise Hamming distances and quantify diffusion percentages between single-character variations to demonstrate the Strict Avalanche Criterion ($\approx 50\%$ bit flip probability).
5. **Security & Cryptanalysis:** Analyze the vulnerability of MD5 to differential collision attacks (Wang et al., 2004/2005) and length extension risks, understanding why MD5 is deprecated for modern security while remaining foundational for educational study.

---

## 2. Theory & Mathematical Formulation

### 2.1 Overview & History
Designed by Professor **Ronald L. Rivest** (MIT/RSA) in 1991 to succeed MD4, MD5 is standardized in **RFC 1321**. It accepts an arbitrary-length message and computes a fixed-size **128-bit (16-byte)** message digest, rendered as a 32-character hexadecimal string.

### 2.2 Algorithm Pipeline & Step-by-Step Architecture

```
+-------------------------+
| Plaintext Input Message |
+-------------------------+
             |
             v
+-------------------------+
| UTF-8 Encoding & Byte   |
| Conversion (L bits)     |
+-------------------------+
             |
             v
+-------------------------+
| Padding: Append '1' bit |
| (0x80) + '0' bits to    |
| Length = 448 mod 512    |
+-------------------------+
             |
             v
+-------------------------+
| Append 64-bit Message   |
| Length (Little-Endian)  |
| Total = N x 512 bits    |
+-------------------------+
             |
             v
+-------------------------+
| Split into N x 512-bit  |
| Blocks (M_0 ... M_{N-1})|
+-------------------------+
             |
             v
+-------------------------+
| Each Block -> 16 Words  |
| M[0...15] (32-bit LE)   |
+-------------------------+
             |
             v
+-------------------------+ <-----------------------------+
| Initialize / Load State |                              |
| A, B, C, D Registers    |                              |
+-------------------------+                              |
             |                                           |
             v                                           |
+-------------------------+                              |
| Round 1: Steps 0-15     |                              |
| F(B,C,D) = (B&C)|(~B&D)  |                              |
+-------------------------+                              |
             |                                           |
             v                                           |
+-------------------------+                              |
| Round 2: Steps 16-31    |                              |
| G(B,C,D) = (B&D)|(C&~D)  |                              |
+-------------------------+                              |
             |                                           |
             v                                           |
+-------------------------+                              |
| Round 3: Steps 32-47    |                              |
| H(B,C,D) = B ^ C ^ D    |                              |
+-------------------------+                              |
             |                                           |
             v                                           |
+-------------------------+                              |
| Round 4: Steps 48-63    |                              |
| I(B,C,D) = C ^ (B | ~D) |                              |
+-------------------------+                              |
             |                                           |
             v                                           |
+-------------------------+                              |
| Merkle-Damgard Addition |                              |
| A+=a, B+=b, C+=c, D+=d  | --- (Repeat for next block) -+
+-------------------------+
             |
             v
+-------------------------+
| Little-Endian Word Hex  |
| Assembly -> 128-bit Hex |
| Digest (32 characters)  |
+-------------------------+
```

### 2.3 Initial Constants & State
The four 32-bit chaining variables are initialized as:
- $A = \text{0x67452301}$
- $B = \text{0xEFCDAB89}$
- $C = \text{0x98BADCFE}$
- $D = \text{0x10325476}$

### 2.4 Round Auxiliary Functions
| Round | Steps | Function | Word Index $g$ |
|---|---|---|---|
| **Round 1** | 0 – 15 | $F(B, C, D) = (B \land C) \lor (\neg B \land D)$ | $g = i$ |
| **Round 2** | 16 – 31 | $G(B, C, D) = (B \land D) \lor (C \land \neg D)$ | $g = (5i + 1) \bmod 16$ |
| **Round 3** | 32 – 47 | $H(B, C, D) = B \oplus C \oplus D$ | $g = (3i + 5) \bmod 16$ |
| **Round 4** | 48 – 63 | $I(B, C, D) = C \oplus (B \lor \neg D)$ | $g = (7i) \bmod 16$ |

### 2.5 Per-Step Operation
For step $i$ from 0 to 63:
$$\begin{aligned}
\text{temp} &= D \\
D &= C \\
C &= B \\
B &= \left( B + \text{leftRotate}\Big((A + \text{auxFunc}(B,C,D) + K[i] + M[g]) \bmod 2^{32}, S[i]\Big) \right) \bmod 2^{32} \\
A &= \text{temp}
\end{aligned}$$

---

## 3. Standard Test Vectors (RFC 1321 Validation)

| Input String | Expected MD5 Digest (Hex) |
|---|---|
| `""` (Empty string) | `d41d8cd98f00b204e9800998ecf8427e` |
| `"a"` | `0cc175b9c0f1b6a831c399e269772661` |
| `"abc"` | `900150983cd24fb0d6963f7d28e17f72` |
| `"message digest"` | `f96b697d7cb7938d525a2f31aaf161d0` |
| `"abcdefghijklmnopqrstuvwxyz"` | `c3fcd3d76192e4007dfb496cca67e13b` |
| `"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"` | `d174ab98d277d9f5a5611c2c9f419d9f` |
| `"12345678901234567890123456789012345678901234567890123456789012345678901234567890"` | `57edf4a22be3c955ac49da2e2107b67a` |

---

## 4. Avalanche Effect & Experimental Analysis

The **Strict Avalanche Criterion (SAC)** states that when any single input bit is inverted, every output bit changes with an independent probability of $50\%$.

### Example Comparison:
- **Message 1:** `"The quick brown fox jumps over the lazy dog"`
  - MD5: `9e107d9d372bb6826bd81d3542a419d6`
- **Message 2:** `"The quick brown fox jumps over the lazy dog."` (Added single period `.` at the end)
  - MD5: `e4d909c290d0fb1ca068ffaddf22cbd0`
- **Avalanche Metrics:**
  - **Hamming Distance:** 67 bits flipped out of 128 bits.
  - **Avalanche Diffusion Ratio:** $52.34\%$ (closely matching the theoretical ideal of $50\%$).
  - **Hex Characters Modified:** 30 out of 32 characters.

---

## 5. Assessment / Quiz (10 Questions)

1. **Output Digest Size:** 128 bits (32 hexadecimal characters).
2. **Padding Start Byte:** `0x80` (`10000000_2`).
3. **Block & Word Size:** 512-bit block and 32-bit word.
4. **Operations per Block:** 64 total operations (4 rounds $\times$ 16 steps).
5. **Avalanche Effect:** Single-bit input changes flip $\approx 50\%$ of output digest bits.
6. **Round 1 Auxiliary Function:** $F(B, C, D) = (B \land C) \lor (\neg B \land D)$.
7. **Constants $K[i]$ Derivation:** Derived as $\lfloor 2^{32} \times |\sin(i + 1)| \rfloor$.
8. **Length Appending:** 64-bit little-endian integer encoding original bit length.
9. **Endianness:** Little-endian byte ordering.
10. **Security Status:** Vulnerable to practical differential collision attacks (broken by Wang et al., 2004/2005).

---

## 6. Authoritative References

1. **RFC 1321:** Rivest, R. (1992). *The MD5 Message-Digest Algorithm*. Network Working Group, IETF. [https://www.ietf.org/rfc/rfc1321.txt](https://www.ietf.org/rfc/rfc1321.txt)
2. **Cryptography & Network Security:** Stallings, W. (2017). *Cryptography and Network Security: Principles and Practice* (7th ed.). Pearson Education.
3. **EUROCRYPT 2005 Collision Cryptanalysis:** Wang, X., & Yu, H. (2005). *How to Break MD5 and Other Hash Functions*. Advances in Cryptology &ndash; EUROCRYPT 2005, LNCS 3494, pp. 19–35. Springer. [https://doi.org/10.1007/11426639_2](https://doi.org/10.1007/11426639_2)
4. **NIST SP 800-131A (Rev. 2):** Barker, E., & Roginsky, A. (2019). *Transitioning the Use of Cryptographic Algorithms and Key Lengths*. National Institute of Standards and Technology, U.S. Department of Commerce. [https://doi.org/10.6028/NIST.SP.800-131Ar2](https://doi.org/10.6028/NIST.SP.800-131Ar2)
