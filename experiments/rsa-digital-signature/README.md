# RSA Digital Signature

## Experiment Name

Implementation and Simulation of RSA Digital Signature

## Objective

The objective of this experiment is to understand the working of RSA digital signatures and demonstrate how a message can be digitally signed using a private key and verified using the corresponding public key.

The experiment also demonstrates message integrity and detects whether a signed message has been modified.

---

## Introduction

RSA is an asymmetric cryptographic algorithm that uses two mathematically related keys: a public key and a private key.

The public key can be shared with other users, while the private key must be kept secret.

RSA is widely used in cryptographic applications for authentication, secure communication and digital signatures.

A digital signature provides important security services such as:

- Authentication
- Integrity
- Non-repudiation

In a digital signature system, the sender generates a signature using their private key. The receiver can use the sender's public key to verify the signature.

If the original message is modified after signing, the verification process fails.

---

## Working of RSA Digital Signature

The RSA digital signature process consists of the following steps:

1. Generate an RSA public and private key pair.
2. Enter the message that needs to be signed.
3. Calculate the SHA-256 hash of the message.
4. Use the RSA private key to generate the digital signature.
5. Send the message and signature to the receiver.
6. The receiver uses the RSA public key to verify the signature.
7. If the message has not been modified, verification succeeds.
8. If the message has been modified, verification fails.

---

## Mathematical Representation

RSA uses:

- Public key = `(e, n)`
- Private key = `d`

The message is first converted into a hash value.

The digital signature is generated using the private key.

Conceptually:

`S = H(M)^d mod n`

where:

- `M` = message
- `H(M)` = hash of the message
- `S` = digital signature
- `d` = private key
- `n` = RSA modulus

During verification, the public key is used to verify that the signature corresponds to the message.

---

## Procedure

### Step 1

Open the RSA Digital Signature experiment in a web browser.

### Step 2

Open the Simulation tab.

### Step 3

Enter a message in the Message Text field.

Example:

`Approve Transaction #9872`

### Step 4

Click the `Sign and Verify` button.

### Step 5

The application generates an RSA digital signature using the private key.

### Step 6

The application verifies the signature using the public key.

### Step 7

Observe the following output:

- Input message
- SHA-256 hash
- RSA public key
- Computed signature
- Verification result

### Step 8

Click `Run Tamper Test`.

The application modifies the original message and attempts verification again.

The verification should fail because the message has been changed.

---

## Input Specification

The experiment accepts:

- Text message
- Any normal text string can be entered into the Message Text field.

Example:

`Approve Transaction #9872`

---

## Output Specification

The simulation displays:

1. Input Message
2. SHA-256 Hash
3. Generated RSA Public Key
4. Computed RSA Signature
5. Signature Verification Result

For a valid message, the result should indicate:

`Signature Verified Successfully`

For a modified message, the result should indicate:

`Signature Verification Failed - Message Was Modified`

---

## Test Cases

### Test Case 1 - Valid Message

Input:

`Approve Transaction #9872`

Expected Result:

`Signature Verified Successfully`

---

### Test Case 2 - Different Message

Input:

`Approve Transaction #9873`

Expected Result:

A different RSA signature is generated and verification succeeds for the new message.

---

### Test Case 3 - Modified Message

Original message:

`Approve Transaction #9872`

Modified message:

`Approve Transaction #9872 [MODIFIED]`

Expected Result:

`Signature Verification Failed - Message Was Modified`

---

## Quiz

The experiment contains an interactive quiz with questions related to:

- RSA private and public keys
- Digital signatures
- Authentication
- Integrity
- Non-repudiation
- Message modification

The user can select answers and click `Check Answers` to view the score.

---

## Technologies Used

- HTML5
- CSS3
- JavaScript
- RSA
- SHA-256
- Forge JavaScript Cryptography Library

---

## Browser Compatibility

The experiment is designed to work in modern browsers such as:

- Google Chrome
- Mozilla Firefox
- Microsoft Edge
- Safari

---

## Advantages of Digital Signatures

- Provides message integrity.
- Provides sender authentication.
- Supports non-repudiation.
- Helps detect unauthorized modifications.
- Uses public-key cryptography for verification.

---

## Limitations

This simulation is intended for educational purposes.

The RSA key size used in the browser demonstration is smaller than the key sizes normally recommended for production cryptographic systems.

Real-world applications should use established cryptographic libraries and secure key-management practices.

---

## Conclusion

The RSA Digital Signature experiment demonstrates how asymmetric cryptography can be used to create and verify digital signatures.

The sender uses the private key to create the signature, while the receiver uses the corresponding public key to verify it.

The tamper test demonstrates the importance of message integrity because modifying the signed message causes signature verification to fail.

Therefore, RSA digital signatures provide an important mechanism for authentication, integrity and non-repudiation.

---

## References

1. B. A. Forouzan, Cryptography and Network Security.
2. Mark Stamp, Information Security Principles and Practice.
3. Rivest, Shamir and Adleman, A Method for Obtaining Digital Signatures and Public-Key Cryptosystems.
4. NIST Cryptographic Standards and Guidelines.