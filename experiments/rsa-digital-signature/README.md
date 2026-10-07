# RSA Digital Signature

Generate an RSA digital signature for a given message and verify the
signature using the corresponding public key.

## Aim

To generate an RSA digital signature for a given message and verify the
signature using the corresponding public key.

## Input

- Message text entered by the user.

## RSA Parameters

The simulation uses the following educational RSA parameters:

- p = 61
- q = 53
- n = 3233
- φ(n) = 3120
- Public exponent e = 17
- Private exponent d = 2753

## Output

The simulation displays:

- RSA public key
- RSA private key
- Generated digital signature
- Signature verification result

## Simulation

1. Enter a message in the Message Text field.
2. Click **Sign and Verify**.
3. The message is signed using the RSA private key.
4. The generated signature is verified using the RSA public key.
5. The verification result is displayed on the page.

## Tamper Test

The simulation also provides a **Run Tamper Test** option.

The original message is signed first. The message is then modified and
the original signature is verified against the modified message.

Expected result:

- Verification succeeds for the original message.
- Verification fails when the signed message is modified.

## Test Cases

### Test Case 1

Input:

`Hello World`

Expected result:

Signature is generated and verification succeeds.

### Test Case 2

Input:

`Transfer Rs 5000`

Expected result:

Signature is generated and verification succeeds.

### Test Case 3

Input:

`Student ID: 12345`

Expected result:

Signature is generated and verification succeeds.

### Test Case 4 — Tampered Message

Input:

`Student ID: 12345`

Action:

Run the **Tamper Test**.

Expected result:

Verification fails because the message has been modified.

## Important Note

This simulation uses small RSA parameters for educational demonstration.
They are not suitable for real-world cryptographic security.