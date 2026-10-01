# RSA Digital Signature with Hash

Generate the hash of a message, create an RSA digital signature using the hash, and verify the signature using the corresponding public key.

## Input
- Message text and RSA keypair (public and private keys)

## Output
- Cryptographic hash digest (SHA-256), RSA signature (hex/base64), and signature verification status (Valid / Invalid)

## Test
- Sign the hash of message M with private key d. Verify with public key e. Modify 1 character of message M and confirm verification fails.
