# Password Hashing Comparison

Compare MD5, SHA-1, SHA-256, bcrypt, scrypt, and Argon2 for password hashing and analyze their security characteristics.

## Input
- Candidate password and configuration parameters

## Output
- Hash outputs, computation times (ms), memory footprint, and resistance against GPU / ASIC cracking

## Test
- Benchmark hashing execution times across fast hashes (MD5, SHA-256) vs slow adaptive/memory-hard hashes (bcrypt, Argon2).
