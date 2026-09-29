Argon2id Password Hashing
Virtual lab experiment for CSS TH ISE. It implements Argon2id password hashing in the browser and compares its output and computational parameters with MD5, SHA-1, SHA-256, PBKDF2 and bcrypt.
Inputs
Password (text)
Memory size in KB (1024 to 65536)
Iterations (1 to 10)
Parallelism (1 to 4)
A second password to verify against the last generated hash
Outputs
Encoded Argon2id hash containing the parameters, random 16-byte salt and 32-byte digest
Time taken, memory, iterations, parallelism and salt
Verification result (match or no match)
Comparison table with output, time per hash, guesses per second, time for one billion guesses, memory used and suitability for password storage
Dependencies
All libraries are the ones already bundled in `js/vendor/`:
`hash-wasm.min.js` for Argon2id and Argon2 verification
`crypto-js.min.js` for MD5, SHA-1, SHA-256 and PBKDF2
`bcrypt.min.js` for bcrypt
No network access and no package installation are needed.
How to Run
From the repository root:
```bash
python3 -m http.server 8000
```
Open `http://localhost:8000` and select the Argon2id experiment.
Test Cases
Password `correct horse battery staple` with default settings. The hash starts with `$argon2id$v=19$m=16384,t=3,p=1$`.
Verify the same password against that hash. Result: MATCH.
Verify `correct horse battery stapl3`. Result: NO MATCH.
Click "Hash with Argon2id" twice with the same password. The two hashes differ because each uses a new random salt.
Password `abc` in the comparison table. MD5 shows `900150983cd24fb0d6963f7d28e17f72` and SHA-1 starts with `a9993e364706816aba3e25717850c26c`.
Raise memory from 1024 KB to 65536 KB. Argon2id time increases while MD5, SHA-1 and SHA-256 stay almost instant.
Quiz: answer all 5 questions and submit. The score and explanations are shown. "Try again" clears the answers.
Known Limitations
Timings depend on the device and browser and are single-thread estimates. The parallelism setting changes the hash but may not speed it up in a browser.
Very high memory settings can be slow or fail on low-memory phones.
bcrypt and PBKDF2 run on the main thread, so the page may pause for a moment during comparison.
PBKDF2 uses 100000 iterations for a quick demo. Current recommendations are higher.
The comparison is educational and is not a security audit.