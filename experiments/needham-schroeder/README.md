# Integration README

Group: Needham-Schroeder | Experiment ID: EXP21
Folder: `/experiments/needham-schroeder/` | Entry file: `index.html`
Navigation Title: Needham-Schroeder Symmetric Key Protocol
Short Description: Simulate the 5-message symmetric-key authentication protocol and see how a shared session key is established, and how it can be attacked.
Required Libraries: None (Web Crypto API) | Input: IDs, keys, nonces, scenario
Output: session key Kab, ticket, message log, authentication result
Expected Navigation Link: `/experiments/needham-schroeder/`

---

## Test-case Table

| Scenario | Inputs | Expected Output | Actual Output in Sim |
| :--- | :--- | :--- | :--- |
| **Normal Run** | Scenario: normal | Messages 1-5 trace successfully. Kab is established. | Authentication successful. |
| **Wrong Kas** | Scenario: wrong_kas | Alice fails to decrypt Msg 2, as it was encrypted with a wrong key. | Step 2 fails. Protocol aborts. |
| **Tampered Ticket** | Scenario: tampered_ticket | Bob's decryption of the ticket (Msg 3) fails due to corrupted ciphertext/GCM tag. | Step 3 fails. Protocol aborts. |
| **Nonce Mismatch** | Scenario: nonce_mismatch | Alice decrypts Msg 2 but finds a different Na than what she sent. | Step 2 fails (Na mismatch). Protocol aborts. |
| **Wrong Nb-1 Reply** | Scenario: wrong_nb1 | Alice sends the wrong (Nb-1) value in Msg 5. Bob detects the mismatch. | Step 5 fails (Nb-1 incorrect). |
| **Replay Attack** | Scenario: replay_attack | Mallory replays an old ticket/Msg 3 using a compromised old Kab. Bob accepts it. | Step 5 succeeds. Attacker bypasses authentication. |
| **Replay + Timestamp Fix** | Scenario: replay_timestamp | Mallory replays the old ticket. Bob checks the timestamp and finds it expired. | Step 3 fails (Ticket stale). Protocol aborts. |

---

## Viva Questions & Model Answers

**Q1: Why is the Needham-Schroeder protocol classified as a symmetric-key protocol?**
*Answer:* Because it relies entirely on symmetric encryption algorithms (like AES or DES) where the sender and receiver use the same secret key. Pre-shared keys (Kas, Kbs) and the session key (Kab) are all symmetric.

**Q2: What is the main purpose of the Key Distribution Center (KDC)?**
*Answer:* The KDC securely distributes a temporary session key (Kab) between two parties who do not initially share a key, avoiding the need for every pair of nodes in a network to store a long-term shared key.

**Q3: What is a "nonce" and what role does it play here?**
*Answer:* A nonce (number used once) is a random, unpredictable number used in a specific protocol run. In this protocol, Alice's nonce (Na) is returned to her encrypted by the KDC, proving that the KDC's message is fresh and not a replay of an old session setup.

**Q4: In Message 2, why is the ticket {Kab, A}Kbs encrypted again inside Alice's message?**
*Answer:* The ticket is primarily encrypted with Bob's key (Kbs) so Alice cannot read or tamper with it. It is double-encrypted under Alice's key (Kas) during transmission in Message 2 simply as part of the entire block sent to Alice, ensuring confidentiality of the entire payload from outsiders.

**Q5: Describe the Denning-Sacco replay vulnerability in the original protocol.**
*Answer:* Bob receives the ticket {Kab, A}Kbs in Message 3. However, there is no freshness indicator (like a nonce or timestamp) inside the ticket for Bob. If an attacker compromises an old session key, they can replay the old ticket to Bob. Bob will accept it, believing Alice wants to communicate.

**Q6: How does Kerberos fix the Denning-Sacco vulnerability?**
*Answer:* Kerberos fixes this by adding timestamps and lifetimes to the ticket. When Bob receives the ticket, he checks the timestamp. If it is too old, he rejects it, preventing the replay of stale tickets.

**Q7: Why does Alice send {Nb - 1} encrypted with Kab in Message 5?**
*Answer:* Bob sends Nb to Alice in Message 4 as a challenge. By decrypting it, subtracting 1 (which requires knowledge of the plaintext), and re-encrypting it, Alice proves to Bob that she possesses the session key Kab and is alive and actively participating in the session.

**Q8: If an attacker intercepts Message 4 ({Nb}Kab) and forwards it back to Bob, can they authenticate as Alice?**
*Answer:* No. Bob expects to receive {Nb - 1}Kab. Even if the attacker reflects the message, they cannot compute Nb - 1 without knowing the session key Kab to decrypt the challenge first.
