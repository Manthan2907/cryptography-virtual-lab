# Kerberos Authentication Protocol — Virtual Cryptography Laboratory

## Experiment Title
**Kerberos Authentication Protocol Simulation**

## Objective
To provide an interactive, visual, step-by-step educational demonstration of the Kerberos Authentication Protocol for undergraduate cryptographic security courses. Learners observe how mutual authentication, ticket issuing (TGT and Service Tickets), session key distribution, and freshness verification (nonces) work across Client Alice, Authentication Server (AS), Ticket Granting Server (TGS), and Server Identity Bob.

## Inputs
- **Client Identity:** Default `Alice` (editable string)
- **Server Identity:** Default `Bob` (editable string)
- **Nonce:** Default `N12345` (editable string)
- **Session Key Placeholder:** Default `KEY-12345` (editable string)

## Outputs
- **AS-REQ Payload:** Client Identity, Target Realm/TGS, Nonce, Timestamp
- **Ticket Granting Ticket (TGT):** Dynamic simulated token (e.g. `TGT-ALICE-A81F`) & Client-TGS Session Key ($K_{c,tgs}$)
- **TGS-REQ Payload:** Target Server Identity, TGT, Authenticator, Nonce
- **Service Ticket (ST):** Dynamic simulated token (e.g. `ST-ALICE-BOB-72E1`) & Client-Server Session Key ($K_{c,v}$)
- **AP-REQ Payload:** Service Ticket, Authenticator, Target Server Identity
- **Verification Result:** Sequential verification of ticket integrity, authenticator matching, freshness check (nonce verification), and final authentication success state.

## Kerberos Protocol Flow
```
Alice                        AS                         TGS                        Bob
  |                          |                           |                          |
  |-------- AS-REQ --------->|                           |                          |
  |<------- AS-REP (TGT) ----|                           |                          |
  |                                                      |                          |
  |----------------------- TGS-REQ (TGT+Auth) ---------->|                          |
  |<---------------------- TGS-REP (Service Ticket) -----|                          |
  |                                                                                 |
  |---------------------------------- AP-REQ (ST+Auth) ---------------------------->|
  |<--------------------------------- Verified / Success ---------------------------|
```

## How to Run
1. Open `index.html` in `experiments/kerberos/index.html` using any modern web browser.
2. Select the **Simulation** tab.
3. Verify or edit the Client Identity (`Alice`), Server Identity (`Bob`), Nonce (`N12345`), and Session Key Placeholder (`KEY-12345`).
4. Click **Initialize Simulation** to start Step 1.
5. Follow the step-by-step buttons (**Send AS-REQ**, **Generate TGT**, **Send TGS-REQ**, **Generate Service Ticket**, **Send Service Request**).
6. Observe the packet transmission animations and verification steps.
7. Click **Reset Simulation** to generate a new set of dynamic tokens and restart.

## How the Simulation Works
- **Interactive Stepper:** Navigates through 7 distinct protocol stages (Setup, AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ, Verified).
- **Web Animations API:** Animates visual packet badges traveling between Alice, AS, TGS, and Bob across a central communication stage.
- **Dynamic Token Generation:** Each simulation run generates random hex-suffixed TGTs, Service Tickets, Authenticators, and Session Keys to reflect fresh authentication sessions.
- **Input Guardrails:** Validates required inputs before proceeding and disables out-of-sequence step buttons.

## Test Cases
1. **Default Run:** Keep `Alice` and `Bob`, run through Steps 1 to 7, verify that ticket IDs and keys generate dynamically and all checkmarks pass.
2. **Custom Name Test:** Change `Alice` to `Charlie` and `Bob` to `FileServer`, click Initialize, verify that stage diagrams, ticket headers, and final success messages update dynamically to `Charlie` and `FileServer`.
3. **Empty Input Validation:** Clear the Client Identity input and click Initialize. Verify that an error message (`Please enter a client identity.`) appears and Step 2 remains disabled.
4. **Reset Test:** Complete a full run, click **Reset Simulation**, run again, and verify that newly generated ticket IDs differ from the previous run.
5. **Mandatory All-Question Quiz Test:** Open the **Quiz** tab, answer 9 of the 10 questions leaving 1 blank, click **Submit Quiz**. Verify that a browser alert pops up (`Please attempt all questions before submitting the quiz! (1 question(s) remaining)`), the unattempted question card is highlighted in amber, and submission is blocked. Answer the remaining question, click **Submit Quiz**, and verify that the score banner displays your score out of 10 along with detailed explanations.

## Known Limitations
- Educational visualization: Simulated ticket payloads and session keys are conceptual placeholders and do not perform real AES/DES cryptographic encryption or ASN.1 binary encoding.

## Dependencies
**Dependencies:** None.

This experiment uses pure static HTML5, CSS3, and standard vanilla JavaScript (ES6+). It integrates seamlessly with the Virtual Cryptography Laboratory portal layout.
