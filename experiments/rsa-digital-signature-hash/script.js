/*
 * ============================================================
 * RSA DIGITAL SIGNATURE WITH SHA-256
 * ============================================================
 *
 * MAIN EDUCATIONAL FOCUS:
 * SHA-256 HASHING
 *
 * Simulation flow:
 *
 * 1. Explore SHA-256
 * 2. Create RSA signature from the hash
 * 3. Verify the signature
 * 4. Independently experiment with message tampering
 *
 * ============================================================
 */


document.addEventListener("DOMContentLoaded", () => {


  // ==========================================================
  // ELEMENTS
  // ==========================================================


  // SHA playground

  const shaMessage =
    document.getElementById("shaMessage");

  const btnHash =
    document.getElementById("btnHash");

  const btnClearHash =
    document.getElementById("btnClearHash");

  const hashOutput =
    document.getElementById("hashOutput");

  const hashBits =
    document.getElementById("hashBits");

  const hashLength =
    document.getElementById("hashLength");

  const visualMessage =
    document.getElementById("visualMessage");

  const visualHash =
    document.getElementById("visualHash");


  // RSA signing

  const btnSign =
    document.getElementById("btnSign");

  const signHashDisplay =
    document.getElementById("signHashDisplay");

  const sigHex =
    document.getElementById("sigHex");

  const sigBase64 =
    document.getElementById("sigBase64");

  const sigStatus =
    document.getElementById("sigStatus");


  // Verification

  const verifyMsg =
    document.getElementById("verifyMsg");

  const btnVerify =
    document.getElementById("btnVerify");

  const verifyHashComputed =
    document.getElementById("verifyHashComputed");

  const verifyRecoveredHash =
    document.getElementById("verifyRecoveredHash");

  const verifyResult =
    document.getElementById("verifyResult");


  // Tampering

  const tamperOriginal =
    document.getElementById("tamperOriginal");

  const tamperModified =
    document.getElementById("tamperModified");

  const tamperOriginalHash =
    document.getElementById("tamperOriginalHash");

  const tamperModifiedHash =
    document.getElementById("tamperModifiedHash");

  const btnTamper =
    document.getElementById("btnTamper");

  const btnResetTamper =
    document.getElementById("btnResetTamper");

  const tamperResult =
    document.getElementById("tamperResult");


  // Summary

  const summaryMsg =
    document.getElementById("summaryMsg");

  const summaryAlgo =
    document.getElementById("summaryAlgo");

  const summaryHash =
    document.getElementById("summaryHash");

  const summarySigStatus =
    document.getElementById("summarySigStatus");

  const summaryVerifyStatus =
    document.getElementById("summaryVerifyStatus");


  // Quiz

  const quizForm =
    document.getElementById("quizForm");

  const quizResult =
    document.getElementById("quizResult");


  // ==========================================================
  // CHECK LIBRARIES
  // ==========================================================


  if (typeof CryptoJS === "undefined") {

    console.error(
      "CryptoJS library is not loaded."
    );

    return;
  }


  if (typeof forge === "undefined") {

    console.error(
      "Forge library is not loaded."
    );

    return;
  }


  // ==========================================================
  // VARIABLES
  // ==========================================================


  let rsaKeyPair = null;

  let currentSignatureBytes = null;

  let currentSignatureBase64 = "";

  let currentHashHex = "";


  // ==========================================================
  // HELP CONTENT
  // ==========================================================


  const helpBoxes = {

    "sha-message":
      "This is the input to SHA-256. You can enter a word, sentence, number, or any other text.",

    "sha-result":
      "This is the SHA-256 digest. It always represents a 256-bit output, regardless of the length of the input message.",

    "rsa-sign":
      "RSA is used here after SHA-256. The SHA-256 digest is signed with the RSA private key so that the receiver can later verify it.",

    "verification":
      "Verification checks whether the RSA signature is valid for the message. The message is hashed again and the signature is checked using the RSA public key.",

    "tampering":
      "Changing even a small part of the message changes its SHA-256 digest. This is called the avalanche effect and helps detect tampering."

  };


  // ==========================================================
  // HELP BUTTONS
  // ==========================================================


  document
    .querySelectorAll("[data-help]")
    .forEach((button) => {

      button.addEventListener(
        "click",
        () => {

          const topic =
            button.getAttribute("data-help");

          const message =
            helpBoxes[topic];

          if (!message) {
            return;
          }


          /*
           * Find the closest section/card.
           * The help box is inserted into the relevant
           * area rather than opening a large theory popup.
           */

          let target = null;


          if (topic === "sha-message") {

            target =
              document.getElementById(
                "shaMessageHelp"
              );

          }


          else if (topic === "sha-result") {

            target =
              document.getElementById(
                "shaResultHelp"
              );

          }


          else if (topic === "rsa-sign") {

            target =
              document.getElementById(
                "rsaSignHelp"
              );

          }


          else if (topic === "verification") {

            target =
              document.getElementById(
                "verificationHelp"
              );

          }


          else if (topic === "tampering") {

            target =
              document.getElementById(
                "tamperHelp"
              );

          }


          if (!target) {
            return;
          }


          target.textContent =
            message;


          target.classList.toggle(
            "show"
          );

        }

      );

    });


  // ==========================================================
  // SHA-256 FUNCTION
  // ==========================================================


  function calculateSHA256(message) {

    return CryptoJS
      .SHA256(message)
      .toString(
        CryptoJS.enc.Hex
      );

  }


  // ==========================================================
  // HEX / BYTES HELPERS
  // ==========================================================


  function bytesToHex(bytes) {

    return forge.util.bytesToHex(
      bytes
    );

  }


  function hexToBytes(hex) {

    return forge.util.hexToBytes(
      hex
    );

  }


  // ==========================================================
  // DISPLAY SHA-256
  // ==========================================================


  function displayHash(
    message,
    hash
  ) {


    hashOutput.textContent =
      hash;


    hashBits.textContent =
      "256 bits";


    hashLength.textContent =
      hash.length;


    visualMessage.textContent =
      message;


    visualHash.textContent =
      hash;


    summaryMsg.textContent =
      message;


    summaryAlgo.textContent =
      "SHA-256";


    summaryHash.textContent =
      hash;


    signHashDisplay.textContent =
      hash;


    /*
     * Keep tampering original message
     * synchronized with the currently
     * generated message.
     */

    tamperOriginal.value =
      message;


    tamperOriginalHash.textContent =
      hash;


    /*
     * Reset modified message to a
     * simple changed version.
     */

    tamperModified.value =
      message.replace(
        "1000",
        "5000"
      );


    if (
      tamperModified.value ===
      message
    ) {

      tamperModified.value =
        message + " changed";

    }


    tamperModifiedHash.textContent =
      "Click \"Compare Hashes\"";


  }


  // ==========================================================
  // SHA-256 BUTTON
  // ==========================================================


  btnHash.addEventListener(
    "click",
    () => {


      const message =
        shaMessage.value;


      if (!message.trim()) {

        alert(
          "Please enter a message."
        );

        return;

      }


      currentHashHex =
        calculateSHA256(
          message
        );


      displayHash(
        message,
        currentHashHex
      );


      /*
       * Reset RSA-related status because
       * the message may have changed.
       */

      summarySigStatus.textContent =
        "Not generated for this message";


      summaryVerifyStatus.textContent =
        "Not performed";


      sigStatus.textContent =
        "Generate a signature for this message.";


      verifyResult.className =
        "status-card status-neutral";


      verifyResult.textContent =
        "Generate a signature before verification.";


      console.log(
        "SHA-256:",
        currentHashHex
      );

    }
  );


  // ==========================================================
  // CLEAR HASH
  // ==========================================================


  btnClearHash.addEventListener(
    "click",
    () => {


      shaMessage.value =
        "";


      hashOutput.textContent =
        "Enter a message and generate the hash.";


      hashBits.textContent =
        "256 bits";


      hashLength.textContent =
        "64";


      visualMessage.textContent =
        "Waiting...";


      visualHash.textContent =
        "Waiting...";


      currentHashHex =
        "";


      signHashDisplay.textContent =
        "Generate a SHA-256 hash first.";


      sigHex.textContent =
        "Waiting for signature...";


      sigBase64.textContent =
        "Waiting for signature...";


      sigStatus.textContent =
        "Waiting...";


      verifyHashComputed.textContent =
        "Waiting...";


      verifyRecoveredHash.textContent =
        "Waiting...";


      verifyResult.className =
        "status-card status-neutral";


      verifyResult.textContent =
        "Verification has not been performed.";


    }
  );


  // ==========================================================
  // RSA SIGNATURE
  // ==========================================================


  btnSign.addEventListener(
    "click",
    () => {


      const message =
        shaMessage.value;


      if (!message.trim()) {

        alert(
          "Enter a message and generate its SHA-256 hash first."
        );

        return;

      }


      /*
       * If the displayed hash is not
       * for the current message,
       * calculate it again.
       */

      currentHashHex =
        calculateSHA256(
          message
        );


      displayHash(
        message,
        currentHashHex
      );


      sigStatus.textContent =
        "Generating RSA key pair and signature...";


      summarySigStatus.textContent =
        "Generating...";


      /*
       * Generate educational RSA key pair.
       */

      try {

        rsaKeyPair =
          forge.pki.rsa.generateKeyPair({

            bits: 1024,

            e: 65537

          });

      }

      catch (error) {

        console.error(
          "RSA key generation failed:",
          error
        );


        sigStatus.textContent =
          "RSA key generation failed.";


        summarySigStatus.textContent =
          "Failed";


        return;

      }


      // ======================================================
      // CREATE SHA-256 DIGEST FOR RSA SIGNING
      // ======================================================


      try {


        const md =
          forge.md.sha256.create();


        md.update(
          message,
          "utf8"
        );


        /*
         * Real RSA signing operation.
         *
         * Forge performs the appropriate
         * RSA signature encoding.
         */

        currentSignatureBytes =
          rsaKeyPair.privateKey.sign(
            md
          );


        currentSignatureBase64 =
          forge.util.encode64(
            currentSignatureBytes
          );


      }

      catch (error) {

        console.error(
          "RSA signing failed:",
          error
        );


        sigStatus.textContent =
          "Signature generation failed.";


        summarySigStatus.textContent =
          "Failed";


        return;

      }


      // ======================================================
      // DISPLAY SIGNATURE
      // ======================================================


      const signatureHex =
        bytesToHex(
          currentSignatureBytes
        );


      sigHex.textContent =
        signatureHex;


      sigBase64.textContent =
        currentSignatureBase64;


      sigStatus.textContent =
        "✓ RSA signature created successfully.";


      summarySigStatus.textContent =
        "Generated successfully";


      /*
       * Put the original message into
       * the verification section.
       */

      verifyMsg.value =
        message;


      /*
       * Reset verification display.
       */

      verifyHashComputed.textContent =
        "Click Verify Signature";


      verifyRecoveredHash.textContent =
        "Click Verify Signature";


      verifyResult.className =
        "status-card status-neutral";


      verifyResult.textContent =
        "Signature created. You can now verify it.";


      console.log(
        "SHA-256:",
        currentHashHex
      );


      console.log(
        "RSA signature generated."
      );


      console.log(
        "Signature Hex:",
        signatureHex
      );


      console.log(
        "Signature Base64:",
        currentSignatureBase64
      );

    }
  );


  // ==========================================================
  // VERIFY SIGNATURE
  // ==========================================================


  btnVerify.addEventListener(
    "click",
    () => {


      /*
       * A signature must exist first.
       */

      if (
        !rsaKeyPair ||
        !currentSignatureBytes
      ) {

        verifyResult.className =
          "status-card status-invalid";


        verifyResult.textContent =
          "Create the RSA signature first.";


        return;

      }


      const message =
        verifyMsg.value;


      if (!message.trim()) {

        alert(
          "Enter a message for verification."
        );

        return;

      }


      // ======================================================
      // STEP 1: SHA-256 OF RECEIVED MESSAGE
      // ======================================================


      const computedHash =
        calculateSHA256(
          message
        );


      verifyHashComputed.textContent =
        computedHash;


      // ======================================================
      // STEP 2: VERIFY RSA SIGNATURE
      // ======================================================


      let signatureValid =
        false;


      try {


        const md =
          forge.md.sha256.create();


        md.update(
          message,
          "utf8"
        );


        const digestBytes =
          md.digest().bytes();


        /*
         * Actual cryptographic verification.
         */

        signatureValid =
          rsaKeyPair.publicKey.verify(
            digestBytes,
            currentSignatureBytes
          );


      }

      catch (error) {

        console.error(
          "Verification failed:",
          error
        );


        signatureValid =
          false;

      }


      // ======================================================
      // EDUCATIONAL RECOVERED DIGEST
      // ======================================================


      let recoveredHash =
        "";


      try {


        const encodedDigestInfo =
          rsaKeyPair.publicKey.encrypt(
            currentSignatureBytes,
            "RAW"
          );


        const recoveredHex =
          bytesToHex(
            encodedDigestInfo
          );


        /*
         * SHA-256 DigestInfo prefix.
         */

        const sha256Prefix =
          "3031300d060960864801650304020105000420";


        const prefixIndex =
          recoveredHex.indexOf(
            sha256Prefix
          );


        if (prefixIndex !== -1) {


          const digestStart =
            prefixIndex +
            sha256Prefix.length;


          recoveredHash =
            recoveredHex.substring(
              digestStart,
              digestStart + 64
            );


        }


      }

      catch (error) {

        console.log(
          "Educational digest recovery unavailable."
        );

      }


      if (recoveredHash) {

        verifyRecoveredHash.textContent =
          recoveredHash;

      }

      else {

        verifyRecoveredHash.textContent =
          "Verified using RSA public key";

      }


      // ======================================================
      // FINAL RESULT
      // ======================================================


      if (signatureValid) {


        verifyResult.className =
          "status-card status-valid";


        verifyResult.innerHTML = `

          <strong>
            ✓ Signature VALID
          </strong>

          <p style="margin:8px 0 0;">

            The SHA-256 hash of the verification message
            is valid for the RSA signature.

          </p>

          <p style="margin:8px 0 0;">

            Message integrity check:
            <strong>PASS</strong>

          </p>

        `;


        summaryVerifyStatus.textContent =
          "VALID";


      }

      else {


        verifyResult.className =
          "status-card status-invalid";


        verifyResult.innerHTML = `

          <strong>
            ✗ Signature INVALID
          </strong>

          <p style="margin:8px 0 0;">

            The message does not match the original
            signed message.

          </p>

          <p style="margin:8px 0 0;">

            The SHA-256 digest has changed or the
            signature is not valid for this message.

          </p>

        `;


        summaryVerifyStatus.textContent =
          "INVALID";


      }


      console.log(
        "Verification message:",
        message
      );


      console.log(
        "Computed SHA-256:",
        computedHash
      );


      console.log(
        "Recovered digest:",
        recoveredHash
      );


      console.log(
        "RSA verification:",
        signatureValid
      );

    }
  );


  // ==========================================================
  // TAMPERING SIMULATION
  // ==========================================================


  btnTamper.addEventListener(
    "click",
    () => {


      const original =
        tamperOriginal.value;


      const modified =
        tamperModified.value;


      if (!original.trim()) {

        alert(
          "Generate the original SHA-256 hash first."
        );

        return;

      }


      if (!modified.trim()) {

        alert(
          "Enter a modified message."
        );

        return;

      }


      // ======================================================
      // CALCULATE BOTH HASHES
      // ======================================================


      const originalHash =
        calculateSHA256(
          original
        );


      const modifiedHash =
        calculateSHA256(
          modified
        );


      tamperOriginalHash.textContent =
        originalHash;


      tamperModifiedHash.textContent =
        modifiedHash;


      // ======================================================
      // COMPARE
      // ======================================================


      if (
        originalHash ===
        modifiedHash
      ) {


        tamperResult.className =
          "tamper-result status-valid";


        tamperResult.innerHTML = `

          <strong>
            Same Hash
          </strong>

          <p>

            The two inputs are identical.

          </p>

        `;

      }

      else {


        tamperResult.className =
          "tamper-result status-invalid";


        tamperResult.innerHTML = `

          <strong>
            ✓ Tampering Detected
          </strong>

          <p>

            The messages are different, so their SHA-256
            hash values are also different.

          </p>

          <p>

            This demonstrates the
            <strong>avalanche effect</strong>.

          </p>

        `;

      }


      console.log(
        "Original:",
        original
      );


      console.log(
        "Original SHA-256:",
        originalHash
      );


      console.log(
        "Modified:",
        modified
      );


      console.log(
        "Modified SHA-256:",
        modifiedHash
      );

    }
  );


  // ==========================================================
  // RESET TAMPERING
  // ==========================================================


  btnResetTamper.addEventListener(
    "click",
    () => {


      const original =
        tamperOriginal.value;


      tamperModified.value =
        original;


      tamperModifiedHash.textContent =
        "Click Compare Hashes";


      tamperResult.className =
        "tamper-result status-neutral";


      tamperResult.textContent =
        "Modify the message and compare the hashes.";

    }
  );


  // ==========================================================
  // MCQ QUIZ
  // ==========================================================


  quizForm.addEventListener(
    "submit",
    (event) => {


      event.preventDefault();


      /*
       * SHA-focused assessment.
       */

      const correctAnswers = {

        q1: "b",

        q2: "c",

        q3: "a",

        q4: "b",

        q5: "a",

        q6: "b",

        q7: "b",

        q8: "a"

      };


      const explanations = {

        q1:
          "SHA-256 converts an input message into a fixed-size hash value.",

        q2:
          "SHA-256 produces a 256-bit digest.",

        q3:
          "A cryptographic hash is commonly compared to a digital fingerprint of the input.",

        q4:
          "A small change in the input causes a significantly different SHA-256 output.",

        q5:
          "The avalanche effect causes small input changes to produce large changes in the hash.",

        q6:
          "Hashing helps detect modification because a changed message produces a different digest.",

        q7:
          "The same input to SHA-256 produces the same hash output.",

        q8:
          "In hash-then-sign, SHA-256 first produces the digest that is then used in the signing process."

      };


      let score =
        0;


      let unanswered =
        0;


      let review =
        [];


      Object.keys(
        correctAnswers
      ).forEach(
        (question) => {


          const selected =
            quizForm.querySelector(
              `input[name="${question}"]:checked`
            );


          if (!selected) {

            unanswered++;

            review.push(`

              <li>

                <strong>
                  ${question.toUpperCase()}:
                </strong>

                ${explanations[question]}

              </li>

            `);

            return;

          }


          if (
            selected.value ===
            correctAnswers[question]
          ) {

            score++;

          }

          else {

            review.push(`

              <li>

                <strong>
                  ${question.toUpperCase()}:
                </strong>

                ${explanations[question]}

              </li>

            `);

          }

        }
      );


      let resultHTML = `

        <h3>
          Score: ${score} / 8
        </h3>

      `;


      if (score === 8) {

        resultHTML += `

          <p>
            Excellent! You have a strong understanding of SHA-256
            and its role in message integrity.
          </p>

        `;

      }

      else if (score >= 6) {

        resultHTML += `

          <p>
            Good work! Review the explanations below for the
            questions you missed.
          </p>

        `;

      }

      else {

        resultHTML += `

          <p>
            Review the SHA-256 concepts in the Theory and Simulation
            sections and try the quiz again.
          </p>

        `;

      }


      if (review.length > 0) {

        resultHTML += `

          <hr>

          <p>
            <strong>
              Review:
            </strong>
          </p>

          <ul>

            ${review.join("")}

          </ul>

        `;

      }


      quizResult.innerHTML =
        resultHTML;


    }
  );


  // ==========================================================
  // INITIAL STATE
  // ==========================================================


  summaryAlgo.textContent =
    "SHA-256";


  summaryVerifyStatus.textContent =
    "Not performed";


  summarySigStatus.textContent =
    "Not generated";


  /*
   * Generate an initial SHA-256 hash so the user sees
   * an immediate working example.
   */

  const initialMessage =
    shaMessage.value;


  if (initialMessage.trim()) {

    currentHashHex =
      calculateSHA256(
        initialMessage
      );


    displayHash(
      initialMessage,
      currentHashHex
    );

  }
  


});