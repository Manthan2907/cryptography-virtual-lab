// RSA Digital Signature Experiment
// Interactive signing, verification and tamper detection

document.addEventListener("DOMContentLoaded", function () {

  const messageInput = document.getElementById("plainMsg");
  const signButton = document.getElementById("btnRsaSign");
  const tamperButton = document.getElementById("btnTamperTest");
  const output = document.getElementById("rsaSigOutput");

  let keyPair = null;
  let lastSignature = null;
  let lastMessage = null;


  // Generate RSA key pair when the experiment loads
  function generateKeys() {

    try {

      keyPair = forge.pki.rsa.generateKeyPair({
        bits: 1024,
        e: 0x10001
      });

      console.log("RSA key pair generated successfully.");

    } catch (error) {

      console.error("RSA key generation failed:", error);

      output.innerHTML =
        "<p>Unable to generate RSA keys.</p>";

    }
  }


  // Convert text into SHA-256 digest
  function calculateHash(message) {

    const md = forge.md.sha256.create();

    md.update(message, "utf8");

    return md.digest().toHex();
  }


  // Create RSA digital signature
  function createSignature(message) {

    if (!keyPair) {
      generateKeys();
    }

    const md = forge.md.sha256.create();

    md.update(message, "utf8");

    const signatureBytes =
      keyPair.privateKey.sign(md);

    return forge.util.bytesToHex(signatureBytes);
  }


  // Verify RSA digital signature
  function verifySignature(message, signatureHex) {

    try {

      if (!keyPair || !signatureHex) {
        return false;
      }

      const md = forge.md.sha256.create();

      md.update(message, "utf8");

      const signatureBytes =
        forge.util.hexToBytes(signatureHex);

      return keyPair.publicKey.verify(
        md.digest().bytes(),
        signatureBytes
      );

    } catch (error) {

      console.error("Verification error:", error);

      return false;
    }
  }


  // Sign and verify button
  if (signButton) {

    signButton.addEventListener("click", function () {

      const message =
        messageInput.value.trim();

      if (!message) {

        output.innerHTML =
          "<p>Please enter a message first.</p>";

        return;
      }


      if (!keyPair) {
        generateKeys();
      }


      lastMessage = message;

      // Create signature
      const signature =
        createSignature(message);

      lastSignature = signature;

      // Verify signature
      const verified =
        verifySignature(message, signature);

      // Calculate message hash
      const hash =
        calculateHash(message);


      output.innerHTML = `

        <div>

          <h3>RSA Digital Signature Result</h3>

          <p>
            <strong>Input Message:</strong>
            ${escapeHtml(message)}
          </p>

          <p>
            <strong>SHA-256 Hash:</strong>
            <br>
            <code>${hash}</code>
          </p>

          <p>
            <strong>Generated RSA Public Key:</strong>
            <br>
            <code>
              (e = 65537, n = ${keyPair.publicKey.n.toString(16)})
            </code>
          </p>

          <p>
            <strong>Computed Signature:</strong>
            <br>
            <code>${signature}</code>
          </p>

          <p>
            <strong>Verification Result:</strong>
            ${
              verified
                ? "Signature Verified Successfully"
                : "Signature Verification Failed"
            }
          </p>

        </div>

      `;

    });

  }


  // Tamper test
  if (tamperButton) {

    tamperButton.addEventListener("click", function () {

      if (!lastSignature || !lastMessage) {

        output.innerHTML =
          "<p>Please click Sign and Verify first.</p>";

        return;
      }


      const tamperedMessage =
        lastMessage + " [MODIFIED]";


      const verificationResult =
        verifySignature(
          tamperedMessage,
          lastSignature
        );


      output.innerHTML = `

        <div>

          <h3>RSA Tamper Test</h3>

          <p>
            <strong>Original Message:</strong>
            ${escapeHtml(lastMessage)}
          </p>

          <p>
            <strong>Modified Message:</strong>
            ${escapeHtml(tamperedMessage)}
          </p>

          <p>
            <strong>Original Signature:</strong>
            <br>
            <code>${lastSignature}</code>
          </p>

          <p>
            <strong>Verification Result:</strong>
            ${
              verificationResult
                ? "Verification Passed"
                : "Verification Failed - Message Was Modified"
            }
          </p>

        </div>

      `;

    });

  }


  // Quiz functionality
  const quizButton =
    document.getElementById("checkQuiz");


  if (quizButton) {

    quizButton.addEventListener("click", function () {

      const correctAnswers = {
        q1: "b",
        q2: "b",
        q3: "b",
        q4: "a",
        q5: "a"
      };


      let score = 0;


      Object.keys(correctAnswers).forEach(function (question) {

        const selected =
          document.querySelector(
            `input[name="${question}"]:checked`
          );

        const answerElement =
          document.getElementById(
            "answer" + question.substring(1)
          );


        if (selected &&
            selected.value === correctAnswers[question]) {

          score++;

          if (answerElement) {
            answerElement.textContent =
              "Correct!";
          }

        } else {

          if (answerElement) {
            answerElement.textContent =
              "Incorrect.";
          }

        }

      });


      const scoreElement =
        document.getElementById("quizScore");


      if (scoreElement) {

        scoreElement.textContent =
          `Your Score: ${score}/5`;

      }

    });

  }


  // Basic HTML escaping
  function escapeHtml(text) {

    const div =
      document.createElement("div");

    div.textContent = text;

    return div.innerHTML;
  }


  // Generate the RSA key pair once
  generateKeys();

});