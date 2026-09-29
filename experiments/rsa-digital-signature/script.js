document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("btnRsaSign");
    const tamperBtn = document.getElementById("btnTamperTest");
    const input = document.getElementById("plainMsg");
    const output = document.getElementById("rsaSigOutput");

    // Educational RSA parameters
    const p = 61n;
    const q = 53n;
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    const e = 17n;
    const d = 2753n;

    // Fast modular exponentiation
    function modPow(base, exponent, modulus) {
        let result = 1n;
        base = base % modulus;

        while (exponent > 0n) {
            if (exponent % 2n === 1n) {
                result = (result * base) % modulus;
            }

            base = (base * base) % modulus;
            exponent = exponent / 2n;
        }

        return result;
    }

    // Convert message characters into numbers
    function messageToNumbers(message) {
        return Array.from(message).map(character =>
            BigInt(character.charCodeAt(0))
        );
    }

    // Generate RSA signature
    function generateSignature(message) {
        const numbers = messageToNumbers(message);

        for (const number of numbers) {
            if (number >= n) {
                throw new Error(
                    "Message contains a character that is too large for this educational RSA example."
                );
            }
        }

        return numbers.map(number =>
            modPow(number, d, n)
        );
    }

    // Verify RSA signature
    function verifySignature(message, signature) {
        const messageNumbers = messageToNumbers(message);

        if (messageNumbers.length !== signature.length) {
            return false;
        }

        for (let i = 0; i < signature.length; i++) {
            const recoveredMessage =
                modPow(signature[i], e, n);

            if (recoveredMessage !== messageNumbers[i]) {
                return false;
            }
        }

        return true;
    }

    // SIGN AND VERIFY BUTTON
    if (btn && input && output) {
        btn.addEventListener("click", () => {
            const message = input.value.trim();

            if (!message) {
                output.innerHTML = `
                    <p style="color:#b91c1c; font-weight:bold;">
                        Please enter a message first.
                    </p>
                `;
                return;
            }

            try {
                const signature = generateSignature(message);
                const verified = verifySignature(message, signature);

                output.innerHTML = `
                    <h3>RSA Digital Signature Result</h3>

                    <p>
                        <strong>Input Message:</strong>
                        "${message}"
                    </p>

                    <hr>

                    <h4>RSA Key Generation</h4>

                    <p><strong>p:</strong> ${p}</p>
                    <p><strong>q:</strong> ${q}</p>
                    <p><strong>n = p × q:</strong> ${n}</p>
                    <p><strong>φ(n):</strong> ${phi}</p>

                    <p>
                        <strong>Public Key (e, n):</strong>
                        (${e}, ${n})
                    </p>

                    <p>
                        <strong>Private Key (d, n):</strong>
                        (${d}, ${n})
                    </p>

                    <hr>

                    <h4>Signature Generation</h4>

                    <p>
                        <strong>Formula:</strong>
                        S = M<sup>d</sup> mod n
                    </p>

                    <p>
                        <strong>Generated Signature:</strong>
                        <code>[${signature.join(", ")}]</code>
                    </p>

                    <hr>

                    <h4>Signature Verification</h4>

                    <p>
                        <strong>Formula:</strong>
                        M' = S<sup>e</sup> mod n
                    </p>

                    <p>
                        <strong>Verification:</strong>
                        ${
                            verified
                                ? '<span style="color:green; font-weight:bold;">✔ Signature verified successfully using the Public Key!</span>'
                                : '<span style="color:red; font-weight:bold;">✘ Signature verification failed.</span>'
                        }
                    </p>
                `;

            } catch (error) {
                output.innerHTML = `
                    <p style="color:#b91c1c; font-weight:bold;">
                        Error: ${error.message}
                    </p>
                `;
            }
        });
    }

    // TAMPER TEST BUTTON
    if (tamperBtn && input && output) {
        tamperBtn.addEventListener("click", () => {
            const originalMessage = input.value.trim();

            if (!originalMessage) {
                output.innerHTML = `
                    <p style="color:#b91c1c; font-weight:bold;">
                        Please enter a message first.
                    </p>
                `;
                return;
            }

            try {
                // Generate a signature for the ORIGINAL message
                const originalSignature =
                    generateSignature(originalMessage);

                // Create a modified/tampered message
                let tamperedMessage;

                if (originalMessage.endsWith("2")) {
                    tamperedMessage =
                        originalMessage.slice(0, -1) + "3";
                } else {
                    tamperedMessage =
                        originalMessage + "!";
                }

                // Verify the ORIGINAL signature against
                // the MODIFIED message
                const tamperedVerification =
                    verifySignature(
                        tamperedMessage,
                        originalSignature
                    );

                output.innerHTML = `
                    <h3>RSA Digital Signature — Tamper Test</h3>

                    <p>
                        <strong>Original Message:</strong>
                        "${originalMessage}"
                    </p>

                    <p>
                        <strong>Generated Signature:</strong>
                        <code>[${originalSignature.join(", ")}]</code>
                    </p>

                    <hr>

                    <p>
                        <strong>Tampered Message:</strong>
                        "${tamperedMessage}"
                    </p>

                    <p>
                        The original signature is being checked
                        against the modified message.
                    </p>

                    <hr>

                    <h4>Verification Result</h4>

                    <p>
                        <strong>Verification:</strong>
                        ${
                            tamperedVerification
                                ? '<span style="color:red; font-weight:bold;">✘ Tampered message was incorrectly verified.</span>'
                                : '<span style="color:green; font-weight:bold;">✔ Verification failed — message has been tampered with!</span>'
                        }
                    </p>

                    <p>
                        <strong>Conclusion:</strong>
                        Any change to the signed message causes
                        signature verification to fail.
                    </p>
                `;

            } catch (error) {
                output.innerHTML = `
                    <p style="color:#b91c1c; font-weight:bold;">
                        Error: ${error.message}
                    </p>
                `;
            }
        });
    }
});
const quizButton = document.getElementById("checkQuiz");

if (quizButton) {
    quizButton.addEventListener("click", function () {

        const answers = {
            q1: "b",
            q2: "b",
            q3: "b",
            q4: "a",
            q5: "a"
        };

        let score = 0;

        for (let i = 1; i <= 5; i++) {
            const selected = document.querySelector(
                `input[name="q${i}"]:checked`
            );

            const answerBox = document.getElementById(`answer${i}`);

            if (!selected) {
                answerBox.textContent = "Please select an answer.";
                answerBox.style.color = "orange";
            } 
            else if (selected.value === answers[`q${i}`]) {
                score++;
                answerBox.textContent = "✔ Correct!";
                answerBox.style.color = "green";
            } 
            else {
                answerBox.textContent = "✘ Incorrect.";
                answerBox.style.color = "red";
            }
        }

        document.getElementById("quizScore").textContent =
            `Your Score: ${score} / 5`;
    });
}
const feedbackButton = document.getElementById("submitFeedback");

if (feedbackButton) {
    feedbackButton.addEventListener("click", function () {
        const rating = document.getElementById("feedbackRating").value;
        const comment = document.getElementById("feedbackComment").value.trim();
        const message = document.getElementById("feedbackMessage");

        if (rating === "") {
            message.textContent = "Please select a rating.";
            message.style.color = "red";
            return;
        }

        if (comment === "") {
            message.textContent = "Please enter your feedback.";
            message.style.color = "red";
            return;
        }

        message.textContent = "✔ Thank you for your feedback!";
        message.style.color = "green";
    });
}
