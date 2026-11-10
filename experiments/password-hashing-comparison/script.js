
document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("btnBenchmark");
  const pwdInput = document.getElementById("cmpPassword");
  const output = document.getElementById("cmpOutput");
  const status = document.getElementById("benchmarkStatus");

  const encoder = new TextEncoder();

  // Convert bytes into hexadecimal text.
  function toHex(bytes) {
    return Array.from(bytes)
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  // Generate a cryptographically secure random salt.
  function generateSalt() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  function elapsed(start) {
    return (performance.now() - start).toFixed(3);
  }

  function addResultRow(name, hash, time, suitability) {
    return `
      <tr>
        <td><strong>${name}</strong></td>
        <td><code class="hash-value">${hash}</code></td>
        <td>${time} ms</td>
        <td>${suitability}</td>
      </tr>
    `;
  }

  // Show/hide password.
  document.getElementById("showPassword")?.addEventListener("change", event => {
    pwdInput.type = event.target.checked ? "text" : "password";
  });

  // Main benchmark.
  btn?.addEventListener("click", async () => {
    const password = pwdInput.value;

    if (!password) {
      status.textContent = "Please enter a password first.";
      return;
    }

    if (!window.crypto || !crypto.getRandomValues) {
      status.textContent = "Your browser does not support secure random salt generation.";
      return;
    }

    btn.disabled = true;
    output.innerHTML = "<p>Calculating hashes... please wait.</p>";
    status.textContent = "Benchmark running...";

    const results = [];

    try {
      // Each algorithm receives its own random salt.
      const salt = generateSalt();
      const saltHex = toHex(salt);

      // MD5 - salted only for demonstrating salt effect.
      if (typeof CryptoJS !== "undefined") {
        let start = performance.now();
        const md5 = CryptoJS.MD5(saltHex + password).toString();
        results.push(addResultRow(
          "MD5",
          md5,
          elapsed(start),
          '<span class="status-bad">Not suitable</span>'
        ));

        // SHA-1
        start = performance.now();
        const sha1 = CryptoJS.SHA1(saltHex + password).toString();
        results.push(addResultRow(
          "SHA-1",
          sha1,
          elapsed(start),
          '<span class="status-bad">Not suitable</span>'
        ));

        // SHA-256
        start = performance.now();
        const sha256 = CryptoJS.SHA256(saltHex + password).toString();
        results.push(addResultRow(
          "SHA-256",
          sha256,
          elapsed(start),
          '<span class="status-neutral">Too fast for password storage</span>'
        ));
      } else {
        throw new Error("CryptoJS library could not be loaded.");
      }

      // bcrypt
      try {
        if (typeof dcodeIO === "undefined" || !dcodeIO.bcrypt) {
          throw new Error("bcrypt library unavailable");
        }

        const cost = Number(document.getElementById("bcryptCost").value);
        const start = performance.now();
        const bcryptSalt = dcodeIO.bcrypt.genSaltSync(cost);
        const bcryptHash = dcodeIO.bcrypt.hashSync(password, bcryptSalt);

        results.push(addResultRow(
          `bcrypt (cost ${cost})`,
          bcryptHash,
          elapsed(start),
          '<span class="status-good">Suitable</span>'
        ));
      } catch (error) {
        results.push(addResultRow("bcrypt", "Unavailable: " + error.message, "N/A", "Error"));
      }

      // scrypt
      try {
        if (typeof scrypt === "undefined" || typeof scrypt.scrypt !== "function") {
          throw new Error("scrypt library unavailable");
        }

        const N = Number(document.getElementById("scryptN").value);
        const r = 8;
        const p = 1;
        const scryptSalt = generateSalt();
        const start = performance.now();

        const derivedKey = await scrypt.scrypt(
          encoder.encode(password),
          scryptSalt,
          N,
          r,
          p,
          32
        );

        const scryptHash = toHex(derivedKey);
        const scryptEncoded =
          `scrypt$N=${N},r=${r},p=${p}$${toHex(scryptSalt)}$${scryptHash}`;

        results.push(addResultRow(
          "scrypt",
          scryptEncoded,
          elapsed(start),
          '<span class="status-good">Suitable</span>'
        ));
      } catch (error) {
        results.push(addResultRow("scrypt", "Unavailable: " + error.message, "N/A", "Error"));
      }

      // Argon2id
      try {
        if (typeof argon2 === "undefined" || typeof argon2.hash !== "function") {
          throw new Error("Argon2 library unavailable");
        }

        const memory = Number(document.getElementById("argonMemory").value);
        const argonSalt = toHex(generateSalt());
        const start = performance.now();

        const argonResult = await argon2.hash({
          pass: password,
          salt: argonSalt,
          time: 2,
          mem: memory,
          parallelism: 1,
          hashLen: 32,
          type: argon2.ArgonType.Argon2id
        });

        results.push(addResultRow(
          "Argon2id",
          argonResult.encoded,
          elapsed(start),
          '<span class="status-good">Recommended modern choice</span>'
        ));
      } catch (error) {
        results.push(addResultRow("Argon2id", "Unavailable: " + error.message, "N/A", "Error"));
      }

      output.innerHTML = `
        <div class="table-scroll">
          <table class="result-table">
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Generated Hash</th>
                <th>Time (ms)</th>
                <th>Password Storage Suitability</th>
              </tr>
            </thead>
            <tbody>${results.join("")}</tbody>
          </table>
        </div>
        <p class="small-note">
          The fast hashes above use a random salt as a demonstration.
          This does not make MD5, SHA-1 or plain SHA-256 suitable for
          password storage. The bcrypt, scrypt and Argon2id outputs
          use their respective password-hashing methods.
        </p>
      `;

      status.textContent = "Benchmark completed. Compare the results above.";
    } catch (error) {
      output.textContent = "Error: " + error.message;
      status.textContent = "Benchmark could not be completed.";
    } finally {
      btn.disabled = false;
    }
  });

  // Salt demonstration.
  document.getElementById("btnSaltDemo")?.addEventListener("click", () => {
    const password = pwdInput.value;
    const saltOutput = document.getElementById("saltOutput");

    if (!password) {
      saltOutput.textContent = "Please enter a password first.";
      return;
    }

    if (typeof CryptoJS === "undefined") {
      saltOutput.textContent = "CryptoJS library could not be loaded.";
      return;
    }

    const saltA = toHex(generateSalt());
    const saltB = toHex(generateSalt());

    const hashA = CryptoJS.SHA256(saltA + password).toString();
    const hashB = CryptoJS.SHA256(saltB + password).toString();

    saltOutput.innerHTML = `
      <div class="salt-result">
        <strong>Salt A:</strong>
        <code class="hash-value">${saltA}</code>
        <strong>Hash A:</strong>
        <code class="hash-value">${hashA}</code>
      </div>
      <div class="salt-result">
        <strong>Salt B:</strong>
        <code class="hash-value">${saltB}</code>
        <strong>Hash B:</strong>
        <code class="hash-value">${hashB}</code>
      </div>
      <p class="status-good">
        ${hashA !== hashB
        ? "The hashes are different because the salts are different!"
        : "Unexpected match. Try again."}
      </p>
      <p class="small-note">
        This is an educational salt demonstration using SHA-256.
        It is not a recommended password-storage construction.
      </p>
    `;
  });

  // Quiz questions.
  const questions = [
    {
      q: "What is the main purpose of password hashing?",
      options: [
        "To store passwords in plain text",
        "To convert passwords into one-way hash values",
        "To compress passwords",
        "To decrypt passwords"
      ],
      answer: 1,
      explanation: "Hashing converts a password into a one-way value that can be checked during login."
    },
    {
      q: "Which of these is a fast general-purpose hash function?",
      options: ["bcrypt", "scrypt", "MD5", "Argon2id"],
      answer: 2,
      explanation: "MD5 is a fast general-purpose hash function and is unsuitable for password storage."
    },
    {
      q: "Why are fast hash functions unsuitable for password storage?",
      options: [
        "They produce no output",
        "They make password guessing easier",
        "They require too much memory",
        "They cannot process text"
      ],
      answer: 1,
      explanation: "Attackers can test a very large number of password guesses quickly."
    },
    {
      q: "What is a salt?",
      options: [
        "A secret encryption key",
        "A random value added to a password before hashing",
        "The final hash output",
        "A type of password"
      ],
      answer: 1,
      explanation: "A unique random salt helps ensure identical passwords produce different hashes."
    },
    {
      q: "Which algorithm uses a configurable cost factor?",
      options: ["MD5", "SHA-1", "bcrypt", "SHA-256"],
      answer: 2,
      explanation: "bcrypt uses a cost factor that controls its computational work."
    },
    {
      q: "What does memory-hardness mean?",
      options: [
        "The algorithm needs significant memory",
        "The algorithm stores passwords permanently",
        "The algorithm cannot be executed",
        "The algorithm encrypts the computer memory"
      ],
      answer: 0,
      explanation: "Memory-hard algorithms require substantial memory as well as computation."
    },
    {
      q: "Which algorithm is designed to be memory-hard?",
      options: ["MD5", "SHA-1", "scrypt", "SHA-256"],
      answer: 2,
      explanation: "scrypt is specifically designed to make password guessing memory-intensive."
    },
    {
      q: "Which algorithm won the Password Hashing Competition?",
      options: ["MD5", "Argon2", "SHA-1", "SHA-256"],
      answer: 1,
      explanation: "Argon2 was selected as the winner of the Password Hashing Competition."
    },
    {
      q: "What is a brute-force attack?",
      options: [
        "Trying many possible passwords",
        "Deleting stored passwords",
        "Encrypting a database",
        "Generating random salts"
      ],
      answer: 0,
      explanation: "A brute-force attack systematically tries possible password combinations."
    },
    {
      q: "Which is a recommended modern choice for password hashing?",
      options: ["MD5", "SHA-1", "Plain SHA-256", "Argon2id"],
      answer: 3,
      explanation: "Argon2id is a modern password-hashing option recommended by current guidance."
    }
  ];

  const quizContainer = document.getElementById("quizQuestions");
  const quizForm = document.getElementById("quizForm");
  const quizResult = document.getElementById("quizResult");
  const retryButton = document.getElementById("retryQuiz");

  function renderQuiz(showAnswers = false) {
    quizContainer.innerHTML = questions.map((question, index) => `
      <div class="quiz-question">
        <p>${index + 1}. ${question.q}</p>
        ${question.options.map((option, optionIndex) => `
          <label class="quiz-option">
            <input
              type="radio"
              name="question${index}"
              value="${optionIndex}"
              ${showAnswers ? "disabled" : ""}
            >
            ${option}
          </label>
        `).join("")}
        <div class="quiz-explanation" id="explanation${index}" hidden></div>
      </div>
    `).join("");
  }

  renderQuiz();

  quizForm?.addEventListener("submit", event => {
    event.preventDefault();

    let score = 0;

    questions.forEach((question, index) => {
      const selected = quizForm.querySelector(
        `input[name="question${index}"]:checked`
      );

      const explanation = document.getElementById(`explanation${index}`);

      if (selected && Number(selected.value) === question.answer) {
        score++;
        explanation.innerHTML = `<strong class="status-good">Correct!</strong> ${question.explanation}`;
      } else {
        explanation.innerHTML =
          `<strong class="status-bad">Incorrect.</strong> Correct answer: ${question.options[question.answer]}. ${question.explanation}`;
      }

      explanation.hidden = false;
    });

    quizResult.textContent = `Your score: ${score} / ${questions.length}`;
    document.getElementById("submitQuiz").hidden = true;
    retryButton.hidden = false;
  });

  retryButton?.addEventListener("click", () => {
    renderQuiz();
    quizResult.textContent = "";
    document.getElementById("submitQuiz").hidden = false;
    retryButton.hidden = true;
  });
});
