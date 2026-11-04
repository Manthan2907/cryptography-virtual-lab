"use strict";

/* =========================================
   0. TAB HELPER (safe to run alongside common.js)
   - switches tabs
   - makes data-go buttons/links jump to a tab
========================================= */

(() => {
  const tabs = document.querySelectorAll(".tab-btn[data-tab]");
  const panels = document.querySelectorAll("[data-tab-panel]");
  if (!tabs.length) return;

  function showTab(name) {
    tabs.forEach(tab => {
      const on = tab.dataset.tab === name;
      tab.classList.toggle("active", on);
      tab.setAttribute("aria-selected", on ? "true" : "false");
    });

    panels.forEach(panel => {
      panel.hidden = panel.dataset.tabPanel !== name;
    });
  }

  tabs.forEach(tab => {
    tab.addEventListener("click", () => showTab(tab.dataset.tab));
  });

  document.querySelectorAll("[data-go]").forEach(el => {
    el.addEventListener("click", event => {
      event.preventDefault();
      showTab(el.dataset.go);
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });
})();


/* =========================================
   1. BRUTE-FORCE EDUCATIONAL SIMULATION
========================================= */

(() => {
  const targetInput = document.getElementById("targetPassword");
  if (!targetInput) return;

  const charsetSelect = document.getElementById("characterSet");
  const slowToggle = document.getElementById("slowMode");
  const startBtn = document.getElementById("startBtn");
  const pauseBtn = document.getElementById("pauseBtn");
  const resetBtn = document.getElementById("resetBtn");

  const guessEl = document.getElementById("currentGuess");
  const attemptsEl = document.getElementById("attemptCount");
  const totalEl = document.getElementById("totalCombinations");
  const elapsedEl = document.getElementById("elapsedTime");
  const progressBar = document.getElementById("progressBar");
  const progressText = document.getElementById("progressText");
  const statusEl = document.getElementById("status");

  const sets = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    lowerdigits: "abcdefghijklmnopqrstuvwxyz0123456789",
    all: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*?"
  };

  let target = "";
  let alphabet = "";
  let total = 0;
  let attempts = 0;

  let running = false;
  let paused = false;
  let finished = false;

  let timerId = null;
  let startedAt = 0;
  let elapsedBeforePause = 0;

  const formatNumber = number =>
    number.toLocaleString("en-US");

  function getElapsedTime() {
    if (running) {
      return elapsedBeforePause +
        (performance.now() - startedAt) / 1000;
    }

    return elapsedBeforePause;
  }

  function updateElapsedTime() {
    elapsedEl.textContent =
      getElapsedTime().toFixed(2) + " s";
  }

  function showStatus(message, type = "") {
    statusEl.textContent = message;
    statusEl.className = "status";

    if (type) {
      statusEl.classList.add(type);
    }
  }

  /*
    Convert a number into a candidate password.

    Example using lowercase letters:
    0 = aa
    1 = ab
    2 = ac

    The first character changes more slowly than
    the last character.
  */
  function generateCandidate(index, length, characters) {
    const base = characters.length;
    const result = Array(length);

    for (let position = length - 1; position >= 0; position--) {
      result[position] = characters[index % base];
      index = Math.floor(index / base);
    }

    return result.join("");
  }

  function updateResults() {
    attemptsEl.textContent = formatNumber(attempts);

    const percentage = total > 0
      ? (attempts / total) * 100
      : 0;

    progressBar.value = Math.min(100, percentage);
    progressText.textContent =
      percentage.toFixed(2) + "% complete";

    updateElapsedTime();
  }

  function clearSimulationTimer() {
    if (timerId !== null) {
      clearTimeout(timerId);
      timerId = null;
    }
  }

  function unlockControls() {
    targetInput.disabled = false;
    charsetSelect.disabled = false;

    startBtn.disabled = false;
    pauseBtn.disabled = true;
    pauseBtn.textContent = "Pause";
  }

  function updateSearchSpace() {
    if (running || paused) return;

    const value = targetInput.value;
    const characters = sets[charsetSelect.value];

    const valid =
      value.length >= 1 &&
      value.length <= 4 &&
      [...value].every(character => characters.includes(character));

    if (valid) {
      const combinations =
        Math.pow(characters.length, value.length);

      totalEl.textContent = formatNumber(combinations);

      showStatus(
        "Search space calculated. Press Start when ready."
      );
    } else {
      totalEl.textContent = "—";

      if (value.length > 0) {
        showStatus(
          "Enter 1–4 characters that all belong to the selected character set."
        );
      } else {
        showStatus(
          "Enter a sample password to calculate the search space."
        );
      }
    }
  }

  function resetSimulation(message) {
    clearSimulationTimer();

    running = false;
    paused = false;
    finished = false;

    target = "";
    alphabet = "";
    total = 0;
    attempts = 0;

    startedAt = 0;
    elapsedBeforePause = 0;

    guessEl.textContent = "—";
    attemptsEl.textContent = "0";
    totalEl.textContent = "—";
    elapsedEl.textContent = "0.00 s";

    progressBar.value = 0;
    progressText.textContent = "0% complete";

    unlockControls();

    showStatus(
      message ||
      "Enter a sample password to calculate the search space."
    );

    updateSearchSpace();
  }

  function finishSimulation(message, type = "") {
    clearSimulationTimer();

    running = false;
    paused = false;
    finished = true;

    unlockControls();
    showStatus(message, type);
    updateResults();
  }

  /*
    Process a batch of guesses before refreshing
    the display. Batch size does not affect total
    combinations or the order of candidates.
  */
  function processBatch() {
    if (!running || paused) return;

    const slow = slowToggle.checked;
    const batchSize = slow ? 1 : 10;
    const stopAt = Math.min(total, attempts + batchSize);

    while (attempts < stopAt) {
      const guess = generateCandidate(
        attempts,
        target.length,
        alphabet
      );

      attempts++;
      guessEl.textContent = guess;

      if (guess === target) {
        updateResults();

        finishSimulation(
          "Match found: " + guess +
          " — " + formatNumber(attempts) + " attempt(s).",
          "success"
        );

        return;
      }
    }

    updateResults();

    if (attempts >= total) {
      finishSimulation(
        "Search space exhausted without a match.",
        "error"
      );

      return;
    }

    timerId = setTimeout(processBatch, slow ? 700 : 20);
  }

  targetInput.addEventListener("input", updateSearchSpace);
  charsetSelect.addEventListener("change", updateSearchSpace);

  startBtn.addEventListener("click", () => {
    if (running) return;

    // Resume if the simulation was paused.
    if (paused) {
      paused = false;
      running = true;
      startedAt = performance.now();

      startBtn.disabled = true;
      pauseBtn.disabled = false;
      pauseBtn.textContent = "Pause";

      showStatus("Simulation resumed.");
      processBatch();

      return;
    }

    const value = targetInput.value;
    const characters = sets[charsetSelect.value];

    const valid =
      value.length >= 1 &&
      value.length <= 4 &&
      [...value].every(character => characters.includes(character));

    if (!valid) {
      showStatus(
        "Enter a valid 1–4 character target that matches the selected character set.",
        "error"
      );

      targetInput.focus();
      updateSearchSpace();

      return;
    }

    // A new run starts from the beginning.
    target = value;
    alphabet = characters;
    total = Math.pow(alphabet.length, target.length);

    attempts = 0;
    elapsedBeforePause = 0;
    startedAt = performance.now();

    running = true;
    paused = false;
    finished = false;

    totalEl.textContent = formatNumber(total);
    guessEl.textContent = "—";

    targetInput.disabled = true;
    charsetSelect.disabled = true;

    startBtn.disabled = true;
    pauseBtn.disabled = false;
    pauseBtn.textContent = "Pause";

    showStatus("Running: generating and checking candidates.");

    processBatch();
  });

  pauseBtn.addEventListener("click", () => {
    if (running && !paused) {
      // Pause the simulation.
      paused = true;
      running = false;

      clearSimulationTimer();

      elapsedBeforePause = getElapsedTime();
      startedAt = 0;

      startBtn.disabled = false;
      pauseBtn.textContent = "Resume";

      showStatus("Simulation paused.");
      updateResults();

    } else if (paused && !finished) {
      // Resume the simulation.
      paused = false;
      running = true;
      startedAt = performance.now();

      startBtn.disabled = true;
      pauseBtn.textContent = "Pause";

      showStatus("Simulation resumed.");
      processBatch();
    }
  });

  resetBtn.addEventListener("click", () => {
    resetSimulation();
  });

  resetSimulation();
})();


/* =========================================
   2. TEN-QUESTION QUIZ
========================================= */

(() => {
  const form = document.getElementById("quizForm");
  const container = document.getElementById("quizQuestions");

  if (!form || !container) return;

  const result = document.getElementById("quizResult");
  const retakeButton = document.getElementById("retakeQuiz");

  const questions = [
    {
      question: "What is a brute-force attack?",
      options: [
        "Encrypting a file",
        "Trying possible password combinations systematically",
        "Backing up a database",
        "Compressing data"
      ],
      answer: 1,
      explanation:
        "It systematically tries candidates until a match is found."
    },
    {
      question: "What does a character set describe?",
      options: [
        "Number of users",
        "Password creation date",
        "Characters available for a password",
        "Network speed"
      ],
      answer: 2,
      explanation:
        "The character set defines which characters can appear."
    },
    {
      question: "How many combinations are possible for 2 characters using 26 lowercase letters?",
      options: ["52", "676", "26", "256"],
      answer: 1,
      explanation: "26² = 26 × 26 = 676."
    },
    {
      question: "What generally happens when password length increases?",
      options: [
        "The search space increases",
        "It becomes zero",
        "It never changes",
        "It always decreases"
      ],
      answer: 0,
      explanation:
        "For C available characters and length L, the search space is C^L."
    },
    {
      question: "How does a dictionary attack differ?",
      options: [
        "It is always identical",
        "It only uses numbers",
        "It never tests passwords",
        "It tries candidates from a list of likely words or passwords"
      ],
      answer: 3,
      explanation:
        "A dictionary attack uses a list of likely candidates."
    },
    {
      question: "What does the attempt counter show?",
      options: [
        "Users online",
        "Candidates tested",
        "Storage capacity",
        "Files saved"
      ],
      answer: 1,
      explanation:
        "The counter records how many guesses have been checked."
    },
    {
      question: "With 10 available characters and length 3, what is the search space?",
      options: ["30", "100", "1,000", "10,000"],
      answer: 2,
      explanation: "10³ = 1,000."
    },
    {
      question: "What happens if more characters are available at each position?",
      options: [
        "Search space increases",
        "It becomes zero",
        "Password is revealed",
        "It cannot change"
      ],
      answer: 0,
      explanation:
        "More choices per position create more combinations."
    },
    {
      question: "Why can simulation time vary?",
      options: [
        "Time is always identical",
        "Length has no effect",
        "All devices have identical speed",
        "Guessing speed and system conditions differ"
      ],
      answer: 3,
      explanation:
        "Runtime depends on processing speed and search size. This demo is not a real-world speed estimate."
    },
    {
      question: "Which helps protect against password guessing?",
      options: [
        "Reuse a short password",
        "Use long unique passwords and MFA",
        "Share passwords publicly",
        "Disable monitoring"
      ],
      answer: 1,
      explanation:
        "Long unique passwords and multi-factor authentication improve security."
    }
  ];

  function renderQuiz() {
    result.hidden = true;
    result.replaceChildren();
    container.replaceChildren();

    questions.forEach((item, index) => {
      const section = document.createElement("section");
      section.className = "quiz-question";

      const heading = document.createElement("h3");
      heading.textContent =
        (index + 1) + ". " + item.question;

      section.appendChild(heading);

      item.options.forEach((option, optionIndex) => {
        const label = document.createElement("label");
        label.className = "option";

        const radio = document.createElement("input");
        radio.type = "radio";
        radio.name = "q" + index;
        radio.value = String(optionIndex);
        radio.required = optionIndex === 0;

        label.appendChild(radio);
        label.appendChild(document.createTextNode(" " + option));

        section.appendChild(label);
      });

      container.appendChild(section);
    });
  }

  form.addEventListener("submit", event => {
    event.preventDefault();

    if (!form.reportValidity()) return;

    const answers = new FormData(form);
    let score = 0;

    questions.forEach((item, index) => {
      if (Number(answers.get("q" + index)) === item.answer) {
        score++;
      }
    });

    result.replaceChildren();
    result.hidden = false;

    const heading = document.createElement("h2");
    heading.textContent = "Your score: " + score + " / 10";
    result.appendChild(heading);

    const summary = document.createElement("p");

    if (score >= 8) {
      summary.textContent = "Excellent work!";
    } else if (score >= 5) {
      summary.textContent =
        "Good effort. Review the explanations below.";
    } else {
      summary.textContent =
        "Keep learning. Revisit the Theory tab and try again.";
    }

    result.appendChild(summary);

    questions.forEach((item, index) => {
      const chosen = Number(answers.get("q" + index));

      const box = document.createElement("div");
      box.className = "feedback-item";

      const title = document.createElement("strong");
      title.textContent =
        (index + 1) + ". " +
        (chosen === item.answer ? "Correct" : "Incorrect");

      const answer = document.createElement("p");
      answer.textContent =
        "Correct answer: " + item.options[item.answer];

      const explanation = document.createElement("p");
      explanation.textContent = item.explanation;

      box.appendChild(title);
      box.appendChild(answer);
      box.appendChild(explanation);

      result.appendChild(box);
    });

    result.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });
  });

  retakeButton.addEventListener("click", () => {
    form.reset();
    renderQuiz();
    window.scrollTo({ top: 0, behavior: "smooth" });
  });

  renderQuiz();
})();

/* Feedback is handled by the shared ../../js/feedback.js, so no feedback code is needed here. */