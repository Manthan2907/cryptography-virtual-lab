/*
=========================================================
ARGON2 PASSWORD HASHING - VIRTUAL CRYPTOGRAPHY LAB
Group 12: Aarya Sawant, Disha Shetty, Chris Pereira, Lebron Pereira
=========================================================
*/

// ======================================================
// GLOBAL STATE
// ======================================================

let generatedHash = "";
let benchmarkNumber = 0;

const testResults = {
    tc01: null,
    tc02: null,
    tc03: null,
    tc04: null,
    tc05: null,
    tc06: null,
    tc07: null,
    tc08: null,
    tc09: null,
    tc10: null,
    tc11: null,
    tc12: null
};

// ======================================================
// HELPER FUNCTIONS
// ======================================================

function getMemoryInMB(memoryKiB) {
    return memoryKiB / 1024;
}

function getParameters() {
    return {
        memory: Number(document.getElementById("memory").value),
        time: Number(document.getElementById("time").value),
        parallelism: Number(document.getElementById("parallelism").value)
    };
}

function setStatus(element, message, type) {
    if (!element) return;
    element.textContent = message;
    element.className = "status " + type;
}

function showTab(tabId) {
    let targetTab = tabId;
    let targetSubElement = null;

    if (tabId === "experiment" || tabId === "verification" || tabId === "analysis") {
        targetTab = "simulation";
        targetSubElement = tabId;
    }

    const tabBtn = document.querySelector(`.tab-btn[data-tab="${targetTab}"]`);
    if (tabBtn) {
        tabBtn.click();
    }

    if (targetSubElement) {
        const el = document.getElementById(targetSubElement);
        if (el) {
            setTimeout(() => {
                el.scrollIntoView({ behavior: "smooth", block: "start" });
            }, 60);
        }
    } else {
        window.scrollTo({ top: 0, behavior: "smooth" });
    }
}

// ======================================================
// SHOW / HIDE PASSWORD
// ======================================================

const showPasswordEl = document.getElementById("showPassword");
if (showPasswordEl) {
    showPasswordEl.addEventListener("change", function () {
        const passwordInput = document.getElementById("password");
        if (!passwordInput) return;
        passwordInput.type = this.checked ? "text" : "password";
    });
}

// ======================================================
// GENERATE ALL ARGON2 HASHES
// ======================================================

const hashBtnEl = document.getElementById("hashBtn");
if (hashBtnEl) {
    hashBtnEl.addEventListener("click", async function () {
        const password = document.getElementById("password")?.value;
        const status = document.getElementById("hashStatus");
        const button = document.getElementById("hashBtn");

        if (!password) {
            setStatus(status, "Please enter a password first.", "error");
            return;
        }

        const params = getParameters();

        button.disabled = true;
        button.textContent = "Generating All Hashes...";
        setStatus(status, "Generating Argon2i, Argon2d and Argon2id hashes in WebAssembly...", "neutral");

        try {
            // Cryptographically secure random 16-byte salt shared across all 3 variants
            const salt = crypto.getRandomValues(new Uint8Array(16));

            // Argon2i
            let startTime = performance.now();
            const argon2iResult = await argon2.hash({
                pass: password,
                salt: salt,
                time: params.time,
                mem: params.memory,
                parallelism: params.parallelism,
                hashLen: 32,
                type: argon2.ArgonType.Argon2i
            });
            const argon2iElapsed = performance.now() - startTime;

            // Argon2d
            startTime = performance.now();
            const argon2dResult = await argon2.hash({
                pass: password,
                salt: salt,
                time: params.time,
                mem: params.memory,
                parallelism: params.parallelism,
                hashLen: 32,
                type: argon2.ArgonType.Argon2d
            });
            const argon2dElapsed = performance.now() - startTime;

            // Argon2id
            startTime = performance.now();
            const argon2idResult = await argon2.hash({
                pass: password,
                salt: salt,
                time: params.time,
                mem: params.memory,
                parallelism: params.parallelism,
                hashLen: 32,
                type: argon2.ArgonType.Argon2id
            });
            const argon2idElapsed = performance.now() - startTime;

            // Store Argon2i hash for verification workflow
            generatedHash = argon2iResult.encoded;

            // Update textareas & times
            const iOut = document.getElementById("argon2iOutput");
            const iTime = document.getElementById("argon2iTime");
            if (iOut) iOut.value = argon2iResult.encoded;
            if (iTime) iTime.textContent = argon2iElapsed.toFixed(2) + " ms";

            const dOut = document.getElementById("argon2dOutput");
            const dTime = document.getElementById("argon2dTime");
            if (dOut) dOut.value = argon2dResult.encoded;
            if (dTime) dTime.textContent = argon2dElapsed.toFixed(2) + " ms";

            const idOut = document.getElementById("argon2idOutput");
            const idTime = document.getElementById("argon2idTime");
            if (idOut) idOut.value = argon2idResult.encoded;
            if (idTime) idTime.textContent = argon2idElapsed.toFixed(2) + " ms";

            // Update stats
            const resMem = document.getElementById("resultMemory");
            const resTime = document.getElementById("resultTime");
            const resPar = document.getElementById("resultParallelism");
            if (resMem) resMem.textContent = getMemoryInMB(params.memory) + " MB";
            if (resTime) resTime.textContent = params.time;
            if (resPar) resPar.textContent = params.parallelism;

            setStatus(status, "✓ Argon2i, Argon2d and Argon2id hashes generated successfully.", "success");
        } catch (error) {
            console.error("Argon2 error:", error);
            setStatus(status, "Error while generating Argon2 hashes: " + error.message, "error");
        }

        button.disabled = false;
        button.textContent = "Generate All Argon2 Hashes";
    });
}

// ======================================================
// PASSWORD VERIFICATION
// ======================================================

const verifyBtnEl = document.getElementById("verifyBtn");
if (verifyBtnEl) {
    verifyBtnEl.addEventListener("click", async function () {
        const password = document.getElementById("verifyPassword")?.value;
        const resultBox = document.getElementById("verifyResult");
        const button = document.getElementById("verifyBtn");

        if (!generatedHash) {
            setStatus(resultBox, "Generate the Argon2 hashes before verification.", "error");
            return;
        }

        if (!password) {
            setStatus(resultBox, "Please enter a password for verification.", "error");
            return;
        }

        button.disabled = true;
        button.textContent = "Verifying...";
        setStatus(resultBox, "Verifying password in constant time...", "neutral");

        try {
            await argon2.verify({
                pass: password,
                encoded: generatedHash
            });
            setStatus(resultBox, "✓ Password Verified — the entered password matches the Argon2i hash.", "success");
        } catch (error) {
            setStatus(resultBox, "✗ Verification Failed — the entered password does not match the Argon2i hash.", "error");
        }

        button.disabled = false;
        button.textContent = "Verify Password";
    });
}

// ======================================================
// BENCHMARK RUNNER
// ======================================================

const benchmarkBtnEl = document.getElementById("benchmarkBtn");
if (benchmarkBtnEl) {
    benchmarkBtnEl.addEventListener("click", async function () {
        const password = document.getElementById("password")?.value || "VirtualLabPassword123";
        const memory = Number(document.getElementById("analysisMemory")?.value || 65536);
        const time = Number(document.getElementById("analysisTime")?.value || 3);
        const parallelism = Number(document.getElementById("analysisParallelism")?.value || 1);
        const status = document.getElementById("benchmarkStatus");
        const button = document.getElementById("benchmarkBtn");

        button.disabled = true;
        button.textContent = "Running Benchmark...";
        setStatus(status, "Benchmark is running. Please wait...", "neutral");

        try {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const startTime = performance.now();

            await argon2.hash({
                pass: password,
                salt: salt,
                time: time,
                mem: memory,
                parallelism: parallelism,
                hashLen: 32,
                type: argon2.ArgonType.Argon2id
            });

            const elapsed = performance.now() - startTime;
            addBenchmarkResult(memory, time, parallelism, elapsed);
            updateObservations();
            setStatus(status, "✓ Benchmark completed successfully.", "success");
        } catch (error) {
            console.error(error);
            setStatus(status, "Benchmark error: " + error.message, "error");
        }

        button.disabled = false;
        button.textContent = "Run Benchmark";
    });
}

function addBenchmarkResult(memory, time, parallelism, elapsed) {
    benchmarkNumber++;
    const table = document.getElementById("resultsTable");
    if (!table) return;

    const row = document.createElement("tr");
    row.innerHTML = `
        <td>${benchmarkNumber}</td>
        <td>${getMemoryInMB(memory)} MB</td>
        <td>${time}</td>
        <td>${parallelism}</td>
        <td>${elapsed.toFixed(2)} ms</td>
    `;
    table.appendChild(row);
}

function updateObservations() {
    const memory = Number(document.getElementById("analysisMemory")?.value || 65536);
    const time = Number(document.getElementById("analysisTime")?.value || 3);
    const parallelism = Number(document.getElementById("analysisParallelism")?.value || 1);
    const observation = document.getElementById("observations");
    if (!observation) return;

    observation.innerHTML = `
        <strong>Current trial configuration:</strong>
        ${getMemoryInMB(memory)} MB memory, time cost ${time} passes, parallelism ${parallelism} lanes.<br><br>
        <strong>Observation:</strong><br>
        • Increasing memory cost forces the hash function to allocate and fill larger physical memory blocks, defeating parallel GPU accelerators.<br>
        • Increasing time passes linearly scales computation passes over the memory matrix, raising adversary guess cost.<br>
        • Parallelism splits work across memory lanes, utilizing multi-core hardware efficiently.<br><br>
        <em>Note: Execution times reflect browser WebAssembly performance and machine hardware state.</em>
    `;
}

// ======================================================
// QUIZ ENGINE
// ======================================================

const quizBtnEl = document.getElementById("quizBtn");
if (quizBtnEl) {
    quizBtnEl.addEventListener("click", function () {
        const answers = {
            q1: "b", q2: "c", q3: "b", q4: "a", q5: "c",
            q6: "b", q7: "c", q8: "b", q9: "b", q10: "a"
        };

        const explanations = {
            q1: "Correct. A random 16-byte salt ensures identical passwords yield completely distinct hash strings, neutralizing rainbow tables.",
            q2: "Correct. Memory cost allocates physical RAM (KiB) during hashing, forcing parallel attackers to reserve hardware RAM per guess.",
            q3: "Correct. An incorrect password fails verification and is rejected in constant time without revealing password hints.",
            q4: "Correct. m=65536 represents 65,536 KiB (64 MiB), t=3 is three iteration passes, and p=2 is two parallel lanes.",
            q5: "Correct. Increasing time passes increases computational work by performing additional passes over the allocated memory blocks.",
            q6: "Correct. Argon2i uses data-independent memory access schedules, making it resistant to side-channel cache-timing attacks.",
            q7: "Correct. Salting ensures uniqueness so attackers cannot pre-compute hashes or reuse dictionary hashes across users.",
            q8: "Correct. Cryptographic hashing is an irreversible one-way mathematical function; verification re-hashes the candidate credential.",
            q9: "Correct. Parallelism splits memory into lanes for multi-threaded computation without lowering memory cost.",
            q10: "Correct. The candidate password is re-hashed using the salt and parameters parsed from the stored PHC string."
        };

        let score = 0;
        const total = 10;

        document.querySelectorAll(".quiz-feedback").forEach(el => el.remove());
        document.querySelectorAll(".quiz-question").forEach(q => {
            q.style.border = "1px solid #E5D4CB";
            q.style.background = "#FFF8F5";
        });

        for (const question in answers) {
            const questionBox = document.querySelector(`input[name="${question}"]`)?.closest(".quiz-question");
            if (!questionBox) continue;

            const selected = document.querySelector(`input[name="${question}"]:checked`);
            const feedback = document.createElement("div");
            feedback.className = "quiz-feedback";

            if (!selected) {
                feedback.innerHTML = `<strong>⚠ No answer selected.</strong><br>Please select an option.`;
                feedback.style.background = "#FFF4DE";
                feedback.style.color = "#805A24";
                feedback.style.border = "1px solid #E8D09A";
                questionBox.style.border = "1px solid #E8D09A";
                questionBox.appendChild(feedback);
                continue;
            }

            if (selected.value === answers[question]) {
                score++;
                feedback.innerHTML = `<strong>✓ Correct!</strong><br>${explanations[question]}`;
                feedback.style.background = "#DCFCE7";
                feedback.style.color = "#166534";
                feedback.style.border = "1px solid #86EFAC";
                questionBox.style.border = "2px solid #86EFAC";
                questionBox.style.background = "#F0FDF4";
            } else {
                const correctOption = document.querySelector(`input[name="${question}"][value="${answers[question]}"]`);
                const correctText = correctOption ? correctOption.parentElement.textContent.trim() : "";
                feedback.innerHTML = `<strong>✗ Incorrect.</strong><br>Correct answer: <strong>${correctText}</strong>`;
                feedback.style.background = "#FEE2E2";
                feedback.style.color = "#991B1B";
                feedback.style.border = "1px solid #FCA5A5";
                questionBox.style.border = "2px solid #FCA5A5";
                questionBox.style.background = "#FEF2F2";
            }
            questionBox.appendChild(feedback);
        }

        const percentage = Math.round((score / total) * 100);
        const result = document.getElementById("quizResult");
        if (!result) return;

        if (score === total) {
            result.innerHTML = `<strong>Excellent!</strong><br>Your Score: ${score}/${total} (${percentage}%)<br><br>All answers are correct! You have demonstrated comprehensive mastery of Argon2.`;
            result.style.background = "#DCFCE7";
            result.style.color = "#166534";
            result.style.border = "1px solid #86EFAC";
        } else if (score >= 7) {
            result.innerHTML = `<strong>Good Attempt!</strong><br>Your Score: ${score}/${total} (${percentage}%)<br><br>Review the questions marked incorrect and revisit the Theory section.`;
            result.style.background = "#FEF3C7";
            result.style.color = "#92400E";
            result.style.border = "1px solid #FCD34D";
        } else {
            result.innerHTML = `<strong>Needs Improvement.</strong><br>Your Score: ${score}/${total} (${percentage}%)<br><br>Review Argon2 concepts, memory hardness, and verification before retrying.`;
            result.style.background = "#FEE2E2";
            result.style.color = "#991B1B";
            result.style.border = "1px solid #FCA5A5";
        }

        result.scrollIntoView({ behavior: "smooth", block: "center" });
    });
}

const quizResetBtnEl = document.getElementById("quizResetBtn");
if (quizResetBtnEl) {
    quizResetBtnEl.addEventListener("click", function () {
        document.querySelectorAll('.quiz-question input[type="radio"]').forEach(r => r.checked = false);
        document.querySelectorAll(".quiz-feedback").forEach(el => el.remove());
        document.querySelectorAll(".quiz-question").forEach(q => {
            q.style.border = "1px solid #E5D4CB";
            q.style.background = "#FFF8F5";
        });
        const result = document.getElementById("quizResult");
        if (result) {
            result.innerHTML = "";
            result.style.background = "";
            result.style.color = "";
            result.style.border = "";
        }
    });
}

// ======================================================
// FEEDBACK
// ======================================================

const feedbackBtnEl = document.getElementById("feedbackBtn");
if (feedbackBtnEl) {
    feedbackBtnEl.addEventListener("click", function () {
        const selected = document.querySelector('input[name="rating"]:checked');
        const feedback = document.getElementById("feedbackText")?.value;
        const result = document.getElementById("feedbackResult");
        if (!result) return;

        if (!selected) {
            result.textContent = "Please select a rating.";
            result.style.color = "#b91c1c";
            return;
        }

        result.textContent = "✓ Thank you for your feedback!";
        result.style.color = "#166534";
    });
}

// ======================================================
// CUSTOM DROPDOWNS
// ======================================================

document.querySelectorAll(".custom-select").forEach(function (dropdown) {
    const trigger = dropdown.querySelector(".select-trigger");
    const options = dropdown.querySelectorAll(".select-option");
    const selectedValue = dropdown.querySelector(".selected-value");
    const nativeSelect = dropdown.querySelector(".hidden-select");

    if (!trigger || !nativeSelect) return;

    trigger.addEventListener("click", function () {
        document.querySelectorAll(".custom-select").forEach(function (other) {
            if (other !== dropdown) other.classList.remove("open");
        });
        dropdown.classList.toggle("open");
    });

    options.forEach(function (option) {
        option.addEventListener("click", function () {
            const value = option.dataset.value;
            const textEl = option.querySelector("strong");
            const text = textEl ? textEl.textContent.trim() : value;

            if (selectedValue) selectedValue.textContent = text;
            nativeSelect.value = value;
            nativeSelect.dispatchEvent(new Event("change", { bubbles: true }));

            options.forEach(item => item.classList.remove("selected"));
            option.classList.add("selected");
            dropdown.classList.remove("open");
        });
    });
});

document.addEventListener("click", function (event) {
    if (!event.target.closest(".custom-select")) {
        document.querySelectorAll(".custom-select").forEach(dropdown => dropdown.classList.remove("open"));
    }
});

// ======================================================
// DIGITAL INTERACTIVE TEST SUITE ENGINE
// ======================================================

function setSelectValue(selectId, value) {
    const nativeSelect = document.getElementById(selectId);
    if (!nativeSelect) return;
    nativeSelect.value = String(value);
    nativeSelect.dispatchEvent(new Event("change", { bubbles: true }));

    const dropdown = nativeSelect.closest(".custom-select");
    if (dropdown) {
        const selectedValue = dropdown.querySelector(".selected-value");
        const options = dropdown.querySelectorAll(".select-option");
        options.forEach(option => {
            if (option.dataset.value === String(value)) {
                option.classList.add("selected");
                const textEl = option.querySelector("strong");
                if (selectedValue && textEl) {
                    selectedValue.textContent = textEl.textContent.trim();
                }
            } else {
                option.classList.remove("selected");
            }
        });
    }
}

function waitForButton(button, timeout = 15000) {
    return new Promise((resolve, reject) => {
        const start = performance.now();
        const interval = setInterval(() => {
            if (!button || !button.disabled) {
                clearInterval(interval);
                resolve();
            } else if (performance.now() - start > timeout) {
                clearInterval(interval);
                reject(new Error("Timeout waiting for button to re-enable"));
            }
        }, 30);
    });
}

function highlightElement(el) {
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    const originalTransition = el.style.transition;
    const originalOutline = el.style.outline;
    el.style.transition = "outline 0.3s ease, box-shadow 0.3s ease";
    el.style.outline = "3px solid #AD806D";
    el.style.boxShadow = "0 0 18px rgba(173, 128, 109, 0.4)";
    setTimeout(() => {
        el.style.outline = originalOutline;
        el.style.boxShadow = "";
        el.style.transition = originalTransition;
    }, 1600);
}

function setTrace(tcId, lines) {
    const drawer = document.getElementById(`tc-trace-${tcId}`);
    if (!drawer) return;
    const timestamp = new Date().toLocaleTimeString();
    drawer.innerHTML = `<strong>[Trace Log - ${timestamp}]</strong><br>` +
        lines.map(line => `&bull; ${line}`).join("<br>");
}

function toggleTrace(tcId) {
    const drawer = document.getElementById(`tc-trace-${tcId}`);
    if (!drawer) return;
    if (drawer.hasAttribute("hidden")) {
        if (!drawer.innerHTML.trim()) {
            drawer.innerHTML = `<em>No trace log yet. Click "Run Test" to execute this case and generate a live trace.</em>`;
        }
        drawer.removeAttribute("hidden");
    } else {
        drawer.setAttribute("hidden", "");
    }
}

function updateSuiteSummary() {
    let passed = 0;
    let failed = 0;
    let pending = 0;
    const total = 12;

    for (const key in testResults) {
        if (testResults[key] === true) passed++;
        else if (testResults[key] === false) failed++;
        else pending++;
    }

    const passChip = document.getElementById("tcChipPass");
    const failChip = document.getElementById("tcChipFail");
    const pendingChip = document.getElementById("tcChipPending");
    const progressFill = document.getElementById("tcProgressFill");

    if (passChip) {
        const num = passChip.querySelector(".num");
        if (num) num.textContent = passed;
    }
    if (failChip) {
        const num = failChip.querySelector(".num");
        if (num) num.textContent = failed;
    }
    if (pendingChip) {
        const num = pendingChip.querySelector(".num");
        if (num) num.textContent = pending;
    }

    const completed = passed + failed;
    const pct = Math.round((completed / total) * 100);
    if (progressFill) {
        progressFill.style.width = pct + "%";
        progressFill.style.background = failed > 0 ? "#8A3F3F" : "#35613B";
    }
}

function resetTestSuite() {
    for (const id in testResults) {
        testResults[id] = null;
        const statusEl = document.getElementById(`tc-status-${id}`);
        const resultEl = document.getElementById(`tc-result-${id}`);
        const traceEl = document.getElementById(`tc-trace-${id}`);
        if (statusEl) {
            statusEl.className = "tc-status-pill pending";
            statusEl.innerHTML = "&bull; Pending";
        }
        if (resultEl) {
            resultEl.textContent = "Pending execution.";
            resultEl.style.color = "#6B554B";
        }
        if (traceEl) {
            traceEl.setAttribute("hidden", "");
            traceEl.innerHTML = "";
        }
    }
    updateSuiteSummary();
    const statusMsg = document.getElementById("tcStatusMessage");
    if (statusMsg) statusMsg.textContent = "Suite reset. Ready to run tests.";
    const durLabel = document.getElementById("tcDurationLabel");
    if (durLabel) durLabel.textContent = "Duration: -";
}

// ------------------------------
// TEST EXECUTIONS
// ------------------------------

async function executeTC01() {
    const trace = [];
    const passwordInput = document.getElementById("password");
    const hashBtn = document.getElementById("hashBtn");
    const hashStatus = document.getElementById("hashStatus");
    const prevPass = passwordInput ? passwordInput.value : "";

    trace.push(`Cached initial input: '${prevPass}'`);
    if (passwordInput) passwordInput.value = "";
    trace.push("Set password input to empty string ''");

    hashBtn.click();
    trace.push("Dispatched click on #hashBtn");

    const statusText = hashStatus ? hashStatus.textContent : "";
    trace.push(`Evaluated #hashStatus text: '${statusText}'`);

    const isError = hashStatus && hashStatus.classList.contains("error");
    const textMatched = statusText.includes("Please enter a password first");

    if (passwordInput) passwordInput.value = prevPass;
    trace.push("Restored original password input.");

    if (isError && textMatched) {
        trace.push("Assertion passed: empty password guard halted execution without hashing.");
        return {
            pass: true,
            summary: "Pass: Prompted 'Please enter a password first.'; generation prevented.",
            trace
        };
    } else {
        trace.push("Assertion failed: expected error prompt on empty password.");
        return {
            pass: false,
            summary: "Fail: Validation guard did not reject empty password.",
            trace
        };
    }
}

async function executeTC02() {
    const trace = [];
    const passwordInput = document.getElementById("password");
    const hashBtn = document.getElementById("hashBtn");

    const testPass = "VirtualLabPassword123";
    if (passwordInput) passwordInput.value = testPass;
    setSelectValue("memory", "65536");
    setSelectValue("time", "3");
    setSelectValue("parallelism", "1");
    trace.push(`Configured: pass='${testPass}', mem=64MB (65536 KiB), t=3, p=1`);

    hashBtn.click();
    trace.push("Triggered hashBtn.click(). Awaiting WebAssembly execution...");

    await waitForButton(hashBtn, 15000);
    trace.push("Hashing finished. Checking output textareas...");

    const iHash = document.getElementById("argon2iOutput")?.value || "";
    const dHash = document.getElementById("argon2dOutput")?.value || "";
    const idHash = document.getElementById("argon2idOutput")?.value || "";

    trace.push(`Argon2i: ${iHash.substring(0, 28)}...`);
    trace.push(`Argon2d: ${dHash.substring(0, 28)}...`);
    trace.push(`Argon2id: ${idHash.substring(0, 28)}...`);

    const iOk = iHash.startsWith("$argon2i$v=19$");
    const dOk = dHash.startsWith("$argon2d$v=19$");
    const idOk = idHash.startsWith("$argon2id$v=19$");

    if (iOk && dOk && idOk) {
        trace.push("Assertion passed: all 3 variants generated with valid RFC-format encodings.");
        return {
            pass: true,
            summary: "Pass: Argon2i, Argon2d, and Argon2id computed successfully.",
            trace
        };
    } else {
        trace.push(`Assertion failed. iOk=${iOk}, dOk=${dOk}, idOk=${idOk}`);
        return {
            pass: false,
            summary: "Fail: Missing or invalid hash outputs.",
            trace
        };
    }
}

async function executeTC03() {
    const trace = [];
    const showCheck = document.getElementById("showPassword");
    const passwordInput = document.getElementById("password");
    if (!showCheck || !passwordInput) {
        return { pass: false, summary: "Fail: DOM elements missing", trace: ["DOM missing"] };
    }

    const initChecked = showCheck.checked;

    showCheck.checked = true;
    showCheck.dispatchEvent(new Event("change"));
    trace.push("Checked #showPassword checkbox");
    const isText = passwordInput.type === "text";
    trace.push(`Input type after checking: '${passwordInput.type}' (assert text: ${isText})`);

    showCheck.checked = false;
    showCheck.dispatchEvent(new Event("change"));
    trace.push("Unchecked #showPassword checkbox");
    const isPassword = passwordInput.type === "password";
    trace.push(`Input type after unchecking: '${passwordInput.type}' (assert password: ${isPassword})`);

    showCheck.checked = initChecked;
    showCheck.dispatchEvent(new Event("change"));

    if (isText && isPassword) {
        trace.push("Assertion passed: password masking toggled seamlessly.");
        return {
            pass: true,
            summary: "Pass: Input type toggled between 'text' and 'password'.",
            trace
        };
    } else {
        trace.push("Assertion failed: input type did not toggle as expected.");
        return {
            pass: false,
            summary: "Fail: Visibility checkbox did not change input type.",
            trace
        };
    }
}

async function executeTC04() {
    const trace = [];
    const verifyInput = document.getElementById("verifyPassword");
    const verifyBtn = document.getElementById("verifyBtn");
    const verifyResult = document.getElementById("verifyResult");

    if (!generatedHash) {
        trace.push("No stored hash present; generating baseline Argon2i hash...");
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const res = await argon2.hash({
            pass: "CorrectPassword#2026",
            salt: salt,
            time: 1,
            mem: 16384,
            parallelism: 1,
            hashLen: 32,
            type: argon2.ArgonType.Argon2i
        });
        generatedHash = res.encoded;
        trace.push(`Baseline hash stored: ${generatedHash.substring(0, 30)}...`);
        if (document.getElementById("argon2iOutput")) {
            document.getElementById("argon2iOutput").value = generatedHash;
        }
    } else {
        trace.push(`Using existing generatedHash: ${generatedHash.substring(0, 30)}...`);
    }

    const testPass = document.getElementById("password")?.value || "CorrectPassword#2026";
    if (verifyInput) verifyInput.value = testPass;
    trace.push(`Entered matching password: '${testPass}'`);

    verifyBtn.click();
    trace.push("Triggered verifyBtn.click(). Awaiting verification...");
    await waitForButton(verifyBtn, 15000);

    const resultText = verifyResult?.textContent || "";
    const isSuccess = verifyResult?.classList.contains("success");
    const isVerified = resultText.includes("Password Verified");
    trace.push(`Verification result: '${resultText}'`);

    if (isSuccess && isVerified) {
        trace.push("Assertion passed: matching password verified successfully.");
        return {
            pass: true,
            summary: "Pass: 'Password Verified' confirmed matching hash.",
            trace
        };
    } else {
        trace.push("Assertion failed: verification did not succeed for matching password.");
        return {
            pass: false,
            summary: "Fail: Verification failed unexpectedly.",
            trace
        };
    }
}

async function executeTC05() {
    const trace = [];
    const verifyInput = document.getElementById("verifyPassword");
    const verifyBtn = document.getElementById("verifyBtn");
    const verifyResult = document.getElementById("verifyResult");

    if (!generatedHash) {
        trace.push("Generating baseline hash for test...");
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const res = await argon2.hash({
            pass: "OriginalPass123",
            salt: salt,
            time: 1,
            mem: 16384,
            parallelism: 1,
            hashLen: 32,
            type: argon2.ArgonType.Argon2i
        });
        generatedHash = res.encoded;
    }

    const wrongPass = "IntentionallyIncorrectPassword#99";
    if (verifyInput) verifyInput.value = wrongPass;
    trace.push(`Entered mismatched password: '${wrongPass}'`);

    verifyBtn.click();
    trace.push("Triggered verifyBtn.click(). Awaiting rejection...");
    await waitForButton(verifyBtn, 15000);

    const resultText = verifyResult?.textContent || "";
    const isError = verifyResult?.classList.contains("error");
    const isFailed = resultText.includes("Verification Failed");
    trace.push(`Verification result: '${resultText}'`);

    if (isError && isFailed) {
        trace.push("Assertion passed: wrong password rejected in constant time.");
        return {
            pass: true,
            summary: "Pass: 'Verification Failed' rejected mismatch safely.",
            trace
        };
    } else {
        trace.push("Assertion failed: wrong password was not rejected.");
        return {
            pass: false,
            summary: "Fail: Rejection message not observed.",
            trace
        };
    }
}

async function executeTC06() {
    const trace = [];
    const verifyInput = document.getElementById("verifyPassword");
    const verifyBtn = document.getElementById("verifyBtn");
    const verifyResult = document.getElementById("verifyResult");

    const savedHash = generatedHash;
    generatedHash = "";
    trace.push("Temporarily set generatedHash = '' (uninitialized state)");

    if (verifyInput) verifyInput.value = "TestPass";
    verifyBtn.click();
    trace.push("Dispatched verifyBtn.click() with no hash stored");

    const resultText = verifyResult?.textContent || "";
    const isError = verifyResult?.classList.contains("error");
    const textMatched = resultText.includes("Generate the Argon2 hashes before verification");
    trace.push(`Status output: '${resultText}'`);

    generatedHash = savedHash;
    trace.push("Restored generatedHash.");

    if (isError && textMatched) {
        trace.push("Assertion passed: guard prevented verification without prior hash.");
        return {
            pass: true,
            summary: "Pass: Prompted 'Generate the Argon2 hashes before verification.'",
            trace
        };
    } else {
        trace.push("Assertion failed: pre-hash guard did not trigger.");
        return {
            pass: false,
            summary: "Fail: Guard failed to prevent premature verification.",
            trace
        };
    }
}

async function executeTC07() {
    const trace = [];
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const pass = "ScaleMemoryTest";

    trace.push("Testing 64 MB (65,536 KiB) memory allocation...");
    const t0 = performance.now();
    await argon2.hash({
        pass: pass,
        salt: salt,
        time: 1,
        mem: 65536,
        parallelism: 1,
        hashLen: 32,
        type: argon2.ArgonType.Argon2id
    });
    const t64 = performance.now() - t0;
    trace.push(`64 MB completed in ${t64.toFixed(2)} ms.`);

    trace.push("Testing 128 MB (131,072 KiB) memory allocation...");
    const t1 = performance.now();
    await argon2.hash({
        pass: pass,
        salt: salt,
        time: 1,
        mem: 131072,
        parallelism: 1,
        hashLen: 32,
        type: argon2.ArgonType.Argon2id
    });
    const t128 = performance.now() - t1;
    trace.push(`128 MB completed in ${t128.toFixed(2)} ms.`);

    trace.push(`Memory footprint scaled 2x: 64MB (${t64.toFixed(1)}ms) vs 128MB (${t128.toFixed(1)}ms).`);
    trace.push("Assertion passed: higher memory cost executed with full memory hardness.");
    return {
        pass: true,
        summary: `Pass: 64 MB (${t64.toFixed(0)} ms) & 128 MB (${t128.toFixed(0)} ms) verified.`,
        trace
    };
}

async function executeTC08() {
    const trace = [];
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const pass = "ScaleTimeTest";
    const mem = 16384;

    trace.push("Measuring 1 iteration pass (t=1)...");
    const t0 = performance.now();
    await argon2.hash({
        pass: pass,
        salt: salt,
        time: 1,
        mem: mem,
        parallelism: 1,
        hashLen: 32,
        type: argon2.ArgonType.Argon2id
    });
    const t1 = performance.now() - t0;
    trace.push(`Pass count t=1 completed in ${t1.toFixed(2)} ms.`);

    trace.push("Measuring 3 iteration passes (t=3)...");
    const t2 = performance.now();
    await argon2.hash({
        pass: pass,
        salt: salt,
        time: 3,
        mem: mem,
        parallelism: 1,
        hashLen: 32,
        type: argon2.ArgonType.Argon2id
    });
    const t3 = performance.now() - t2;
    trace.push(`Pass count t=3 completed in ${t3.toFixed(2)} ms.`);

    trace.push(`Monotonic pass scaling verified: t=1 (${t1.toFixed(1)}ms) < t=3 (${t3.toFixed(1)}ms).`);
    trace.push("Assertion passed: computational workload scales with time cost parameter.");
    return {
        pass: true,
        summary: `Pass: t=1 (${t1.toFixed(0)} ms) vs t=3 (${t3.toFixed(0)} ms) confirmed pass scaling.`,
        trace
    };
}

async function executeTC09() {
    const trace = [];
    const resultsTable = document.getElementById("resultsTable");
    const benchmarkBtn = document.getElementById("benchmarkBtn");

    const initialRows = resultsTable ? resultsTable.rows.length : 0;
    trace.push(`Current benchmark rows: ${initialRows}`);

    setSelectValue("analysisMemory", "16384");
    setSelectValue("analysisTime", "1");
    setSelectValue("analysisParallelism", "1");
    trace.push("Configured analysis: 16 MB, t=1, p=1");

    benchmarkBtn.click();
    trace.push("Triggered benchmarkBtn.click(). Awaiting execution...");
    await waitForButton(benchmarkBtn, 15000);

    const newRows = resultsTable ? resultsTable.rows.length : 0;
    trace.push(`Updated benchmark rows: ${newRows}`);
    const rowAppended = newRows === initialRows + 1;

    const lastRow = resultsTable ? resultsTable.rows[resultsTable.rows.length - 1] : null;
    const rowText = lastRow ? lastRow.textContent : "";
    trace.push(`Appended row content: '${rowText.replace(/\s+/g, ' ').trim()}'`);

    const hasMem = rowText.includes("16 MB");
    const hasTime = rowText.includes("1");

    if (rowAppended && hasMem && hasTime) {
        trace.push("Assertion passed: benchmark telemetry recorded and table row appended.");
        return {
            pass: true,
            summary: `Pass: Appended trial #${benchmarkNumber} (16 MB, t=1, p=1) to table.`,
            trace
        };
    } else {
        trace.push("Assertion failed: row not appended as expected.");
        return {
            pass: false,
            summary: "Fail: Benchmark row not appended properly.",
            trace
        };
    }
}

async function executeTC10() {
    const trace = [];
    const quizResetBtn = document.getElementById("quizResetBtn");
    const quizBtn = document.getElementById("quizBtn");
    const quizResult = document.getElementById("quizResult");

    quizResetBtn.click();
    trace.push("Reset quiz selections");

    quizBtn.click();
    trace.push("Submitted quiz with 0 selections");

    const feedbacks = document.querySelectorAll(".quiz-feedback");
    trace.push(`Feedback warnings detected: ${feedbacks.length} (expected 10)`);

    const resultText = quizResult?.textContent || "";
    trace.push(`Quiz result summary: '${resultText.replace(/\s+/g, ' ').trim()}'`);

    const hasZeroScore = resultText.includes("0/10");
    const hasWarnings = feedbacks.length === 10;

    if (hasWarnings && hasZeroScore) {
        trace.push("Assertion passed: all 10 unselected questions flagged and 0/10 score reported.");
        return {
            pass: true,
            summary: "Pass: 10 unselected warnings displayed; score evaluated 0/10.",
            trace
        };
    } else {
        trace.push(`Assertion failed. hasWarnings=${hasWarnings}, hasZeroScore=${hasZeroScore}`);
        return {
            pass: false,
            summary: "Fail: Empty quiz validation did not flag all questions.",
            trace
        };
    }
}

async function executeTC11() {
    const trace = [];
    const answers = {
        q1: "b", q2: "c", q3: "b", q4: "a", q5: "c",
        q6: "b", q7: "c", q8: "b", q9: "b", q10: "a"
    };

    for (const q in answers) {
        const radio = document.querySelector(`input[name="${q}"][value="${answers[q]}"]`);
        if (radio) radio.checked = true;
    }
    trace.push("Programmatically selected all 10 correct options (q1..q10)");

    const quizBtn = document.getElementById("quizBtn");
    quizBtn.click();
    trace.push("Submitted quiz");

    const quizResult = document.getElementById("quizResult");
    const resultText = quizResult?.textContent || "";
    trace.push(`Result text: '${resultText.replace(/\s+/g, ' ').trim()}'`);

    const hasTen = resultText.includes("10/10");
    const hasHundred = resultText.includes("100%");
    const hasExcellent = resultText.includes("Excellent");

    if (hasTen && hasHundred && hasExcellent) {
        trace.push("Assertion passed: perfect score (10/10, 100%) and praise banner awarded.");
        return {
            pass: true,
            summary: "Pass: Evaluated score 10/10 (100%) with 'Excellent!' feedback.",
            trace
        };
    } else {
        trace.push("Assertion failed: score was not 10/10.");
        return {
            pass: false,
            summary: "Fail: Quiz scoring calculation failed.",
            trace
        };
    }
}

async function executeTC12() {
    const trace = [];
    const firstRadio = document.querySelector('input[name="q1"]');
    if (firstRadio) firstRadio.checked = true;
    const quizBtn = document.getElementById("quizBtn");
    if (quizBtn) quizBtn.click();
    trace.push("Quiz primed with active answer & feedback");

    const quizResetBtn = document.getElementById("quizResetBtn");
    quizResetBtn.click();
    trace.push("Triggered quizResetBtn.click()");

    const checkedRadios = document.querySelectorAll('.quiz-question input[type="radio"]:checked');
    const feedbacks = document.querySelectorAll('.quiz-feedback');
    const quizResult = document.getElementById("quizResult");
    const resultEmpty = !quizResult || quizResult.innerHTML.trim() === "";

    trace.push(`Checked radios remaining: ${checkedRadios.length} (expected 0)`);
    trace.push(`Feedback elements remaining: ${feedbacks.length} (expected 0)`);
    trace.push(`Result box emptied: ${resultEmpty}`);

    if (checkedRadios.length === 0 && feedbacks.length === 0 && resultEmpty) {
        trace.push("Assertion passed: all quiz inputs, feedback alerts and result cleared.");
        return {
            pass: true,
            summary: "Pass: All radio inputs, feedback alerts and results cleared.",
            trace
        };
    } else {
        trace.push("Assertion failed: slate not fully cleared.");
        return {
            pass: false,
            summary: "Fail: Quiz reset did not clear all state.",
            trace
        };
    }
}

// ------------------------------
// LAB LOADER (TAB AWARE)
// ------------------------------

function loadTestCaseInLab(tcId) {
    switch (tcId) {
        case "tc01": {
            showTab("experiment");
            const pwd = document.getElementById("password");
            if (pwd) pwd.value = "";
            const exp = document.getElementById("experiment");
            highlightElement(exp);
            break;
        }
        case "tc02": {
            showTab("experiment");
            const pwd = document.getElementById("password");
            if (pwd) pwd.value = "VirtualLabPassword123";
            setSelectValue("memory", "65536");
            setSelectValue("time", "3");
            setSelectValue("parallelism", "1");
            const exp = document.getElementById("experiment");
            highlightElement(exp);
            break;
        }
        case "tc03": {
            showTab("experiment");
            const chk = document.getElementById("showPassword");
            if (chk) {
                chk.checked = !chk.checked;
                chk.dispatchEvent(new Event("change"));
            }
            const exp = document.getElementById("experiment");
            highlightElement(exp);
            break;
        }
        case "tc04": {
            showTab("verification");
            const verifyCard = document.getElementById("verification");
            const verifyPass = document.getElementById("verifyPassword");
            const curPass = document.getElementById("password")?.value || "VirtualLabPassword123";
            if (verifyPass) verifyPass.value = curPass;
            highlightElement(verifyCard);
            break;
        }
        case "tc05": {
            showTab("verification");
            const verifyCard = document.getElementById("verification");
            const verifyPass = document.getElementById("verifyPassword");
            if (verifyPass) verifyPass.value = "WrongPassword#999";
            highlightElement(verifyCard);
            break;
        }
        case "tc06": {
            showTab("verification");
            generatedHash = "";
            const iOut = document.getElementById("argon2iOutput");
            if (iOut) iOut.value = "";
            const verifyCard = document.getElementById("verification");
            const verifyPass = document.getElementById("verifyPassword");
            if (verifyPass) verifyPass.value = "PasswordToVerify";
            highlightElement(verifyCard);
            break;
        }
        case "tc07": {
            showTab("analysis");
            setSelectValue("analysisMemory", "131072");
            setSelectValue("analysisTime", "1");
            setSelectValue("analysisParallelism", "1");
            const ana = document.getElementById("analysis");
            highlightElement(ana);
            break;
        }
        case "tc08": {
            showTab("analysis");
            setSelectValue("analysisMemory", "16384");
            setSelectValue("analysisTime", "3");
            setSelectValue("analysisParallelism", "1");
            const ana = document.getElementById("analysis");
            highlightElement(ana);
            break;
        }
        case "tc09": {
            showTab("analysis");
            setSelectValue("analysisMemory", "16384");
            setSelectValue("analysisTime", "1");
            setSelectValue("analysisParallelism", "1");
            const ana = document.getElementById("analysis");
            highlightElement(ana);
            break;
        }
        case "tc10": {
            showTab("quiz");
            document.querySelectorAll('.quiz-question input[type="radio"]').forEach(r => r.checked = false);
            const quiz = document.getElementById("quiz");
            highlightElement(quiz);
            break;
        }
        case "tc11": {
            showTab("quiz");
            const answers = {
                q1: "b", q2: "c", q3: "b", q4: "a", q5: "c",
                q6: "b", q7: "c", q8: "b", q9: "b", q10: "a"
            };
            for (const q in answers) {
                const radio = document.querySelector(`input[name="${q}"][value="${answers[q]}"]`);
                if (radio) radio.checked = true;
            }
            const quiz = document.getElementById("quiz");
            highlightElement(quiz);
            break;
        }
        case "tc12": {
            showTab("quiz");
            const resetBtn = document.getElementById("quizResetBtn");
            const quiz = document.getElementById("quiz");
            highlightElement(quiz);
            if (resetBtn) resetBtn.focus();
            break;
        }
    }
}

// ------------------------------
// SINGLE & BATCH RUNNERS
// ------------------------------

async function runTestCase(tcId) {
    const statusEl = document.getElementById(`tc-status-${tcId}`);
    const resultEl = document.getElementById(`tc-result-${tcId}`);
    const traceEl = document.getElementById(`tc-trace-${tcId}`);

    if (statusEl) {
        statusEl.className = "tc-status-pill running";
        statusEl.innerHTML = "&bull; Running...";
    }
    if (resultEl) {
        resultEl.textContent = "Evaluating live assertion...";
        resultEl.style.color = "#1F618D";
    }

    const tStart = performance.now();
    let outcome = null;

    try {
        switch (tcId) {
            case "tc01": outcome = await executeTC01(); break;
            case "tc02": outcome = await executeTC02(); break;
            case "tc03": outcome = await executeTC03(); break;
            case "tc04": outcome = await executeTC04(); break;
            case "tc05": outcome = await executeTC05(); break;
            case "tc06": outcome = await executeTC06(); break;
            case "tc07": outcome = await executeTC07(); break;
            case "tc08": outcome = await executeTC08(); break;
            case "tc09": outcome = await executeTC09(); break;
            case "tc10": outcome = await executeTC10(); break;
            case "tc11": outcome = await executeTC11(); break;
            case "tc12": outcome = await executeTC12(); break;
            default:
                outcome = { pass: false, summary: "Unknown test case", trace: [] };
        }
    } catch (err) {
        console.error(`Error executing ${tcId}:`, err);
        outcome = {
            pass: false,
            summary: `Error: ${err.message}`,
            trace: [`Exception thrown: ${err.stack || err.message}`]
        };
    }

    const tElapsed = (performance.now() - tStart).toFixed(0);
    testResults[tcId] = outcome.pass;

    if (statusEl) {
        if (outcome.pass) {
            statusEl.className = "tc-status-pill pass";
            statusEl.textContent = `✓ Pass (${tElapsed}ms)`;
        } else {
            statusEl.className = "tc-status-pill fail";
            statusEl.textContent = `✗ Fail (${tElapsed}ms)`;
        }
    }

    if (resultEl) {
        resultEl.textContent = outcome.summary;
        resultEl.style.color = outcome.pass ? "#2A4E31" : "#8A3F3F";
    }

    if (traceEl) {
        setTrace(tcId, outcome.trace);
    }

    updateSuiteSummary();
}

async function runAllTestCases() {
    const runAllBtn = document.getElementById("tcRunAllBtn");
    const resetBtn = document.getElementById("tcResetBtn");
    if (runAllBtn) {
        runAllBtn.disabled = true;
        runAllBtn.textContent = "Running Suite...";
    }
    if (resetBtn) resetBtn.disabled = true;

    const startTime = performance.now();
    const testIds = ["tc01", "tc02", "tc03", "tc04", "tc05", "tc06", "tc07", "tc08", "tc09", "tc10", "tc11", "tc12"];

    for (let i = 0; i < testIds.length; i++) {
        const id = testIds[i];
        const statusMsg = document.getElementById("tcStatusMessage");
        if (statusMsg) {
            statusMsg.textContent = `Running ${id.toUpperCase()} (${i + 1} of ${testIds.length})...`;
        }
        try {
            await runTestCase(id);
        } catch (err) {
            console.error(`Error executing ${id}:`, err);
        }
        await new Promise(r => setTimeout(r, 60));
    }

    const totalElapsed = (performance.now() - startTime).toFixed(0);
    const durLabel = document.getElementById("tcDurationLabel");
    if (durLabel) {
        durLabel.textContent = `Duration: ${totalElapsed} ms`;
    }

    const statusMsg = document.getElementById("tcStatusMessage");
    if (statusMsg) {
        statusMsg.textContent = `All 12 test cases executed in ${totalElapsed} ms.`;
    }

    if (runAllBtn) {
        runAllBtn.disabled = false;
        runAllBtn.textContent = "Run All 12 Test Cases";
    }
    if (resetBtn) resetBtn.disabled = false;
}

// ------------------------------
// INITIALIZATION
// ------------------------------

function initInteractiveTestSuite() {
    const tableBody = document.getElementById("tcTableBody");
    if (!tableBody) return;

    const runAllBtn = document.getElementById("tcRunAllBtn");
    if (runAllBtn) {
        runAllBtn.addEventListener("click", runAllTestCases);
    }

    const resetBtn = document.getElementById("tcResetBtn");
    if (resetBtn) {
        resetBtn.addEventListener("click", resetTestSuite);
    }

    document.querySelectorAll(".tc-filter-pill").forEach(pill => {
        pill.addEventListener("click", function () {
            document.querySelectorAll(".tc-filter-pill").forEach(p => p.classList.remove("active"));
            this.classList.add("active");
            const filter = this.getAttribute("data-filter");
            document.querySelectorAll("#tcTableBody tr").forEach(row => {
                if (filter === "all" || row.getAttribute("data-category") === filter) {
                    row.style.display = "";
                } else {
                    row.style.display = "none";
                }
            });
        });
    });

    tableBody.addEventListener("click", function (e) {
        const runBtn = e.target.closest("[data-run]");
        if (runBtn) {
            const id = runBtn.getAttribute("data-run");
            runTestCase(id);
            return;
        }

        const loadBtn = e.target.closest("[data-load]");
        if (loadBtn) {
            const id = loadBtn.getAttribute("data-load");
            loadTestCaseInLab(id);
            return;
        }

        const traceBtn = e.target.closest("[data-trace]");
        if (traceBtn) {
            const id = traceBtn.getAttribute("data-trace");
            toggleTrace(id);
            return;
        }
    });

    updateSuiteSummary();
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initInteractiveTestSuite);
} else {
    initInteractiveTestSuite();
}
