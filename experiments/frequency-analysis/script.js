document.addEventListener('DOMContentLoaded', () => {
    // =====================================================================
    //  Frequency Analysis experiment
    //  Requires words.js (loaded before this file) for the ranked dictionary
    // =====================================================================
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // --- Sample data -----------------------------------------------------
    // Builds a cipher->plain lookup for a Caesar shift (cipher = plain + shift)
    function caesarMapping(shift) {
        const m = {};
        for (let i = 0; i < 26; i++) {
            m[alphabet[(i + shift + 26) % 26]] = alphabet[i];
        }
        return m;
    }

    const samples = {
        "1": {
            ciphertext: "WKLV LV D VLPSOH PHVVDJH. LW XVHV D VWDQGDUG FDHVDU VKLIW.",
            plaintext: "THIS IS A SIMPLE MESSAGE. IT USES A STANDARD CAESAR SHIFT.",
            mapping: caesarMapping(3)    // shift +3
        },
        "2": {
            ciphertext: "ZOVMQLDOXMEV FP QEB MOXZQFZB XKA PQRAV LC QBZEKFNRBP CLO PBZROB ZLJJRKFZXQFLK",
            plaintext: "CRYPTOGRAPHY IS THE PRACTICE AND STUDY OF TECHNIQUES FOR SECURE COMMUNICATION",
            mapping: caesarMapping(-3)   // shift -3
        }
    };

    // --- DOM elements ----------------------------------------------------
    const sampleSelector = document.getElementById('sample-selector');
    const ciphertextInput = document.getElementById('ciphertext');
    const btnAnalyze = document.getElementById('btn-analyze');
    const btnReset = document.getElementById('btn-reset');
    const analysisSection = document.getElementById('analysis-section');

    const chartContainer = document.getElementById('chart-container');
    const freqTableHead = document.getElementById('freq-table-head');
    const freqTableCount = document.getElementById('freq-table-count');
    const freqTablePercent = document.getElementById('freq-table-percent');

    const mappingContainer = document.getElementById('mapping-container');
    const btnApplyMapping = document.getElementById('btn-apply-mapping');
    const btnCheckAnswer = document.getElementById('btn-check-answer');
    const btnHint = document.getElementById('btn-hint');
    const hintBox = document.getElementById('hint-box');
    const verificationBox = document.getElementById('verification-box');
    const decryptedOutput = document.getElementById('decrypted-output');
    const btnAutoSolve = document.getElementById('btn-autosolve');

    let currentFreqData = [];
    let currentTotalAlpha = 0;
    let hintLevel = 0;
    let currentMappingInputs = {};

    // --- Initialization --------------------------------------------------
    function init() {
        sampleSelector.addEventListener('change', handleSampleChange);
        btnAnalyze.addEventListener('click', analyzeFrequency);
        btnReset.addEventListener('click', resetSimulation);
        btnApplyMapping.addEventListener('click', applyMapping);
        btnCheckAnswer.addEventListener('click', checkAnswer);
        btnHint.addEventListener('click', showHint);
        if (btnAutoSolve) btnAutoSolve.addEventListener('click', autoSolve);

        initQuiz();
    }

    // --- Core functions --------------------------------------------------
    function handleSampleChange() {
        const val = sampleSelector.value;
        if (val && samples[val]) {
            ciphertextInput.value = samples[val].ciphertext;
        } else {
            ciphertextInput.value = "";
        }
    }

    function analyzeFrequency() {
        const text = ciphertextInput.value.toUpperCase();
        if (!text.trim()) {
            alert("Please enter some ciphertext to analyze.");
            return;
        }

        const counts = {};
        let totalAlpha = 0;

        for (let i = 0; i < 26; i++) {
            counts[String.fromCharCode(65 + i)] = 0;
        }

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            if (char >= 'A' && char <= 'Z') {
                counts[char]++;
                totalAlpha++;
            }
        }

        if (totalAlpha === 0) {
            alert("No alphabetic characters found to analyze.");
            return;
        }

        currentTotalAlpha = totalAlpha;

        // Alphabetical data (chart and mapping use this order)
        let data = Object.keys(counts).map(char => ({
            char: char,
            count: counts[char],
            percent: ((counts[char] / totalAlpha) * 100).toFixed(2)
        }));

        currentFreqData = [...data];

        renderChart(data);
        renderTable(data);
        renderMappingWorkspace(data);

        // Initialize output preview with unmapped text
        applyMapping();

        analysisSection.style.display = 'block';
        hintLevel = 0;
        hintBox.style.display = 'none';
        verificationBox.style.display = 'none';

        // Check Answer only makes sense when the text is an unedited sample
        const sid = sampleSelector.value;
        if (sid && samples[sid] && samples[sid].ciphertext === text.trim()) {
            btnCheckAnswer.style.display = 'inline-block';
        } else {
            btnCheckAnswer.style.display = 'none';
        }
    }

    function renderChart(data) {
        chartContainer.innerHTML = '';
        const maxPercent = Math.max(...data.map(d => parseFloat(d.percent)), 13); // min 13% for scale

        data.forEach(item => {
            const heightPercent = (parseFloat(item.percent) / maxPercent) * 100;

            const barContainer = document.createElement('div');
            barContainer.className = 'bar-container';

            const barValue = document.createElement('div');
            barValue.className = 'bar-value';
            barValue.textContent = item.percent + '%';

            const bar = document.createElement('div');
            bar.className = 'bar';
            bar.style.height = heightPercent + '%';

            const label = document.createElement('div');
            label.className = 'bar-label';
            label.textContent = item.char;

            barContainer.appendChild(barValue);
            barContainer.appendChild(bar);
            barContainer.appendChild(label);
            chartContainer.appendChild(barContainer);
        });
    }

    function renderTable(data) {
        // Sort by frequency, highest first
        const sortedData = [...data].sort((a, b) => b.count - a.count);

        freqTableHead.innerHTML = '<th>Letter</th>';
        freqTableCount.innerHTML = '<th>Count</th>';
        freqTablePercent.innerHTML = '<th>%</th>';

        sortedData.forEach(item => {
            freqTableHead.innerHTML += `<th>${item.char}</th>`;
            freqTableCount.innerHTML += `<td>${item.count}</td>`;
            freqTablePercent.innerHTML += `<td>${item.percent}</td>`;
        });
    }

    function renderMappingWorkspace(data) {
        mappingContainer.innerHTML = '';
        currentMappingInputs = {};

        data.forEach(item => {
            const wrap = document.createElement('div');
            wrap.className = 'mapping-item';

            const label = document.createElement('span');
            label.textContent = item.char;

            const input = document.createElement('input');
            input.type = 'text';
            input.maxLength = 1;
            input.dataset.cipher = item.char;

            currentMappingInputs[item.char] = input;

            wrap.appendChild(label);
            wrap.appendChild(input);
            mappingContainer.appendChild(wrap);
        });
    }

    function applyMapping() {
        const text = ciphertextInput.value.toUpperCase();
        let mappedTextHTML = "";

        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            if (char >= 'A' && char <= 'Z') {
                const input = currentMappingInputs[char];
                const mappedVal = input && input.value ? input.value.toUpperCase() : null;

                if (mappedVal && mappedVal >= 'A' && mappedVal <= 'Z') {
                    mappedTextHTML += `<span class="output-char-mapped">${mappedVal.toLowerCase()}</span>`;
                } else {
                    mappedTextHTML += `<span class="output-char-unmapped">${char}</span>`;
                }
            } else {
                mappedTextHTML += `<span class="output-char-unmapped">${char}</span>`;
            }
        }

        decryptedOutput.innerHTML = mappedTextHTML;
        verificationBox.style.display = 'none';
    }

    function checkAnswer() {
        const sampleId = sampleSelector.value;
        if (!sampleId || !samples[sampleId]) return;

        const expectedMapping = samples[sampleId].mapping;
        const lettersInSample = new Set(samples[sampleId].ciphertext.replace(/[^A-Z]/g, '').split(''));
        let filledCount = 0;
        let incorrectCount = 0;
        let correctNeeded = 0;

        for (const cipherChar in currentMappingInputs) {
            const mappedVal = currentMappingInputs[cipherChar].value.toUpperCase();
            if (mappedVal) {
                filledCount++;
                if (expectedMapping[cipherChar] !== mappedVal) incorrectCount++;
                else if (lettersInSample.has(cipherChar)) correctNeeded++;
            }
        }

        verificationBox.className = 'alert-box';

        if (filledCount === 0) {
            verificationBox.textContent = "Please enter some mappings before checking.";
            verificationBox.classList.add('info');
        } else if (incorrectCount === 0) {
            if (correctNeeded >= lettersInSample.size) {
                verificationBox.textContent = "Excellent work! Every letter in the message is mapped correctly. You have decrypted the message.";
            } else {
                verificationBox.textContent = `Good start! All ${filledCount} mappings so far are correct. ${lettersInSample.size - correctNeeded} letter(s) of the message are still unmapped.`;
            }
            verificationBox.classList.add('success');
        } else {
            verificationBox.textContent = `${incorrectCount} of your ${filledCount} mappings are incorrect. Review your frequency analysis and try again.`;
            verificationBox.classList.add('error');
        }
        verificationBox.style.display = 'block';
    }

    function showHint() {
        if (!currentFreqData.length) {
            hintBox.textContent = "Click Analyze Frequency first, then ask for a hint.";
            hintBox.style.display = 'block';
            return;
        }
        hintLevel++;
        hintBox.style.display = 'block';

        const sorted = [...currentFreqData].sort((a, b) => b.count - a.count);
        const mostFreq = sorted[0].char;

        if (hintLevel === 1) {
            hintBox.textContent = `Hint 1: The most frequent letter in your ciphertext is '${mostFreq}'. In English, the most frequent letter is usually 'E'. Try mapping '${mostFreq}' to 'E'.`;
        } else if (hintLevel === 2) {
            hintBox.textContent = `Hint 2: Look at small common words like "THE", "IS", "AND". After mapping 'E', look for patterns. For example, if you see a 3-letter word ending in 'e', it might be "the".`;
        } else {
            hintBox.textContent = `Hint 3: The next most common English letters are 'T', 'A', 'O', 'I'. Compare the top 4-5 letters in the Ciphertext Frequency Table with the English Reference table.`;
            hintLevel = 0; // restart the hint loop
        }
    }

    function resetSimulation() {
        ciphertextInput.value = '';
        sampleSelector.value = '';
        analysisSection.style.display = 'none';
        chartContainer.innerHTML = '';
        mappingContainer.innerHTML = '';
        decryptedOutput.innerHTML = '';
        freqTableHead.innerHTML = '';
        freqTableCount.innerHTML = '';
        freqTablePercent.innerHTML = '';
        currentFreqData = [];
        currentMappingInputs = {};
        currentTotalAlpha = 0;
        btnCheckAnswer.style.display = 'none';
        hintLevel = 0;
        hintBox.style.display = 'none';
        verificationBox.style.display = 'none';
    }

    // =====================================================================
    //  AUTO-SOLVE
    //  1. Caesar / Atbash / Affine: try every key, accept a clear winner
    //  2. Otherwise: dictionary word-pattern matching (most constrained
    //     word first), then a statistical hill-climb for leftover letters
    //  3. Long texts with poor dictionary coverage: statistical solver
    // =====================================================================
    const ENGLISH_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ";
    const COMMON_BIGRAMS = new Set("TH HE IN ER AN RE ON AT EN ND TI ES OR TE OF ED IS IT AL AR ST TO NT NG SE HA AS OU IO LE VE CO ME DE HI RI RO IC NE EA RA CE LI CH LL BE MA SI OM UR".split(" "));
    const COMMON_TRIGRAMS = new Set("THE AND ING ENT ION HER FOR THA NTH INT ERE TIO TER EST ERS ATI HAT ATE ALL ETH HES VER HIS OFT ITH FTH STH OTH RES ONT".split(" "));
    const COMMON_WORDS = new Set("THE AND OF TO A IN IS THAT IT FOR AS WITH WAS ON BE BY AT THIS ARE FROM OR AN HAVE NOT BUT WE YOU ALL CAN HER HIS THEY WILL ONE WHICH THERE THEIR HAS BEEN IF MORE WHEN WHO SO NO USE USES".split(" "));

    function scoreText(plain) {
        let score = 0;
        const words = plain.split(/[^A-Z]+/);
        for (const w of words) {
            if (!w) continue;
            if (COMMON_WORDS.has(w)) score += 2 * w.length;
            for (let i = 0; i + 1 < w.length; i++) {
                if (COMMON_BIGRAMS.has(w.substr(i, 2))) score += 1;
                if (i + 2 < w.length && COMMON_TRIGRAMS.has(w.substr(i, 3))) score += 3;
            }
        }
        return score;
    }

    // ---- Statistical solver (frequency start + hill climbing) ----
    function solveSubstitution(cipher) {
        const counts = Array(26).fill(0);
        for (const ch of cipher) {
            if (ch >= 'A' && ch <= 'Z') counts[ch.charCodeAt(0) - 65]++;
        }

        const order = [...Array(26).keys()].sort((a, b) => counts[b] - counts[a]);
        const startKey = Array(26);
        order.forEach((cipherIdx, rank) => { startKey[cipherIdx] = ENGLISH_ORDER[rank]; });

        const decrypt = k => cipher.replace(/[A-Z]/g, ch => k[ch.charCodeAt(0) - 65]);

        function climb(k) {
            let best = scoreText(decrypt(k));
            let improved = true;
            while (improved) {
                improved = false;
                for (let i = 0; i < 26; i++) {
                    for (let j = i + 1; j < 26; j++) {
                        [k[i], k[j]] = [k[j], k[i]];
                        const s = scoreText(decrypt(k));
                        if (s > best) { best = s; improved = true; }
                        else { [k[i], k[j]] = [k[j], k[i]]; }
                    }
                }
            }
            return best;
        }

        let bestKey = startKey.slice();
        let bestScore = climb(bestKey);

        for (let r = 0; r < 15; r++) {
            const k = bestKey.slice();
            for (let t = 0; t < 4; t++) {
                const a = Math.floor(Math.random() * 26);
                const b = Math.floor(Math.random() * 26);
                [k[a], k[b]] = [k[b], k[a]];
            }
            const s = climb(k);
            if (s > bestScore) { bestScore = s; bestKey = k; }
        }
        return bestKey;
    }

    // ---- Dictionary: ranked list from words.js, with a tiny fallback ----
    const WORD_LIST = (window.WORD_FREQ && window.WORD_FREQ.length)
        ? window.WORD_FREQ
        : "THE OF AND TO A IN IS THAT IT FOR AS WITH WAS ON BE BY AT THIS ARE FROM OR AN I".split(" ");

    const WORD_RANK = {};                       // lower number = more common
    WORD_LIST.forEach((w, i) => { if (!(w in WORD_RANK)) WORD_RANK[w] = i; });
    const WORD_SET = new Set(WORD_LIST);

    // very common words weigh about 3, rare words tend towards 1
    function wordWeight(w) {
        const r = WORD_RANK[w];
        if (r === undefined) return 0;
        return 1 + 2 / (1 + r / 300);
    }

    function wordPattern(w) {
        const m = {}; let n = 0;
        return [...w].map(c => (m[c] === undefined ? (m[c] = n++) : m[c])).join(',');
    }

    const WORDS_BY_PATTERN = {};
    WORD_LIST.forEach(w => {
        const p = wordPattern(w);
        (WORDS_BY_PATTERN[p] = WORDS_BY_PATTERN[p] || []).push(w);   // kept in rank order
    });

    // ---- Dictionary word-pattern solver ----
    // Repeatedly picks the cipher word with the fewest dictionary candidates
    // that fit the letters fixed so far, so one solid match narrows the rest.
    function solveByWords(cipher, nodeLimit) {
        const words = [...new Set(cipher.split(/[^A-Z]+/).filter(Boolean))];
        const pats = words.map(wordPattern);
        let best = { score: -1, map: {} };
        let nodes = 0;

        function consistent(w, cand, c2p, p2c) {
            for (let k = 0; k < w.length; k++) {
                const c = w[k], p = cand[k];
                if (c2p[c] !== undefined) { if (c2p[c] !== p) return false; }
                else if (p2c[p] !== undefined) return false;
            }
            return true;
        }

        function search(done, c2p, p2c, score) {
            if (++nodes > nodeLimit) return;
            if (score > best.score) best = { score, map: { ...c2p } };

            let remaining = 0;
            for (let i = 0; i < words.length; i++) if (!done[i]) remaining += words[i].length * 3;
            if (score + remaining <= best.score) return;      // cannot beat best

            let pick = -1, pickCands = null;
            for (let i = 0; i < words.length; i++) {
                if (done[i]) continue;
                const cands = (WORDS_BY_PATTERN[pats[i]] || []).filter(c => consistent(words[i], c, c2p, p2c));
                if (cands.length === 0) { done[i] = 2; continue; }   // no dictionary word fits
                if (pickCands === null || cands.length < pickCands.length ||
                    (cands.length === pickCands.length && words[i].length > words[pick].length)) {
                    pick = i; pickCands = cands;
                }
            }
            if (pick < 0) return;

            const w = words[pick];
            done[pick] = 1;
            for (const cand of pickCands.slice(0, 60)) {
                const added = [];
                for (let k = 0; k < w.length; k++) {
                    const c = w[k], p = cand[k];
                    if (c2p[c] === undefined) { c2p[c] = p; p2c[p] = c; added.push(c); }
                }
                const snapshot = done.slice();
                search(done, c2p, p2c, score + w.length * wordWeight(cand));
                for (let i = 0; i < done.length; i++) done[i] = snapshot[i];
                for (const c of added) { delete p2c[c2p[c]]; delete c2p[c]; }
                if (nodes > nodeLimit) break;
            }
            done[pick] = 2;                        // option: word is not in the dictionary
            search(done, c2p, p2c, score);
            done[pick] = 0;
        }

        search(words.map(() => 0), {}, {}, 0);
        return best.map;
    }

    // ---- Classical solver: tries every Caesar / Atbash / Affine key ----
    function solveClassical(cipher) {
        const results = [];
        for (const a of [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]) {
            for (let b = 0; b < 26; b++) {
                const map = {};
                for (let p = 0; p < 26; p++) {
                    map[alphabet[(a * p + b) % 26]] = alphabet[p];   // cipher -> plain
                }
                const plain = cipher.replace(/[A-Z]/g, c => map[c]);
                let score = scoreText(plain);
                for (const w of plain.split(/[^A-Z]+/)) {
                    if (w.length > 1 && WORD_SET.has(w)) score += 3 * w.length;
                }
                results.push({ a, b, map, score });
            }
        }
        results.sort((x, y) => y.score - x.score);
        const best = results[0], second = results[1];

        // must be clearly ahead of the runner-up
        if (best.score < 8 || best.score < 1.2 * second.score) return null;

        // and the result must be mostly real dictionary words
        const bestPlain = cipher.replace(/[A-Z]/g, c => best.map[c]);
        const ws = bestPlain.split(/[^A-Z]+/).filter(Boolean);
        const total = ws.reduce((n, w) => n + w.length, 0);
        const known = ws.filter(w => WORD_SET.has(w)).reduce((n, w) => n + w.length, 0);
        if (total === 0 || known / total < 0.6) return null;

        let name;
        if (best.a === 1) name = `Caesar cipher (shift ${best.b})`;
        else if (best.a === 25 && best.b === 25) name = "Atbash cipher";
        else name = `Affine cipher (a=${best.a}, b=${best.b})`;
        return { mapping: best.map, name };
    }

    // Fill letters the word solver could not place, then polish them by hill climbing
    function completeMapping(text, mapping) {
        const used = new Set(Object.values(mapping));
        const freeP = [...ENGLISH_ORDER].filter(p => !used.has(p));
        const count = c => (text.split(c).length - 1);
        const freeC = [...alphabet].filter(c => !(c in mapping)).sort((a, b) => count(b) - count(a));
        freeC.forEach((c, i) => { mapping[c] = freeP[i]; });

        const dec = m => text.replace(/[A-Z]/g, c => m[c]);
        let best = scoreText(dec(mapping)), improved = true;
        while (improved) {
            improved = false;
            for (let i = 0; i < freeC.length; i++) {
                for (let j = i + 1; j < freeC.length; j++) {
                    [mapping[freeC[i]], mapping[freeC[j]]] = [mapping[freeC[j]], mapping[freeC[i]]];
                    const s = scoreText(dec(mapping));
                    if (s > best) { best = s; improved = true; }
                    else { [mapping[freeC[i]], mapping[freeC[j]]] = [mapping[freeC[j]], mapping[freeC[i]]]; }
                }
            }
        }
        return mapping;
    }

    function computeSolution(text) {
        const letters = text.replace(/[^A-Z]/g, '');
        const classical = solveClassical(text);
        if (classical) {
            return { mapping: classical.mapping, message: `Detected ${classical.name}. Solution filled in.` };
        }

        const isLong = letters.length >= 200;
        const wordMap = solveByWords(text, isLong ? 4000 : 60000);
        const covered = letters.split('').filter(c => wordMap[c] !== undefined).length;
        const coverage = letters.length ? covered / letters.length : 0;

        if (isLong && coverage < 0.7) {
            const key = solveSubstitution(text);
            const mapping = {};
            for (let i = 0; i < 26; i++) mapping[alphabet[i]] = key[i];
            return { mapping, message: "Auto-solve made a statistical best guess. Fix any wrong letters by hand." };
        }

        const mapping = completeMapping(text, { ...wordMap });
        const message = coverage >= 0.999
            ? "Solved by dictionary matching. Short texts can have more than one valid reading, so check that the preview makes sense."
            : "Best guess from dictionary matching plus statistics. Check the preview and fix any wrong letters by hand.";
        return { mapping, message };
    }

    function autoSolve() {
        analyzeFrequency();
        if (analysisSection.style.display === 'none') return;

        const text = ciphertextInput.value.toUpperCase();
        const sid = sampleSelector.value;
        let mapping, message;

        if (sid && samples[sid] && samples[sid].ciphertext === text.trim()) {
            mapping = samples[sid].mapping;
            message = "Solution filled in from the sample's answer key.";
        } else {
            ({ mapping, message } = computeSolution(text));
        }

        currentFreqData.forEach(item => {
            if (item.count > 0 && currentMappingInputs[item.char]) {
                currentMappingInputs[item.char].value = mapping[item.char] || '';
            }
        });

        applyMapping();   // this hides verificationBox, so set the message afterwards
        verificationBox.className = 'alert-box info';
        verificationBox.textContent = message;
        verificationBox.style.display = 'block';
    }

    // test hook (harmless in the browser)
    window.__computeSolution = computeSolution;

    // =====================================================================
    //  QUIZ (10 questions)
    // =====================================================================
    const quizData = [
        {
            question: "What is frequency analysis in cryptography?",
            options: [
                "A method of guessing passwords quickly.",
                "The study of how often letters or groups of letters appear in ciphertext.",
                "A mathematical formula to generate prime numbers.",
                "Encrypting data multiple times."
            ],
            correct: 1
        },
        {
            question: "Which English letter is typically the most frequent?",
            options: ["A", "T", "E", "O"],
            correct: 2
        },
        {
            question: "Frequency analysis is most effective against which type of cipher?",
            options: [
                "Monoalphabetic substitution cipher",
                "Polyalphabetic substitution cipher (like Vigenère)",
                "One-time pad",
                "Advanced Encryption Standard (AES)"
            ],
            correct: 0
        },
        {
            question: "Why might frequency analysis fail on a very short ciphertext?",
            options: [
                "Short ciphertexts don't use substitution.",
                "The letter distribution in a short text may not match standard language statistics.",
                "The alphabet changes dynamically in short texts.",
                "It takes too much computational power to analyze short texts."
            ],
            correct: 1
        },
        {
            question: "If the letter 'Q' appears 15% of the time in a ciphertext, it is most likely a substitute for:",
            options: ["Z", "Q", "E", "X"],
            correct: 2
        },
        {
            question: "Which scholar is credited with first describing frequency analysis (in the 9th century)?",
            options: ["Julius Caesar", "Claude Shannon", "Blaise de Vigenère", "Al-Kindi"],
            correct: 3
        },
        {
            question: "How many different keys exist for a general monoalphabetic substitution cipher over the 26-letter English alphabet?",
            options: ["26", "26 × 26 = 676", "26! (about 4 × 10²⁶)", "2²⁶"],
            correct: 2
        },
        {
            question: "In an English ciphertext that keeps its word spaces, a single-letter word is most likely to be:",
            options: ["E or T", "A or I", "O or U", "S or Z"],
            correct: 1
        },
        {
            question: "Why is a Caesar cipher easy to break even without frequency analysis?",
            options: [
                "It uses the same key as AES.",
                "It never changes the order of the letters.",
                "It has only 25 useful keys, so every shift can be tried (brute force).",
                "It always maps E to E."
            ],
            correct: 2
        },
        {
            question: "Why does a polyalphabetic cipher such as Vigenère resist simple letter-frequency analysis?",
            options: [
                "The same plaintext letter can become different ciphertext letters, flattening the frequency distribution.",
                "It removes all vowels from the message.",
                "It encrypts only the most frequent letters.",
                "It uses a different alphabet for every word length."
            ],
            correct: 0
        }
    ];

    function initQuiz() {
        const container = document.getElementById('quiz-container');
        container.innerHTML = '';

        quizData.forEach((q, index) => {
            const qDiv = document.createElement('div');
            qDiv.className = 'quiz-question';

            const qText = document.createElement('p');
            qText.innerHTML = `<span>${index + 1}.</span> ${q.question}`;
            qDiv.appendChild(qText);

            const optionsDiv = document.createElement('div');
            optionsDiv.className = 'quiz-options';

            q.options.forEach((opt, optIndex) => {
                const label = document.createElement('label');
                const radio = document.createElement('input');
                radio.type = 'radio';
                radio.name = `quiz-${index}`;
                radio.value = optIndex;

                const optionText = document.createElement('span');
                optionText.textContent = opt;

                label.appendChild(radio);
                label.appendChild(optionText);
                optionsDiv.appendChild(label);
            });

            qDiv.appendChild(optionsDiv);
            container.appendChild(qDiv);
        });

        document.getElementById('btn-submit-quiz').addEventListener('click', submitQuiz);
        document.getElementById('btn-retry-quiz').addEventListener('click', retryQuiz);
    }

    function submitQuiz() {
        let score = 0;
        let allAnswered = true;

        quizData.forEach((q, index) => {
            const selected = document.querySelector(`input[name="quiz-${index}"]:checked`);
            if (selected) {
                if (parseInt(selected.value) === q.correct) score++;
            } else {
                allAnswered = false;
            }
        });

        const resultBox = document.getElementById('quiz-result');

        if (!allAnswered) {
            resultBox.textContent = "Please answer all questions before submitting.";
            resultBox.className = 'alert-box info';
            resultBox.style.display = 'block';
            return;
        }

        resultBox.innerHTML = `You scored ${score} out of ${quizData.length}.<br>`;
        if (score === quizData.length) {
            resultBox.innerHTML += "Excellent! You understand the concepts perfectly.";
            resultBox.className = 'alert-box success';
        } else if (score >= Math.ceil(quizData.length * 0.7)) {
            resultBox.innerHTML += "Good work! Review the theory section for the ones you missed.";
            resultBox.className = 'alert-box success';
        } else {
            resultBox.innerHTML += "Review the theory section and try again.";
            resultBox.className = 'alert-box error';
        }
        resultBox.style.display = 'block';

        document.getElementById('btn-submit-quiz').style.display = 'none';
        document.getElementById('btn-retry-quiz').style.display = 'inline-block';

        // Disable inputs
        document.querySelectorAll('#quiz-container input[type="radio"]').forEach(r => r.disabled = true);
    }

    function retryQuiz() {
        document.querySelectorAll('#quiz-container input[type="radio"]').forEach(r => {
            r.checked = false;
            r.disabled = false;
        });

        const resultBox = document.getElementById('quiz-result');
        resultBox.style.display = 'none';
        resultBox.className = 'alert-box';
        document.getElementById('btn-submit-quiz').style.display = 'inline-block';
        document.getElementById('btn-retry-quiz').style.display = 'none';
    }

    // Start
    init();
});
