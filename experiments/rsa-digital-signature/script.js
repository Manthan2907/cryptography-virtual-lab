// Global State
let n = 0n;
let d = 0n;
let e = 17n;
let currentHash = "";
let currentSig = 0n;


// Modular Exponentiation
function powerMod(base, exp, mod) {
    let result = 1n;

    base = BigInt(base) % BigInt(mod);
    exp = BigInt(exp);
    mod = BigInt(mod);

    while (exp > 0n) {

        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }

        base = (base * base) % mod;
        exp = exp / 2n;
    }

    return result;
}


// Modular Inverse
function modInverse(a, m) {

    let m0 = m;
    let y = 0n;
    let x = 1n;

    if (m === 1n) {
        return 0n;
    }

    while (a > 1n) {

        let q = a / m;

        let t = m;
        m = a % m;
        a = t;

        t = y;
        y = x - q * y;
        x = t;
    }

    if (x < 0n) {
        x += m0;
    }

    return x;
}


// Generate RSA Keys
function generateKeys() {

    let p = 61n;
    let q = 53n;

    n = p * q;

    let phi = (p - 1n) * (q - 1n);

    e = 17n;

    d = modInverse(e, phi);
}


// SHA-256 Hash
async function getHash(message) {

    const data = new TextEncoder().encode(message);

    const hashBuffer =
        await crypto.subtle.digest(
            "SHA-256",
            data
        );

    const hashArray =
        Array.from(new Uint8Array(hashBuffer));

    return hashArray
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}


// Sign Message
async function signMessage() {

    if (n === 0n || d === 0n) {
        generateKeys();
    }

    const input =
        document.getElementById("plainMsg");

    const output =
        document.getElementById("rsaSigOutput");

    const msg = input.value;


    // Generate SHA-256 hash
    currentHash = await getHash(msg);


    // Convert first 8 hash characters to number
    const hashNum =
        BigInt("0x" + currentHash.slice(0, 8));


    // Generate RSA signature
    currentSig =
        powerMod(hashNum, d, n);


    // Verify signature
    const verifiedHash =
        powerMod(currentSig, e, n);

    const expectedHash =
        hashNum % n;


    const verified =
        verifiedHash === expectedHash;


    output.innerHTML = `

        <p>
            <strong>Input:</strong>
            "${msg}"
        </p>

        <p>
            <strong>Generated RSA Public Key (e, n):</strong>
            (${e}, ${n})
        </p>

        <p>
            <strong>SHA-256 Hash:</strong>
            <code>${currentHash}</code>
        </p>

        <p>
            <strong>Computed Signature S:</strong>
            <code>${currentSig}</code>
        </p>

        <p>
            <strong>Verification Calculation:</strong>
            S<sup>e</sup> mod n == Hash mod n
        </p>

        ${
            verified

            ? `
                <p style="color:#15803d; font-weight:bold;">
                    &#10004; Signature verified successfully using Public Key!
                </p>
              `

            : `
                <p style="color:#dc2626; font-weight:bold;">
                    &#10008; Signature verification failed!
                </p>
              `
        }

    `;
}


// Tamper Test
async function runTamperTest() {

    if (n === 0n || d === 0n) {
        generateKeys();
    }

    const input =
        document.getElementById("plainMsg");

    const output =
        document.getElementById("rsaSigOutput");

    const originalMessage =
        input.value;


    // Hash original message
    const originalHash =
        await getHash(originalMessage);


    const originalHashNum =
        BigInt(
            "0x" + originalHash.slice(0, 8)
        );


    // Create signature
    const signature =
        powerMod(
            originalHashNum,
            d,
            n
        );


    // Change message
    const tamperedMessage =
        originalMessage + " (TAMPERED)";


    // Hash tampered message
    const tamperedHash =
        await getHash(tamperedMessage);


    const tamperedHashNum =
        BigInt(
            "0x" + tamperedHash.slice(0, 8)
        );


    // Verify old signature against new message
    const decryptedSignature =
        powerMod(
            signature,
            e,
            n
        );


    const valid =
        decryptedSignature ===
        (tamperedHashNum % n);


    output.innerHTML = `

        <p>
            <strong>Original Message:</strong>
            "${originalMessage}"
        </p>

        <p>
            <strong>Tampered Message:</strong>
            "${tamperedMessage}"
        </p>

        <p>
            <strong>Original Signature:</strong>
            <code>${signature}</code>
        </p>

        ${
            valid

            ? `
                <p style="color:#dc2626; font-weight:bold;">
                    &#10008; Tampering was NOT detected.
                </p>
              `

            : `
                <p style="color:#dc2626; font-weight:bold;">
                    &#10008; Signature verification failed.
                    Message has been tampered!
                </p>
              `
        }

    `;
}


// Tab Switching
document
    .querySelectorAll(".tab-btn")
    .forEach(button => {

        button.addEventListener(
            "click",
            () => {

                document
                    .querySelectorAll(".tab-btn")
                    .forEach(btn =>
                        btn.classList.remove("active")
                    );


                document
                    .querySelectorAll(".tab-content")
                    .forEach(tab =>
                        tab.classList.remove("active")
                    );


                button.classList.add("active");


                const target =
                    document.getElementById(
                        button.getAttribute("data-tab")
                    );


                if (target) {
                    target.classList.add("active");
                }

            }
        );

    });


// Button Events
document.addEventListener(
    "DOMContentLoaded",
    () => {

        generateKeys();


        const signButton =
            document.getElementById("btnRsaSign");


        const tamperButton =
            document.getElementById("btnTamperTest");


        if (signButton) {

            signButton.addEventListener(
                "click",
                signMessage
            );

        }


        if (tamperButton) {

            tamperButton.addEventListener(
                "click",
                runTamperTest
            );

        }

    }
);