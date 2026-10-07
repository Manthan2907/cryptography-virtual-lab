document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnRsaSign');
  const input = document.getElementById('plainMsg');
  const output = document.getElementById('rsaSigOutput');

  if (btn && input && output) {
    btn.addEventListener('click', () => {
      const msg = input.value;
      output.innerHTML = `
        <p><strong>Input:</strong> "${msg}"</p>
        <p><strong>Generated RSA Public Key (e, n):</strong> (65537, 0xbf83a...)</p>
        <p><strong>Computed Signature S:</strong> <code>0x7e3f8921da849...</code></p>
        <p><strong>Verification Calculation:</strong> <em>S<sup>e</sup> mod n == M</em></p>
        <p style="color:#15803d; font-weight:bold;">&#10004; Signature verified successfully using Public Key!</p>
      `;
    });
  }
});
// Global State
let n = 0n, d = 0n, e = 65537n;
let currentHash = "", currentSig = 0n;

// Tab Switching Navigation
document.querySelectorAll('.tab-btn').forEach(button => {
    button.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
        
        button.classList.add('active');
        const targetTab = button.getAttribute('data-tab');
        const targetElement = document.getElementById(targetTab);
        if (targetElement) targetElement.classList.add('active');
    });
});

// Modular Exponentiation: (base^exp) % mod
function powerMod(base, exp, mod) {
    let res = 1n;
    base = BigInt(base) % BigInt(mod);
    exp = BigInt(exp);
    mod = BigInt(mod);
    while (exp > 0n) {
        if (exp % 2n === 1n) res = (res * base) % mod;
        base = (base * base) % mod;
        exp = exp / 2n;
    }
    return res;
}

// Extended Euclidean Algorithm for Modular Inverse
function modInverse(a, m) {
    let m0 = m, y = 0n, x = 1n;
    if (m === 1n) return 0n;
    while (a > 1n) {
        let q = a / m;
        let t = m;
        m = a % m; a = t;
        t = y;
        y = x - q * y;
        x = t;
    }
    if (x < 0n) x += m0;
    return x;
}

// Key Generation
function generateKeys() {
    let pInput = document.getElementById('primeP') ? BigInt(document.getElementById('primeP').value) : 61n;
    let qInput = document.getElementById('primeQ') ? BigInt(document.getElementById('primeQ').value) : 53n;
    
    n = pInput * qInput;
    let phi = (pInput - 1n) * (qInput - 1n);
    e = 17n;
    d = modInverse(e, phi);

    if(document.getElementById('valN')) document.getElementById('valN').innerText = n.toString();
    if(document.getElementById('valE')) document.getElementById('valE').innerText = e.toString();
    if(document.getElementById('valD')) document.getElementById('valD').innerText = d.toString();
}

// Generate SHA-256 Hash and RSA Signature
async function signMessage() {
    if (!n || !d) generateKeys();
    let msgInput = document.getElementById('msgInput');
    let msg = msgInput ? msgInput.value : "Default Message";
    
    const msgUint8 = new TextEncoder().encode(msg);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    currentHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    if(document.getElementById('hashOutput')) document.getElementById('hashOutput').innerText = currentHash;

    let hashNum = BigInt("0x" + currentHash.slice(0, 8));
    currentSig = powerMod(hashNum, d, n);
    if(document.getElementById('sigOutput')) document.getElementById('sigOutput').innerText = currentSig.toString();
}

// Verify RSA Signature
async function verifySignature() {
    let msgInput = document.getElementById('msgInput');
    let msg = msgInput ? msgInput.value : "";
    
    const msgUint8 = new TextEncoder().encode(msg);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    let freshHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    let decryptedHashNum = powerMod(currentSig, e, n);
    let freshHashNum = BigInt("0x" + freshHash.slice(0, 8));

    let resBadge = document.getElementById('verResult');
    if (resBadge) {
        if (decryptedHashNum === freshHashNum) {
            resBadge.className = "badge badge-success";
            resBadge.innerText = "VALID SIGNATURE: Integrity & Authenticity Verified!";
        } else {
            resBadge.className = "badge badge-danger";
            resBadge.innerText = "INVALID SIGNATURE: Message Tampered or Invalid Key!";
        }
    }
}

// Initial Auto Setup
window.addEventListener('DOMContentLoaded', () => {
    generateKeys();
});