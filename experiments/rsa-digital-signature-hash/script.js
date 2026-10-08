/*
 * ============================================================
 * RSA DIGITAL SIGNATURE WITH SHA-256
 * ============================================================
 *
 * Simulation flow:
 *
 * 1. Explore SHA-256
 * 2. Enter (or generate) the sender's public key (n, e) and
 *    private key d, then create an RSA signature from the hash
 * 3. Verify the signature using the sender's public key
 * 4. Tampering: compare hashes and signatures, and verify the
 *    ORIGINAL signature against the MODIFIED message
 *
 * Signing:       s  = EM^d mod n
 * Verification:  EM' = s^e mod n
 * where EM is the SHA-256 digest with standard PKCS#1 v1.5 padding.
 * ============================================================
 */


document.addEventListener("DOMContentLoaded", () => {


  // ==========================================================
  // ELEMENTS
  // ==========================================================


  // SHA playground

  const shaMessage = document.getElementById("shaMessage");
  const btnHash = document.getElementById("btnHash");
  const btnClearHash = document.getElementById("btnClearHash");
  const hashOutput = document.getElementById("hashOutput");
  const hashBits = document.getElementById("hashBits");
  const hashLength = document.getElementById("hashLength");
  const visualMessage = document.getElementById("visualMessage");
  const visualHash = document.getElementById("visualHash");


  // Sender key inputs / outputs

  const keyN = document.getElementById("keyN");
  const keyE = document.getElementById("keyE");
  const keyD = document.getElementById("keyD");
  const btnComputeKeys = document.getElementById("btnComputeKeys");
  const btnGenKeys = document.getElementById("btnGenKeys");
  const keyStatus = document.getElementById("keyStatus");
  const keyPhiDisplay = document.getElementById("keyPhiDisplay"); // shows modulus size
  const keyPublicDisplay = document.getElementById("keyPublicDisplay");
  const keyPrivateDisplay = document.getElementById("keyPrivateDisplay");


  // RSA signing

  const btnSign = document.getElementById("btnSign");
  const signHashDisplay = document.getElementById("signHashDisplay");
  const sigHex = document.getElementById("sigHex");
  const sigBase64 = document.getElementById("sigBase64");
  const sigStatus = document.getElementById("sigStatus");


  // Verification

  const verifyMsg = document.getElementById("verifyMsg");
  const verifyN = document.getElementById("verifyN");
  const verifyE = document.getElementById("verifyE");
  const btnVerify = document.getElementById("btnVerify");
  const verifyHashComputed = document.getElementById("verifyHashComputed");
  const verifyRecoveredHash = document.getElementById("verifyRecoveredHash");
  const verifyResult = document.getElementById("verifyResult");


  // Tampering

  const tamperOriginal = document.getElementById("tamperOriginal");
  const tamperModified = document.getElementById("tamperModified");
  const tamperOriginalHash = document.getElementById("tamperOriginalHash");
  const tamperModifiedHash = document.getElementById("tamperModifiedHash");
  const tamperOriginalSig = document.getElementById("tamperOriginalSig");
  const tamperModifiedSig = document.getElementById("tamperModifiedSig");
  const tamperHashCompare = document.getElementById("tamperHashCompare");
  const tamperSigCompare = document.getElementById("tamperSigCompare");
  const tamperVerifyComputed = document.getElementById("tamperVerifyComputed");
  const tamperVerifyRecovered = document.getElementById("tamperVerifyRecovered");
  const tamperVerifyResult = document.getElementById("tamperVerifyResult");
  const btnTamper = document.getElementById("btnTamper");
  const btnResetTamper = document.getElementById("btnResetTamper");
  const tamperResult = document.getElementById("tamperResult");


  // Summary

  const summaryMsg = document.getElementById("summaryMsg");
  const summaryAlgo = document.getElementById("summaryAlgo");
  const summaryHash = document.getElementById("summaryHash");
  const summarySigStatus = document.getElementById("summarySigStatus");
  const summaryVerifyStatus = document.getElementById("summaryVerifyStatus");


  // Quiz

  const quizForm = document.getElementById("quizForm");
  const quizResult = document.getElementById("quizResult");


  // ==========================================================
  // CHECK LIBRARIES
  // ==========================================================


  if (typeof CryptoJS === "undefined") {
    console.error("CryptoJS library is not loaded.");
    return;
  }

  if (typeof forge === "undefined") {
    console.error("Forge library is not loaded.");
    return;
  }


  // ==========================================================
  // VARIABLES
  // ==========================================================


  const BigInteger = forge.jsbn.BigInteger;

  // SHA-256 DigestInfo prefix (PKCS#1 v1.5)
  const SHA256_PREFIX = "3031300d060960864801650304020105000420";

  // Sender's keys, entered by the user
  let senderKeys = null;

  let currentSignatureHex = "";
  let currentSignatureBase64 = "";
  let currentHashHex = "";

  // The message and keys that the current signature was created with
  // (used by the tampering simulation)
  let signedMessage = null;
  let signedKeys = null;


  // ==========================================================
  // HELP BUTTONS
  // ==========================================================

  const helpTargets = {
    "sha-message": "shaMessageHelp",
    "sha-result": "shaResultHelp",
    "keys": "keyHelp",
    "rsa-sign": "rsaSignHelp",
    "verification": "verificationHelp",
    "tampering": "tamperHelp"
  };

  document.querySelectorAll("[data-help]").forEach((button) => {

    button.addEventListener("click", () => {

      const targetId = helpTargets[button.getAttribute("data-help")];

      if (!targetId) {
        return;
      }

      const target = document.getElementById(targetId);

      if (target) {
        target.classList.toggle("show");
      }

    });

  });


  // ==========================================================
  // SHA-256 FUNCTION
  // ==========================================================


  function calculateSHA256(message) {

    return CryptoJS
      .SHA256(message)
      .toString(CryptoJS.enc.Hex);

  }


  // ==========================================================
  // HELPERS
  // ==========================================================


  function bigToHex(big) {

    let hex = big.toString(16);

    if (hex.length % 2) {
      hex = "0" + hex;
    }

    return hex;

  }

  function padHex(hex, byteLength) {

    while (hex.length < byteLength * 2) {
      hex = "0" + hex;
    }

    return hex;

  }

  function hexToBase64(hex) {
    return forge.util.encode64(forge.util.hexToBytes(hex));
  }

  /*
   * Reads a positive integer typed by the user.
   * Accepts decimal ("65537") or hexadecimal ("0x10001").
   * Returns null if the text is not a valid number.
   */

  function parseNumber(text) {

    const clean = (text || "").replace(/\s+/g, "");

    if (!clean) {
      return null;
    }

    try {

      if (/^0x[0-9a-f]+$/i.test(clean)) {
        return new BigInteger(clean.slice(2), 16);
      }

      if (/^[0-9]+$/.test(clean)) {
        return new BigInteger(clean, 10);
      }

    }

    catch (error) {
      return null;
    }

    return null;

  }

  /*
   * PKCS#1 v1.5 encoding of a SHA-256 digest:
   * 00 01 FF..FF 00 || DigestInfo || hash   (k bytes long)
   * Returns null if the modulus is too small.
   */

  function encodeDigest(hashHex, k) {

    const t = SHA256_PREFIX + hashHex;

    const psLen = k - (t.length / 2) - 3;

    if (psLen < 8) {
      return null;
    }

    return "0001" + "ff".repeat(psLen) + "00" + t;

  }

  /*
   * RSA signing of a message:  s = EM^d mod n
   * Returns the signature as a hex string (k bytes long).
   * Used by the tampering demonstration.
   */

  function signMessage(message, keys) {

    const k = Math.ceil(keys.n.bitLength() / 8);

    const encoded = encodeDigest(calculateSHA256(message), k);

    if (!encoded) {
      throw new Error("Modulus too small for SHA-256 signature.");
    }

    const em = new BigInteger(encoded, 16);

    return padHex(bigToHex(em.modPow(keys.d, keys.n)), k);

  }

  /*
   * Real RSA verification of a signature against a message:
   *   EM' = s^e mod n, then compare with the expected padded
   *   block for SHA-256(message).
   * Returns { valid, computedHash, recoveredHash }.
   */

  function verifySignature(signatureHex, message, n, e) {

    const computedHash = calculateSHA256(message);

    let valid = false;

    let recoveredHash = "";

    try {

      const k = Math.ceil(n.bitLength() / 8);

      const s = new BigInteger(signatureHex, 16);

      const recoveredHex = padHex(bigToHex(s.modPow(e, n)), k);

      const prefixIndex = recoveredHex.indexOf(SHA256_PREFIX);

      if (prefixIndex !== -1) {

        const digestStart = prefixIndex + SHA256_PREFIX.length;

        recoveredHash = recoveredHex.substring(digestStart, digestStart + 64);

      }

      const expected = encodeDigest(computedHash, k);

      valid = (expected !== null && expected === recoveredHex);

    }

    catch (error) {
      valid = false;
    }

    return { valid, computedHash, recoveredHash };

  }


  // ==========================================================
  // TAMPERING DISPLAY HELPERS
  // ==========================================================


  /*
   * Clears the comparison and verification results in the
   * tampering section (the messages themselves are kept).
   */

  function resetTamperOutputs() {

    tamperModifiedHash.textContent = "Click \"Compare Hashes & Signatures\"";

    tamperModifiedSig.textContent = "Click \"Compare Hashes & Signatures\"";

    tamperHashCompare.textContent = "Not compared yet.";

    tamperSigCompare.textContent = "Not compared yet.";

    tamperVerifyComputed.textContent = "Waiting...";

    tamperVerifyRecovered.textContent = "Waiting...";

    tamperVerifyResult.className = "status-card status-neutral";

    tamperVerifyResult.textContent =
      "Verification of the original signature has not been performed yet.";

    tamperResult.className = "tamper-result status-neutral";

    tamperResult.textContent =
      "Modify the message and compare the hashes and signatures.";

  }

  /*
   * Shows the original message, its hash and its signature in the
   * tampering section. If a signature exists, the message that was
   * actually signed is used; otherwise the current SHA-256 message.
   */

  function refreshTamperOriginal() {

    if (currentSignatureHex && signedMessage !== null) {

      tamperOriginal.value = signedMessage;

      tamperOriginalHash.textContent = calculateSHA256(signedMessage);

      tamperOriginalSig.textContent = currentSignatureHex;

    }

    else {

      tamperOriginal.value = shaMessage.value;

      tamperOriginalHash.textContent = shaMessage.value.trim()
        ? calculateSHA256(shaMessage.value)
        : "Generate the original hash first.";

      tamperOriginalSig.textContent =
        "Create the RSA signature first (section 2).";

    }

  }


  // ==========================================================
  // DISPLAY SHA-256
  // ==========================================================


  function displayHash(message, hash) {

    hashOutput.textContent = hash;

    hashBits.textContent = "256 bits";

    hashLength.textContent = hash.length;

    visualMessage.textContent = message;

    visualHash.textContent = hash;

    summaryMsg.textContent = message;

    summaryAlgo.textContent = "SHA-256";

    summaryHash.textContent = hash;

    signHashDisplay.textContent = hash;


    // Keep tampering original message synchronized

    refreshTamperOriginal();


    // Reset modified message to a simple changed version

    const base = tamperOriginal.value;

    tamperModified.value = base.replace("1000", "5000");

    if (tamperModified.value === base) {
      tamperModified.value = base + " changed";
    }

    resetTamperOutputs();

  }


  // ==========================================================
  // SHA-256 BUTTON
  // ==========================================================


  btnHash.addEventListener("click", () => {

    const message = shaMessage.value;

    if (!message.trim()) {
      alert("Please enter a message.");
      return;
    }

    currentHashHex = calculateSHA256(message);

    displayHash(message, currentHashHex);


    // Reset RSA-related status because the message may have changed

    summarySigStatus.textContent = "Not generated for this message";

    summaryVerifyStatus.textContent = "Not performed";

    sigStatus.textContent = "Generate a signature for this message.";

    verifyResult.className = "status-card status-neutral";

    verifyResult.textContent = "Generate a signature before verification.";

    console.log("SHA-256:", currentHashHex);

  });


  // ==========================================================
  // CLEAR HASH
  // ==========================================================


  btnClearHash.addEventListener("click", () => {

    shaMessage.value = "";

    hashOutput.textContent = "Enter a message and generate the hash.";

    hashBits.textContent = "256 bits";

    hashLength.textContent = "64";

    visualMessage.textContent = "Waiting...";

    visualHash.textContent = "Waiting...";

    currentHashHex = "";

    signHashDisplay.textContent = "Generate a SHA-256 hash first.";

    sigHex.textContent = "Waiting for signature...";

    sigBase64.textContent = "Waiting for signature...";

    sigStatus.textContent = "Waiting...";

    verifyHashComputed.textContent = "Waiting...";

    verifyRecoveredHash.textContent = "Waiting...";

    verifyResult.className = "status-card status-neutral";

    verifyResult.textContent = "Verification has not been performed.";

  });


  // ==========================================================
  // SENDER'S RSA KEYS (USER INPUT)
  // ==========================================================


  function setKeyStatus(type, html) {

    keyStatus.className = "status-card status-" + type;

    keyStatus.innerHTML = html;

  }

  function clearSignatureDisplay() {

    currentSignatureHex = "";

    currentSignatureBase64 = "";

    signedMessage = null;

    signedKeys = null;

    sigHex.textContent = "Waiting for signature...";

    sigBase64.textContent = "Waiting for signature...";

    sigStatus.textContent = "Waiting...";

    summarySigStatus.textContent = "Not generated";

    summaryVerifyStatus.textContent = "Not performed";

    verifyHashComputed.textContent = "Waiting...";

    verifyRecoveredHash.textContent = "Waiting...";

    verifyResult.className = "status-card status-neutral";

    verifyResult.textContent = "Verification has not been performed yet.";

    // The earlier signature no longer exists, so reset tampering too

    refreshTamperOriginal();

    resetTamperOutputs();

  }


  /*
   * Reads n, e and d typed by the user and checks that they
   * form a working RSA key pair. Returns the key object, or
   * null if the input is invalid (the reason is shown).
   */

  function loadKeys() {

    const ONE = BigInteger.ONE;

    const n = parseNumber(keyN.value);
    const e = parseNumber(keyE.value);
    const d = parseNumber(keyD.value);

    if (!n || !e || !d) {

      setKeyStatus(
        "invalid",
        "<strong>✗ Invalid input</strong><p style=\"margin:8px 0 0;\">" +
        "Enter valid positive numbers for n, e and d " +
        "(decimal, or hexadecimal starting with 0x).</p>"
      );

      return null;

    }

    if (n.bitLength() < 512) {

      setKeyStatus(
        "invalid",
        "<strong>✗ Modulus n is too small</strong>" +
        "<p style=\"margin:8px 0 0;\">n has " + n.bitLength() +
        " bits. A SHA-256 digest with PKCS#1 padding needs n of at " +
        "least 512 bits. Click \"Generate Random Key\" if unsure.</p>"
      );

      return null;

    }

    if (e.compareTo(ONE) <= 0 || e.compareTo(n) >= 0) {

      setKeyStatus("invalid", "<strong>✗ e must satisfy 1 &lt; e &lt; n.</strong>");

      return null;

    }

    if (d.compareTo(ONE) <= 0 || d.compareTo(n) >= 0) {

      setKeyStatus("invalid", "<strong>✗ d must satisfy 1 &lt; d &lt; n.</strong>");

      return null;

    }


    /*
     * Check that d really is the private key for (n, e):
     * signing and then verifying a test number must return
     * the same number.
     */

    const tests = ["123456789", "987654321987654321"];

    for (const t of tests) {

      const m = new BigInteger(t, 10);

      if (!m.modPow(e, n).modPow(d, n).equals(m)) {

        setKeyStatus(
          "invalid",
          "<strong>✗ Keys do not match</strong>" +
          "<p style=\"margin:8px 0 0;\">The private key d does not belong " +
          "to the public key (n, e). Check your values, or click " +
          "\"Generate Random Key\" to get a matching set.</p>"
        );

        return null;

      }

    }


    // If the key changed, any earlier signature no longer belongs to it

    if (
      senderKeys &&
      (!senderKeys.n.equals(n) || !senderKeys.d.equals(d))
    ) {
      clearSignatureDisplay();
    }

    senderKeys = { n, e, d };


    keyPhiDisplay.textContent = n.bitLength() + " bits";

    keyPublicDisplay.textContent =
      "n = 0x" + bigToHex(n) + "\ne = " + e.toString(10);

    keyPrivateDisplay.textContent = "d = 0x" + bigToHex(d);


    // The public key is shared with the receiver for verification

    verifyN.value = "0x" + bigToHex(n);

    verifyE.value = e.toString(10);


    setKeyStatus(
      "valid",
      "<strong>✓ Key pair accepted</strong><p style=\"margin:8px 0 0;\">" +
      "Modulus size: " + n.bitLength() + " bits. " +
      "The public key (n, e) and private key d match.</p>"
    );

    console.log("RSA n:", "0x" + bigToHex(n));
    console.log("RSA e:", e.toString(10));
    console.log("RSA d:", "0x" + bigToHex(d));

    return senderKeys;

  }


  btnComputeKeys.addEventListener("click", () => {
    loadKeys();
  });


  // Generate a random key pair and fill the n, e and d fields

  function generateRandomKey() {

    setKeyStatus(
      "neutral",
      "Generating a random 1024-bit RSA key pair. Please wait..."
    );

    // Small delay so the status message appears before the work starts

    setTimeout(() => {

      try {

        const generated = forge.pki.rsa.generateKeyPair({
          bits: 1024,
          e: 65537
        });

        keyN.value = "0x" + bigToHex(generated.privateKey.n);

        keyE.value = "65537";

        keyD.value = "0x" + bigToHex(generated.privateKey.d);

        loadKeys();

      }

      catch (error) {

        console.error("RSA key generation failed:", error);

        setKeyStatus("invalid", "<strong>✗ Key generation failed.</strong>");

      }

    }, 50);

  }


  btnGenKeys.addEventListener("click", generateRandomKey);


  // ==========================================================
  // RSA SIGNATURE
  // ==========================================================


  btnSign.addEventListener("click", () => {

    const message = shaMessage.value;

    if (!message.trim()) {
      alert("Enter a message and generate its SHA-256 hash first.");
      return;
    }


    // Read and validate the sender's keys

    const keys = loadKeys();

    if (!keys) {

      sigStatus.textContent =
        "Enter a valid sender key pair (n, e, d) first.";

      summarySigStatus.textContent = "Not generated";

      return;

    }


    // Recalculate the hash for the current message

    currentHashHex = calculateSHA256(message);

    displayHash(message, currentHashHex);

    sigStatus.textContent = "Generating RSA signature...";

    summarySigStatus.textContent = "Generating...";


    try {

      const k = Math.ceil(keys.n.bitLength() / 8);

      const encoded = encodeDigest(currentHashHex, k);

      if (!encoded) {
        throw new Error("Modulus too small for SHA-256 signature.");
      }

      // Signature generation:  s = EM^d mod n

      const em = new BigInteger(encoded, 16);

      const s = em.modPow(keys.d, keys.n);

      currentSignatureHex = padHex(bigToHex(s), k);

      currentSignatureBase64 = hexToBase64(currentSignatureHex);

    }

    catch (error) {

      console.error("RSA signing failed:", error);

      sigStatus.textContent = "Signature generation failed.";

      summarySigStatus.textContent = "Failed";

      return;

    }


    // Remember what was signed (for the tampering simulation)

    signedMessage = message;

    signedKeys = { n: keys.n, e: keys.e, d: keys.d };


    // Display signature

    sigHex.textContent = currentSignatureHex;

    sigBase64.textContent = currentSignatureBase64;

    sigStatus.textContent = "✓ RSA signature created successfully.";

    summarySigStatus.textContent = "Generated successfully";


    // Show the original message, hash and signature in the tampering section

    refreshTamperOriginal();


    // Put the original message into the verification section

    verifyMsg.value = message;


    // Reset verification display

    verifyHashComputed.textContent = "Click Verify Signature";

    verifyRecoveredHash.textContent = "Click Verify Signature";

    verifyResult.className = "status-card status-neutral";

    verifyResult.textContent = "Signature created. You can now verify it.";

    summaryVerifyStatus.textContent = "Not performed";

    console.log("SHA-256:", currentHashHex);
    console.log("Signature Hex:", currentSignatureHex);
    console.log("Signature Base64:", currentSignatureBase64);

  });


  // ==========================================================
  // VERIFY SIGNATURE
  // ==========================================================


  btnVerify.addEventListener("click", () => {

    // A signature must exist first

    if (!currentSignatureHex) {

      verifyResult.className = "status-card status-invalid";

      verifyResult.textContent = "Create the RSA signature first.";

      return;

    }


    const message = verifyMsg.value;

    if (!message.trim()) {
      alert("Enter a message for verification.");
      return;
    }


    // Sender's public key (n, e) entered for verification

    const nPub = parseNumber(verifyN.value);
    const ePub = parseNumber(verifyE.value);

    if (!nPub || !ePub) {

      verifyResult.className = "status-card status-invalid";

      verifyResult.textContent =
        "Enter the sender's public key (n and e) as valid numbers " +
        "(decimal, or hexadecimal starting with 0x).";

      return;

    }


    // STEP 1: SHA-256 of the received message

    const computedHash = calculateSHA256(message);

    verifyHashComputed.textContent = computedHash;


    // STEP 2: recover the digest from the signature:  EM' = s^e mod n

    let signatureValid = false;

    let recoveredHash = "";

    try {

      const k = Math.ceil(nPub.bitLength() / 8);

      const s = new BigInteger(currentSignatureHex, 16);

      const recovered = s.modPow(ePub, nPub);

      const recoveredHex = padHex(bigToHex(recovered), k);

      // Extract the digest from the recovered block

      const prefixIndex = recoveredHex.indexOf(SHA256_PREFIX);

      if (prefixIndex !== -1) {

        const digestStart = prefixIndex + SHA256_PREFIX.length;

        recoveredHash = recoveredHex.substring(digestStart, digestStart + 64);

      }

      // STEP 3: compare with the expected block for this message

      const expected = encodeDigest(computedHash, k);

      signatureValid = (expected !== null && expected === recoveredHex);

    }

    catch (error) {

      console.error("Verification failed:", error);

      signatureValid = false;

    }


    if (recoveredHash) {
      verifyRecoveredHash.textContent = recoveredHash;
    }

    else {
      verifyRecoveredHash.textContent = "Could not recover a valid digest with this public key";
    }


    // FINAL RESULT

    if (signatureValid) {

      verifyResult.className = "status-card status-valid";

      verifyResult.innerHTML = `

        <strong>
          ✓ Signature VALID
        </strong>

        <p style="margin:8px 0 0;">
          The SHA-256 hash of the verification message
          matches the digest recovered from the RSA signature.
        </p>

        <p style="margin:8px 0 0;">
          Message integrity check:
          <strong>PASS</strong>
        </p>

      `;

      summaryVerifyStatus.textContent = "VALID";

    }

    else {

      verifyResult.className = "status-card status-invalid";

      verifyResult.innerHTML = `

        <strong>
          ✗ Signature INVALID
        </strong>

        <p style="margin:8px 0 0;">
          The message does not match the original
          signed message, or the public key does not
          match the sender's private key.
        </p>

        <p style="margin:8px 0 0;">
          The SHA-256 digest has changed or the
          signature is not valid for this message.
        </p>

      `;

      summaryVerifyStatus.textContent = "INVALID";

    }

    console.log("Verification message:", message);
    console.log("Computed SHA-256:", computedHash);
    console.log("Recovered digest:", recoveredHash);
    console.log("RSA verification:", signatureValid);

  });


  // ==========================================================
  // TAMPERING SIMULATION
  // ==========================================================


  btnTamper.addEventListener("click", () => {

    // A signature must exist: the original signature is needed

    if (!currentSignatureHex || signedMessage === null || !signedKeys) {

      tamperResult.className = "tamper-result status-invalid";

      tamperResult.innerHTML = `

        <strong>
          Create the RSA signature first
        </strong>

        <p>
          Go to section 2 and click "Create RSA Digital Signature".
          The tampering simulation needs an original signature.
        </p>

      `;

      return;

    }

    const original = signedMessage;

    const modified = tamperModified.value;

    if (!modified.trim()) {
      alert("Enter a modified message.");
      return;
    }


    // 1. SHA-256 of both messages

    const originalHash = calculateSHA256(original);

    const modifiedHash = calculateSHA256(modified);

    tamperOriginal.value = original;

    tamperOriginalHash.textContent = originalHash;

    tamperModifiedHash.textContent = modifiedHash;

    const hashesMatch = (originalHash === modifiedHash);


    // 2. Original signature, and the signature that WOULD be
    //    generated for the modified message (demonstration only)

    const originalSig = currentSignatureHex;

    let modifiedSig = "";

    try {
      modifiedSig = signMessage(modified, signedKeys);
    }

    catch (error) {

      console.error("Demonstration signing failed:", error);

      tamperResult.className = "tamper-result status-invalid";

      tamperResult.textContent = "Could not generate the demonstration signature.";

      return;

    }

    tamperOriginalSig.textContent = originalSig;

    tamperModifiedSig.textContent = modifiedSig;

    const sigsMatch = (originalSig === modifiedSig);


    // 3. Compare hashes and signatures

    tamperHashCompare.innerHTML = hashesMatch
      ? "<strong>✓ Identical</strong> &mdash; both messages have the same SHA-256 hash."
      : "<strong>✗ Different</strong> &mdash; the two messages have different SHA-256 hashes.";

    tamperSigCompare.innerHTML = sigsMatch
      ? "<strong>✓ Identical</strong> &mdash; both messages produce the same RSA signature."
      : "<strong>✗ Different</strong> &mdash; the modified message would produce a different RSA signature.";


    // 4. REAL verification: ORIGINAL signature against the MODIFIED
    //    message, using the sender's public key (n, e)

    const check = verifySignature(
      originalSig,
      modified,
      signedKeys.n,
      signedKeys.e
    );

    tamperVerifyComputed.textContent = check.computedHash;

    tamperVerifyRecovered.textContent =
      check.recoveredHash || "Could not recover a valid digest";

    if (check.valid) {

      tamperVerifyResult.className = "status-card status-valid";

      tamperVerifyResult.innerHTML = `

        <strong>
          ✓ Signature VALID
        </strong>

        <p style="margin:8px 0 0;">
          The original signature matches this message.
        </p>

      `;

    }

    else {

      tamperVerifyResult.className = "status-card status-invalid";

      tamperVerifyResult.innerHTML = `

        <strong>
          ✗ Signature INVALID
        </strong>

        <p style="margin:8px 0 0;">
          The digest recovered from the original signature does not
          match the SHA-256 hash of the modified message.
        </p>

      `;

    }


    // 5. Final conclusion

    if (check.valid && hashesMatch) {

      tamperResult.className = "tamper-result status-valid";

      tamperResult.innerHTML = `

        <strong>
          ✓ No Tampering Detected
        </strong>

        <p>
          The modified message is identical to the original, so the
          original signature is still valid.
        </p>

      `;

    }

    else {

      tamperResult.className = "tamper-result status-invalid";

      tamperResult.innerHTML = `

        <strong>
          ✗ TAMPERING DETECTED
        </strong>

        <p>
          The message was changed, so its SHA-256 hash and RSA signature
          are different. The original signature is
          <strong>INVALID</strong> for the modified message.
        </p>

        <p>
          This demonstrates the
          <strong>avalanche effect</strong> and shows how a digital
          signature protects message integrity.
        </p>

      `;

    }

    console.log("Original:", original);
    console.log("Original SHA-256:", originalHash);
    console.log("Modified:", modified);
    console.log("Modified SHA-256:", modifiedHash);
    console.log("Original signature:", originalSig);
    console.log("Modified signature (demo):", modifiedSig);
    console.log("Original signature vs modified message:", check.valid);

  });


  // ==========================================================
  // RESET TAMPERING
  // ==========================================================


  btnResetTamper.addEventListener("click", () => {

    const original = tamperOriginal.value;

    tamperModified.value = original;

    resetTamperOutputs();

  });


  // ==========================================================
  // MCQ QUIZ (10 QUESTIONS)
  // ==========================================================


  quizForm.addEventListener("submit", (event) => {

    event.preventDefault();

    const correctAnswers = {
      q1: "b",
      q2: "c",
      q3: "a",
      q4: "b",
      q5: "a",
      q6: "b",
      q7: "b",
      q8: "a",
      q9: "a",
      q10: "c"
    };

    const explanations = {

      q1: "SHA-256 converts an input message into a fixed-size hash value.",

      q2: "SHA-256 produces a 256-bit digest.",

      q3: "A cryptographic hash is commonly compared to a digital fingerprint of the input.",

      q4: "A small change in the input causes a significantly different SHA-256 output.",

      q5: "The avalanche effect causes small input changes to produce large changes in the hash.",

      q6: "Hashing helps detect modification because a changed message produces a different digest.",

      q7: "The same input to SHA-256 produces the same hash output.",

      q8: "In hash-then-sign, SHA-256 first produces the digest that is then used in the signing process.",

      q9: "The sender signs with their own private key, so only the sender can create the signature.",

      q10: "Anyone can verify a signature using the sender's public key, which is shared openly."

    };

    const total = Object.keys(correctAnswers).length;

    let score = 0;

    let review = [];

    Object.keys(correctAnswers).forEach((question) => {

      const selected = quizForm.querySelector(
        `input[name="${question}"]:checked`
      );

      if (selected && selected.value === correctAnswers[question]) {
        score++;
        return;
      }

      review.push(`

        <li>
          <strong>${question.toUpperCase()}:</strong>
          ${explanations[question]}
        </li>

      `);

    });

    let resultHTML = `

      <h3>
        Score: ${score} / ${total}
      </h3>

    `;

    if (score === total) {

      resultHTML += `

        <p>
          Excellent! You have a strong understanding of SHA-256
          and its role in digital signatures.
        </p>

      `;

    }

    else if (score >= 8) {

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
          <strong>Review:</strong>
        </p>

        <ul>
          ${review.join("")}
        </ul>

      `;

    }

    quizResult.innerHTML = resultHTML;

  });


  // ==========================================================
  // INITIAL STATE
  // ==========================================================


  summaryAlgo.textContent = "SHA-256";

  summaryVerifyStatus.textContent = "Not performed";

  summarySigStatus.textContent = "Not generated";


  // Generate an initial SHA-256 hash so the user sees a working example

  const initialMessage = shaMessage.value;

  if (initialMessage.trim()) {

    currentHashHex = calculateSHA256(initialMessage);

    displayHash(initialMessage, currentHashHex);

  }


  /*
   * Pre-fill the key fields with a random key pair so the
   * simulation works immediately. The user can overwrite n, e
   * and d with their own values at any time.
   */

  generateRandomKey();


});