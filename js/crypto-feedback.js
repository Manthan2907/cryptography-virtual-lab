/**
 * Cryptography Virtual Lab - Secure Client-Side Feedback Encryption
 * Hybrid Encryption: RSA-OAEP (2048-bit) + AES-256-GCM
 */
const CryptoFeedback = (() => {
  const CONFIG = {
    SCRIPT_URL: 'https://script.google.com/macros/s/AKfycbzcFxNVRpN5jtzLBdkiaGVTY73KNXsSyla7GkVUz1OUIS89qWFrwljh9BXu5Letxdtj/exec',
    PUB_SPKI_B64: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh7CcRXjsVbiMrxBh12SWfKicLY2ZPG+siKnvOEDJsm/BDgwY1k7ITfeRGsAKjR6AIUAjSrebK4PbbsDZee4CduDuqZNlVi93Kk8isNsnOa+CAsEEP5g7HvCT/PZA/bSojLlJ8mpAx0LVXPThg6Nw2IcVa/EoFPpYfjOCFdYvyEAK2/TBDKwfLDBYNtAzYPFl1AMXNH5Ahaca2EC4235plEvETe3fNLFjSohcFYr91g7ZXPTn6nGizYdfPWjNkGOBxcnqZHboOjeKoyt6vYmcJ7zcLPm4f6ncZNFeuw2SvXhs6ctJeoB+WZKhZK+ftkTgHdKgcIyvlg4fZPLCnSiJsQIDAQAB'
  };

  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  let cachedPubKey = null;

  async function getPublicKey() {
    if (cachedPubKey) return cachedPubKey;
    const keyData = base64ToArrayBuffer(CONFIG.PUB_SPKI_B64);
    cachedPubKey = await window.crypto.subtle.importKey(
      'spki',
      keyData,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );
    return cachedPubKey;
  }

  /**
   * Encrypts arbitrary feedback object using Hybrid RSA-OAEP + AES-256-GCM.
   * Returns a base64-encoded encrypted payload string.
   */
  async function encrypt(feedbackData) {
    const enc = new TextEncoder();
    const plaintextBuffer = enc.encode(JSON.stringify(feedbackData));

    // 1. Generate ephemeral AES-256 key and 12-byte IV
    const aesKey = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // 2. Encrypt feedback with AES-GCM
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      plaintextBuffer
    );

    // 3. Export raw AES key and encrypt with Admin's RSA Public Key
    const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
    const rsaPubKey = await getPublicKey();
    const encKeyBuffer = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      rsaPubKey,
      rawAesKey
    );

    // 4. Compact payload object containing encrypted key, IV, and AES ciphertext
    const payload = {
      k: arrayBufferToBase64(encKeyBuffer),
      iv: arrayBufferToBase64(iv),
      c: arrayBufferToBase64(ciphertextBuffer)
    };

    return JSON.stringify(payload);
  }

  /**
   * Encrypts and sends feedback to the Google Apps Script backend.
   */
  async function submit(experimentId, feedbackData) {
    const payloadString = await encrypt(feedbackData);

    const body = JSON.stringify({
      experiment: experimentId,
      payload: payloadString
    });

    const response = await fetch(CONFIG.SCRIPT_URL, {
      method: 'POST',
      body: body,
      headers: {
        'Content-Type': 'text/plain;charset=utf-8'
      }
    });

    return response;
  }

  return {
    CONFIG,
    encrypt,
    submit,
    base64ToArrayBuffer,
    arrayBufferToBase64
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = CryptoFeedback;
}
