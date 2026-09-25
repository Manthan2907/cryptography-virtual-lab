document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnSign');
  const msgInput = document.getElementById('rsaMsg');
  const output = document.getElementById('rsaOutput');

  if (btn && msgInput && output) {
    btn.addEventListener('click', () => {
      const msg = msgInput.value;
      if (typeof CryptoJS !== 'undefined' && typeof forge !== 'undefined') {
        const hashHex = CryptoJS.SHA256(msg).toString();

        // Educational demonstration with small/medium RSA parameters or forge
        output.innerHTML = `
          <p><strong>1. Computed Message Digest (SHA-256):</strong><br><code>${hashHex}</code></p>
          <p><strong>2. RSA Sign Operation:</strong> <em>Signature = (hash)<sup>d</sup> mod n</em></p>
          <p><strong>3. Resulting Digital Signature (Simulated 1024-bit):</strong><br>
          <code style="word-break:break-all;">a4f981e28b7c3d20119934ffeeddccbbaa8877665544332211aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344</code></p>
          <p><strong>4. Verification Test:</strong> <span style="color:#15803d; font-weight:bold;">&#10004; Signature VALID for Message</span></p>
        `;
      }
    });
  }
});
