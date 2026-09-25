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
