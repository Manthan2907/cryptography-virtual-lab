document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnHash');
  const input = document.getElementById('hashInput');
  const output = document.getElementById('hashOutput');

  if (btn && input && output) {
    btn.addEventListener('click', () => {
      const msg = input.value;
      if (typeof CryptoJS !== 'undefined') {
        const sha256 = CryptoJS.SHA256(msg).toString();
        const md5 = CryptoJS.MD5(msg).toString();
        output.innerHTML = `
          <p><strong>SHA-256 (256-bit):</strong> <code>${sha256}</code></p>
          <p><strong>MD5 (128-bit):</strong> <code>${md5}</code></p>
          <p><strong>Input Length:</strong> ${msg.length} characters</p>
        `;
      } else {
        output.textContent = 'CryptoJS library loading...';
      }
    });
  }
});
