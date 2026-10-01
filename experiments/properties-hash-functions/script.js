document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnAnalyze');
  const m1Input = document.getElementById('msg1');
  const m2Input = document.getElementById('msg2');
  const output = document.getElementById('propOutput');

  if (btn && m1Input && m2Input && output) {
    btn.addEventListener('click', () => {
      const text1 = m1Input.value;
      const text2 = m2Input.value;

      if (typeof CryptoJS !== 'undefined') {
        const hash1Hex = CryptoJS.SHA256(text1).toString();
        const hash2Hex = CryptoJS.SHA256(text2).toString();

        // Convert hex to binary strings
        let bin1 = '';
        let bin2 = '';
        let diffBits = 0;

        for (let i = 0; i < hash1Hex.length; i++) {
          const b1 = parseInt(hash1Hex[i], 16).toString(2).padStart(4, '0');
          const b2 = parseInt(hash2Hex[i], 16).toString(2).padStart(4, '0');
          bin1 += b1;
          bin2 += b2;
          for (let j = 0; j < 4; j++) {
            if (b1[j] !== b2[j]) diffBits++;
          }
        }

        const totalBits = bin1.length;
        const pct = ((diffBits / totalBits) * 100).toFixed(2);

        output.innerHTML = `
          <p><strong>Hash 1:</strong> <code>${hash1Hex}</code></p>
          <p><strong>Hash 2:</strong> <code>${hash2Hex}</code></p>
          <p><strong>Total Bits:</strong> ${totalBits} bits</p>
          <p><strong>Flipped Bits (Hamming Distance):</strong> ${diffBits} bits</p>
          <p><strong>Avalanche Percentage:</strong> <span style="font-size:1.1rem; color:#0265cb; font-weight:bold;">${pct}%</span> (Ideal target is ~50%)</p>
        `;
      }
    });
  }
});
