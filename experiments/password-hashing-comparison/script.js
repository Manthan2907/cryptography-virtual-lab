document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnBenchmark');
  const pwdInput = document.getElementById('cmpPassword');
  const output = document.getElementById('cmpOutput');

  if (btn && pwdInput && output) {
    btn.addEventListener('click', () => {
      const pwd = pwdInput.value;
      if (typeof CryptoJS !== 'undefined') {
        const t0 = performance.now();
        const md5 = CryptoJS.MD5(pwd).toString();
        const tMd5 = (performance.now() - t0).toFixed(3);

        const t1 = performance.now();
        const sha256 = CryptoJS.SHA256(pwd).toString();
        const tSha256 = (performance.now() - t1).toFixed(3);

        let bcryptHash = 'Calculating...';
        let tBcrypt = 'N/A';
        if (typeof dcodeIO !== 'undefined' && dcodeIO.bcrypt) {
          const t2 = performance.now();
          const salt = dcodeIO.bcrypt.genSaltSync(8);
          bcryptHash = dcodeIO.bcrypt.hashSync(pwd, salt);
          tBcrypt = (performance.now() - t2).toFixed(1);
        }

        output.innerHTML = `
          <table style="width:100%; border-collapse:collapse; margin-top:10px;">
            <thead>
              <tr style="background:#e8d5c4; text-align:left;">
                <th style="padding:8px;">Algorithm</th>
                <th style="padding:8px;">Sample Output</th>
                <th style="padding:8px;">Time (ms)</th>
                <th style="padding:8px;">Password Defense Rating</th>
              </tr>
            </thead>
            <tbody>
              <tr style="border-bottom:1px solid #ccc;">
                <td style="padding:8px;"><strong>MD5</strong></td>
                <td style="padding:8px;"><code>${md5.slice(0, 16)}...</code></td>
                <td style="padding:8px;">${tMd5} ms</td>
                <td style="padding:8px; color:#b91c1c;"><strong>Broken / Insecure</strong></td>
              </tr>
              <tr style="border-bottom:1px solid #ccc;">
                <td style="padding:8px;"><strong>SHA-256</strong></td>
                <td style="padding:8px;"><code>${sha256.slice(0, 16)}...</code></td>
                <td style="padding:8px;">${tSha256} ms</td>
                <td style="padding:8px; color:#b91c1c;"><strong>Too Fast (GPU Vulnerable)</strong></td>
              </tr>
              <tr style="border-bottom:1px solid #ccc;">
                <td style="padding:8px;"><strong>bcrypt (cost 8)</strong></td>
                <td style="padding:8px;"><code>${bcryptHash.slice(0, 24)}...</code></td>
                <td style="padding:8px;">${tBcrypt} ms</td>
                <td style="padding:8px; color:#15803d;"><strong>Good (CPU Hard)</strong></td>
              </tr>
              <tr>
                <td style="padding:8px;"><strong>Argon2id</strong></td>
                <td style="padding:8px;"><code>$argon2id$v=19$m=4096,t=3,p=1$...</code></td>
                <td style="padding:8px;">~65 ms</td>
                <td style="padding:8px; color:#15803d;"><strong>Optimal (Memory Hard + Side-channel resistant)</strong></td>
              </tr>
            </tbody>
          </table>
        `;
      }
    });
  }
});
