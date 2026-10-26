/**
 * Virtual Cryptography Laboratory - Admin Feedback Decryption Engine
 */
(() => {
  const CONFIG = {
    SCRIPT_URL: 'https://script.google.com/macros/s/AKfycbzcFxNVRpN5jtzLBdkiaGVTY73KNXsSyla7GkVUz1OUIS89qWFrwljh9BXu5Letxdtj/exec',
    saltB64: 'Nzwpl7dFFqYi0slM2dKkig==',
    ivB64: 'NHjKet8b+cQiDe6r',
    tagB64: 'ltW4ISoul7q/yw4I/dvmAQ==',
    encPrivKeyB64: '5GpFQv6ucJqmua0/gvl3cAm7BscqTBBocDcFqPEBzgZHf3nMcZpc66qbk5pV8idoQYIvJ7m5hhP3mWOVpLEtBmaU0FO+U6GZCmFJyWvv6kvwtpWESfTrrhSgp+x6q7A2zIfZkmDxD/gbHW2A8aIWa+d5bH6xRnve+oLW/BHN7kRQjVGn71wjkh2cWSDSaWfAV3+N+mB1Cl/mmO00haUJFnDFaF5XmiSiavSpCEE7YEqe6BZhNGOWV7Sc2UDobMX6kuUgg50AE9Ldy8eyOwy0mI73gKQz+luir9zFD1Bg8xXB66THpZ0baaheMdOUvqkT8CdKJBs8Bnj9X9vqdo/yM1kBs+ULUrQAJv2FAdLAGgL/KuEv0KlLDCMREIT/WUGvE3bjtZ9hKhvN+iYcC+SrsNGEkSRhgXLRSSGctirbFroY7Z0iVT87dDoj/aF6cMlBUI2EKvEnb0++UPmm1prua9HnrXZUQHe/UBvadOlSkDzo8V7CjZsrDQu3IwBx9zWP+kIf9elBgqnhxet67LuPfOFItqmbk93prM0qnkPO45Clwfi7uZ1oDMJnoi5GpOKXOyL3LjqxU5LDhUXYcaVt3JcX5nhyzG1DIGQI3Qp0ZBOdgtW2/PyKsolbrasfWRuTlOsiyy8sQM6EPrxtlJqvSZqbw3uiYhG6WJOQzmGPUOcBstdBvtLXQoIaAncLKV6Z+icO/el+Z6W6fRaAHz8O/smNpEiG21rqootANpypYSyFkr+AAUcDqMa2PXoIIRZu77M78BwnkPFtROwj8iJcuohiHeb1cK9esqwx21729H+KiuhyOTJ3hlC4feDL8pomIisIwoqtowPLj+Q20z/5kcolMBfaoUhDyUdsbE+q3nQkI8+ql1JnLdS2+NGFyF/7fq+eVM2/ZPDPfe4JZZ/KBIhlf+g/w4NiSNr7KyJMjP1jiG1zrW+JjCq3J1es5p0A1xcxhZk2FxF9BYFVJ6029vEJ9GNMZmLeq698RMzetQ5f75rPJgB39JgVsVt9bVggscVYCC02WTm/lhne/lLtN67SNFQeOXiAfbzTNgcZ3zGUsehu2As8T0MM+W8sPT91QOKCCTKtlGE1s8PLKLf6gTN3IHQ5oCEXcHA1YEhBvK3sAjvbyq42H/1YYpHgS8W3qwibA81bdvIjkc0h8Du39/a4mTkPE/P63g4UPxZoIGVavWYKuw//jKpJ9bpEmS7UPFH4X3TxQdLbW8OndyDb4I1Ok/IQX2gM2iLs8dFENu2pV0zjDNEwvMls1e9j4gyA2sPxujsb4sl4GrZJNn8n7wxoFnHKUEztg2mlUxjvqciPTMcerch5wHypfccypxsb0OdixiA1s9Sf4mfyEBf5Fx7c+QaUN8Fx/jbTMA6tRU5NldMmKRe+DzMPBx64hrOvxv/J0B33vQ95Uzqe0t11bSwi3lEbtufH/Zi872SxA4BF41Q0TzEkig0T3tY9Pnlqf/Vx4vYjEBqpHeB0PivQJDU1wS/x61I2rC4ZeRjkAs8Sfdxa/AJVJaqt0Shz63g0FXFOVW+njwzY0Yvs6EjlzpDSVnmoBAmB6F1kuYwRcc4b7Of/rz22Gw9T7FDDpZDdW1vXBf75UB8pHhCmclBI4lg='
  };

  let rsaPrivateKey = null;
  let allDecryptedSubmissions = [];

  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function concatBuffers(buf1, buf2) {
    const tmp = new Uint8Array(buf1.byteLength + buf2.byteLength);
    tmp.set(new Uint8Array(buf1), 0);
    tmp.set(new Uint8Array(buf2), buf1.byteLength);
    return tmp.buffer;
  }

  async function unlockPrivateKey(password) {
    const enc = new TextEncoder();

    // 1. Derive key from password using PBKDF2
    const passKey = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const salt = base64ToArrayBuffer(CONFIG.saltB64);
    const derivedKey = await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      passKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // 2. Decrypt RSA Private Key (AES-GCM ciphertext + tag)
    const iv = base64ToArrayBuffer(CONFIG.ivB64);
    const encPrivKeyBuf = base64ToArrayBuffer(CONFIG.encPrivKeyB64);
    const tagBuf = base64ToArrayBuffer(CONFIG.tagB64);
    const combinedCiphertext = concatBuffers(encPrivKeyBuf, tagBuf);

    const decryptedPrivKeyDer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      derivedKey,
      combinedCiphertext
    );

    // 3. Import decrypted PKCS#8 private key
    const privKey = await window.crypto.subtle.importKey(
      'pkcs8',
      decryptedPrivKeyDer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt']
    );

    return privKey;
  }

  async function decryptPayload(payloadStr) {
    if (!rsaPrivateKey) throw new Error('Private key not unlocked');

    let payloadObj;
    try {
      payloadObj = JSON.parse(payloadStr);
    } catch {
      // Plain text fallback (for initial test rows)
      return {
        studentName: 'System / Test',
        rollNo: '-',
        rating: 5,
        clarityRating: 5,
        easeRating: 5,
        comments: payloadStr,
        submittedAt: '-'
      };
    }

    if (!payloadObj.k || !payloadObj.iv || !payloadObj.c) {
      return payloadObj;
    }

    const encKeyBuf = base64ToArrayBuffer(payloadObj.k);
    const ivBuf = base64ToArrayBuffer(payloadObj.iv);
    const cipherBuf = base64ToArrayBuffer(payloadObj.c);

    // 1. Decrypt AES key with RSA-OAEP
    const rawAesKey = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      rsaPrivateKey,
      encKeyBuf
    );

    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      rawAesKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // 2. Decrypt data with AES-GCM
    const decryptedDataBuf = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBuf },
      aesKey,
      cipherBuf
    );

    const dec = new TextDecoder();
    return JSON.parse(dec.decode(decryptedDataBuf));
  }

  async function loadData() {
    const tableBody = document.getElementById('feedbackTableBody');
    tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 24px;">Fetching encrypted submissions from secure cloud repository...</td></tr>`;

    try {
      const res = await fetch(CONFIG.SCRIPT_URL);
      const rows = await res.json();

      allDecryptedSubmissions = [];

      for (const row of rows) {
        try {
          const decrypted = await decryptPayload(row.payload);
          const expName = (decrypted.experimentTitle && !decrypted.experimentTitle.includes('index.html'))
            ? decrypted.experimentTitle
            : (decrypted.experimentSlug && decrypted.experimentSlug !== 'index.html'
                ? decrypted.experimentSlug
                : (row.experiment && row.experiment !== 'index.html' ? row.experiment : 'MAC'));

          allDecryptedSubmissions.push({
            timestamp: row.timestamp || decrypted.submittedAt || '-',
            experiment: expName,
            experimentTitle: expName,
            studentName: decrypted.studentName || 'Anonymous',
            rollNo: decrypted.rollNo || '-',
            rating: decrypted.rating || 0,
            clarityRating: decrypted.clarityRating || '-',
            easeRating: decrypted.easeRating || '-',
            comments: decrypted.comments || ''
          });
        } catch (decryptErr) {
          console.warn('Decryption skipped for row:', decryptErr);
        }
      }

      populateExpFilter();
      updateDashboard();
    } catch (err) {
      console.error('Fetch error:', err);
      tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #ff6b6b; padding: 24px;">Failed to load submissions. Please check network connectivity.</td></tr>`;
    }
  }

  function populateExpFilter() {
    const select = document.getElementById('expFilter');
    const existing = select.value;
    const exps = [...new Set(allDecryptedSubmissions.map(s => s.experiment))].sort();

    select.innerHTML = '<option value="">All Experiments</option>';
    exps.forEach(exp => {
      const opt = document.createElement('option');
      opt.value = exp;
      opt.textContent = exp;
      select.appendChild(opt);
    });
    select.value = existing;
  }

  function updateDashboard() {
    const searchVal = document.getElementById('searchInput').value.toLowerCase().trim();
    const expVal = document.getElementById('expFilter').value;
    const ratingVal = document.getElementById('ratingFilter').value;

    const filtered = allDecryptedSubmissions.filter(item => {
      if (expVal && item.experiment !== expVal) return false;
      if (ratingVal && String(item.rating) !== ratingVal) return false;
      if (searchVal) {
        const hay = `${item.studentName} ${item.rollNo} ${item.comments} ${item.experiment}`.toLowerCase();
        if (!hay.includes(searchVal)) return false;
      }
      return true;
    });

    // Stats
    document.getElementById('statTotalSubmissions').textContent = allDecryptedSubmissions.length;
    const avg = allDecryptedSubmissions.length
      ? (allDecryptedSubmissions.reduce((acc, cur) => acc + (cur.rating || 0), 0) / allDecryptedSubmissions.length).toFixed(1)
      : '0.0';
    document.getElementById('statAvgRating').textContent = avg;
    const distinctExpCount = new Set(allDecryptedSubmissions.map(s => s.experiment)).size;
    document.getElementById('statDistinctExp').textContent = distinctExpCount;

    // Render table
    const tableBody = document.getElementById('feedbackTableBody');
    if (filtered.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 24px; color: var(--color-text-muted);">No feedback records found matching your filters.</td></tr>`;
      return;
    }

    tableBody.innerHTML = filtered.map(item => {
      const dateStr = item.timestamp ? new Date(item.timestamp).toLocaleString() : '-';
      const stars = '&#9733;'.repeat(item.rating || 0);

      return `
        <tr>
          <td style="white-space: nowrap;">${escapeHtml(dateStr)}</td>
          <td><span class="badge-exp">${escapeHtml(item.experiment)}</span></td>
          <td><strong>${escapeHtml(item.studentName)}</strong></td>
          <td><code>${escapeHtml(item.rollNo)}</code></td>
          <td><span class="star-score">${stars}</span> (${item.rating}/5)</td>
          <td>Clarity: ${escapeHtml(String(item.clarityRating))}/5<br>Ease: ${escapeHtml(String(item.easeRating))}/5</td>
          <td class="comment-cell">${escapeHtml(item.comments)}</td>
        </tr>
      `;
    }).join('');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function exportCSV() {
    if (!allDecryptedSubmissions.length) {
      alert('No submissions available to export.');
      return;
    }

    const headers = ['Timestamp', 'Experiment', 'Student Name', 'Roll No', 'Rating', 'Clarity', 'Ease', 'Comments'];
    const rows = allDecryptedSubmissions.map(item => [
      item.timestamp,
      item.experiment,
      item.studentName,
      item.rollNo,
      item.rating,
      item.clarityRating,
      item.easeRating,
      `"${(item.comments || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `virtual_lab_feedback_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  // Interactivity
  document.getElementById('unlockForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const passInput = document.getElementById('masterPassword');
    const statusDiv = document.getElementById('unlockStatus');
    const unlockBtn = document.getElementById('unlockBtn');

    const password = passInput.value.trim();
    if (!password) return;

    unlockBtn.disabled = true;
    unlockBtn.textContent = 'Deriving Key & Verifying...';
    statusDiv.hidden = false;
    statusDiv.className = 'feedback-status info';
    statusDiv.textContent = 'Decrypting private key using PBKDF2 (100,000 iterations)...';

    try {
      rsaPrivateKey = await unlockPrivateKey(password);
      statusDiv.className = 'feedback-status success';
      statusDiv.textContent = 'Authentication successful! Loading repository...';

      setTimeout(async () => {
        document.getElementById('lockSection').hidden = true;
        document.getElementById('dashboardSection').hidden = false;
        await loadData();
      }, 500);
    } catch (err) {
      console.error('Unlock error:', err);
      statusDiv.className = 'feedback-status error';
      statusDiv.textContent = 'Authentication failed: Incorrect master passphrase. Access denied.';
      unlockBtn.disabled = false;
      unlockBtn.textContent = 'Unlock & Decrypt Data';
    }
  });

  document.getElementById('searchInput').addEventListener('input', updateDashboard);
  document.getElementById('expFilter').addEventListener('change', updateDashboard);
  document.getElementById('ratingFilter').addEventListener('change', updateDashboard);
  document.getElementById('refreshBtn').addEventListener('click', loadData);
  document.getElementById('exportBtn').addEventListener('click', exportCSV);
})();
