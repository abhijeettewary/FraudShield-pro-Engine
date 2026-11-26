let isRegister = false;
let liveTelemetry = { location: 'India', deviceType: 'Web Browser' };
let pendingTransfer = null;
let currentOtp = null;
let pendingScamPayload = null;

const simPresets = {
  safe: { u: 'USR_1042', d: 'DEV-8841', a: 2400, h: 15, c: 'Groceries', l: 'India', age: 210, t: 'Mobile App' },
  suspicious: { u: 'USR_3319', d: 'DEV-4410', a: 22000, h: 2, c: 'Retail', l: 'Singapore', age: 45, t: 'Web Browser' },
  fraud: { u: 'USR_9904', d: 'DEV-9900', a: 85000, h: 3, c: 'Crypto', l: 'Russia', age: 2, t: 'Unknown/VPN' },
  ring: { u: 'USR_BURNER_2', d: 'DEV-9900', a: 18000, h: 14, c: 'Wire Transfer', l: 'India', age: 3, t: 'Web Browser' }
};

function getDeviceId() {
  let id = localStorage.getItem('fs_device_id');
  if (!id) {
    id = 'DEV-WEB-' + Math.floor(1000 + Math.random() * 9000);
    localStorage.setItem('fs_device_id', id);
  }
  return id;
}

async function initTelemetry() {
  const devEl = document.getElementById('telDevice');
  const timeEl = document.getElementById('telTime');
  const locEl = document.getElementById('telLocation');
  const netEl = document.getElementById('telNet');

  if (devEl) devEl.textContent = getDeviceId();
  if (timeEl) timeEl.textContent = new Date().toTimeString().slice(0, 5);

  try {
    const res = await fetch('https://free.freeipapi.com/api/v1/json/');
    const geo = await res.json();
    liveTelemetry.location = geo.countryName || 'India';
    liveTelemetry.deviceType = geo.isProxy ? 'Unknown/VPN' : 'Web Browser';
    if (locEl) locEl.textContent = liveTelemetry.location;
    if (netEl) netEl.textContent = geo.isProxy ? 'VPN / Proxy' : 'Standard';
  } catch {
    if (locEl) locEl.textContent = 'India';
    if (netEl) netEl.textContent = 'Standard';
  }
}

document.querySelectorAll('.subnav-btn').forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll('.subnav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.c-view').forEach(v => v.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'security') loadSecurityCenter();
  };
});

document.querySelectorAll('.preset-btn').forEach(btn => {
  btn.onclick = () => {
    const p = simPresets[btn.dataset.p];
    document.getElementById('sUser').value = p.u;
    document.getElementById('sDev').value = p.d;
    document.getElementById('sAmt').value = p.a;
    document.getElementById('sHour').value = p.h;
    document.getElementById('sCat').value = p.c;
    document.getElementById('sLoc').value = p.l;
    document.getElementById('sAge').value = p.age;
    document.getElementById('sType').value = p.t;
  };
});

document.getElementById('simForm').onsubmit = async (e) => {
  e.preventDefault();
  const simResult = document.getElementById('simResult');
  simResult.innerHTML = '<p style="color:#64748b;">Evaluating transaction...</p>';

  try {
    const res = await fetch('/api/transactions/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: document.getElementById('sUser').value,
        deviceId: document.getElementById('sDev').value,
        amount: document.getElementById('sAmt').value,
        hourOfDay: document.getElementById('sHour').value,
        merchantCategory: document.getElementById('sCat').value,
        location: document.getElementById('sLoc').value,
        accountAgeDays: document.getElementById('sAge').value,
        deviceType: document.getElementById('sType').value
      })
    });
    const r = await res.json();
    if (!res.ok) {
      simResult.innerHTML = `<div class="banner fraudulent"><strong>Error</strong><p style="font-size:0.84rem;margin-top:4px;">${r.message || 'Evaluation failed.'}</p></div>`;
      return;
    }

    simResult.innerHTML = `
      <div class="banner ${r.status.toLowerCase()}" style="margin-bottom:14px;">
        <strong>${r.transactionId} • ${r.status.toUpperCase()} (Risk ${r.riskScore}/100)</strong>
        <p style="font-size:0.82rem;margin-top:4px;">Account: ${r.userId} | Device: ${r.deviceId} | Action: ${r.analystReview}</p>
      </div>
      <div style="font-size:0.82rem;font-weight:600;color:#0f172a;margin-bottom:6px;">Triggered Detection Signals:</div>
      <ul style="padding-left:18px;line-height:1.65;color:#475569;font-size:0.84rem;">
        ${(r.flaggedReasons || []).map(x => `<li>${x}</li>`).join('')}
      </ul>
      <p style="margin-top:14px;font-size:0.78rem;color:#64748b;">
        Logged to MongoDB — open the <strong>Bank Analyst SOC Portal</strong> to inspect this case in the Audit Log, Fraud Network Graph, and AI Investigator.
      </p>
    `;
  } catch {
    simResult.innerHTML = '<div class="banner fraudulent"><strong>Network Error</strong><p style="font-size:0.84rem;margin-top:4px;">Could not reach FraudShield-Pro Engine.</p></div>';
  }
};

async function checkSession() {
  try {
    const res = await fetch('/api/auth/me');
    if (!res.ok) return;
    const user = await res.json();
    if (user.role === 'customer') showApp();
  } catch {}
}

async function showApp() {
  document.getElementById('authSection').classList.add('hidden');
  document.getElementById('appSection').classList.remove('hidden');
  await initTelemetry();
  await loadDashboard();
}

async function loadDashboard() {
  try {
    const res = await fetch('/api/customer/dashboard');
    if (res.status === 401 || res.status === 403) return location.reload();
    const data = await res.json();

    document.getElementById('navUserName').textContent = data.profile.name;
    document.getElementById('balanceDisplay').textContent = '₹' + data.profile.balance.toLocaleString('en-IN');
    document.getElementById('accountNumberDisplay').textContent = data.profile.accountNumber;

    const renderLedgerHtml = (items) =>
      items.length
        ? items.map(e => `
            <div class="tx-item">
              <div>
                <div style="font-weight:600;font-size:0.9rem;">${e.type === 'DEBIT' ? 'Paid to' : 'Received from'} ${e.counterpartyName}</div>
                <div style="font-size:0.75rem;color:#64748b;">${e.transactionRef} • ${e.counterpartyAccount} • Bal: ₹${e.balanceAfter.toLocaleString('en-IN')}</div>
              </div>
              <div style="text-align:right;">
                <div class="${e.type === 'DEBIT' ? 'amt-debit' : 'amt-credit'}">${e.type === 'DEBIT' ? '-' : '+'}₹${e.amount.toLocaleString('en-IN')}</div>
                ${e.type === 'DEBIT' ? `<button class="btn-outline" style="font-size:0.68rem;padding:2px 8px;margin-top:4px;" onclick="reportTx('${e.transactionRef}')">Report</button>` : ''}
              </div>
            </div>`).join('')
        : '<p style="color:#64748b;font-size:0.86rem;">No transfers recorded yet.</p>';

    document.getElementById('homeLedgerList').innerHTML = renderLedgerHtml((data.ledger || []).slice(0, 5));
    document.getElementById('fullLedgerList').innerHTML = renderLedgerHtml(data.ledger || []);

    const alerts = data.alerts || [];
    document.getElementById('homeAlertList').innerHTML = alerts.length
      ? alerts.slice(0, 5).map(a => `
          <div class="tx-item">
            <div>
              <div style="font-weight:600;font-size:0.84rem;">${a.category.replace('_', ' ')}</div>
              <div style="font-size:0.76rem;color:#475569;">${a.message}</div>
            </div>
          </div>`).join('')
      : '<p style="color:#64748b;font-size:0.86rem;">No security alerts. Your account looks safe.</p>';

    const beneficiaries = data.beneficiaries || [];
    const benSelect = document.getElementById('benSelect');
    benSelect.innerHTML = '<option value="">-- Enter manually --</option>' +
      beneficiaries.map(b => `<option value="${b.beneficiaryAccountNumber}">${b.beneficiaryName} (${b.beneficiaryAccountNumber})</option>`).join('');

    document.getElementById('benList').innerHTML = beneficiaries.length
      ? beneficiaries.map(b => `
          <div class="tx-item">
            <div>
              <div style="font-weight:600;font-size:0.9rem;">${b.beneficiaryName} ${b.nickname ? `(${b.nickname})` : ''}</div>
              <div style="font-size:0.75rem;color:#64748b;">${b.beneficiaryAccountNumber} • <span class="${b.trustLevel === 'New' ? 'pill-new' : 'pill-est'}">${b.trustLevel}</span></div>
            </div>
            <button class="btn-outline" onclick="removeBen('${b._id}')">Remove</button>
          </div>`).join('')
      : '<p style="color:#64748b;font-size:0.86rem;">No saved beneficiaries yet.</p>';
  } catch (err) {
    console.error('Dashboard load error:', err);
  }
}

document.getElementById('benSelect').onchange = (e) => {
  if (e.target.value) document.getElementById('recAccInput').value = e.target.value;
};

document.getElementById('addBenForm').onsubmit = async (e) => {
  e.preventDefault();
  const msg = document.getElementById('benMsg');
  msg.style.color = '#64748b';
  msg.textContent = 'Saving...';

  try {
    const res = await fetch('/api/customer/beneficiaries', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountNumber: document.getElementById('newBenAcc').value.trim(),
        nickname: document.getElementById('newBenNick').value.trim()
      })
    });

    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { throw new Error(`HTTP ${res.status}. Restart npm start.`); }

    msg.style.color = res.ok ? '#137333' : '#d93025';
    msg.textContent = res.ok ? `Saved ${data.beneficiaryName} (Trust: New)` : (data.message || 'Failed to save.');

    if (res.ok) {
      document.getElementById('newBenAcc').value = '';
      document.getElementById('newBenNick').value = '';
      await loadDashboard();
    }
  } catch (err) {
    msg.style.color = '#d93025';
    msg.textContent = err.message;
  }
};

window.removeBen = async (id) => {
  await fetch('/api/customer/beneficiaries/' + id, { method: 'DELETE' });
  loadDashboard();
};

window.reportTx = async (txRef) => {
  if (!confirm(`Report transaction ${txRef} as unauthorized?`)) return;
  const res = await fetch('/api/customer/security/report/' + txRef, { method: 'POST' });
  const data = await res.json();
  alert(data.message);
  loadDashboard();
};

async function executeTransfer(payload) {
  try {
    const res = await fetch('/api/customer/transfer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) return alert(data.message || 'Transfer failed');

    const tx = data.transaction;
    document.getElementById('outcomeEmpty').classList.add('hidden');
    document.getElementById('outcomeWrap').classList.remove('hidden');
    const banner = document.getElementById('outcomeBanner');
    banner.className = 'banner ' + tx.status.toLowerCase();
    document.getElementById('otpBox').classList.add('hidden');

    if (tx.status === 'Safe') {
      document.getElementById('outcomeTitle').textContent = `Paid ₹${tx.amount.toLocaleString('en-IN')} to ${data.recipientName}`;
      document.getElementById('outcomeMsg').textContent = `Ref ${tx.transactionId} • Risk ${tx.riskScore}/100 • Ledger updated atomically.`;
    } else if (tx.status === 'Suspicious') {
      pendingTransfer = {
        id: tx._id,
        receiverAccountNumber: payload.beneficiaryAccountNumber,
        description: payload.description,
        idempotencyKey: payload.idempotencyKey
      };
      currentOtp = String(Math.floor(100000 + Math.random() * 900000));
      document.getElementById('demoOtp').textContent = 'SMS OTP: ' + currentOtp;
      document.getElementById('outcomeTitle').textContent = 'Payment Paused — Verification Required';
      document.getElementById('outcomeMsg').textContent = `Unusual activity detected (Risk ${tx.riskScore}/100). Funds have NOT moved yet.`;
      document.getElementById('otpBox').classList.remove('hidden');
    } else {
      document.getElementById('outcomeTitle').textContent = 'Payment Blocked (High Risk)';
      document.getElementById('outcomeMsg').textContent = `Blocked automatically (Risk ${tx.riskScore}/100). No funds were deducted.`;
    }
    loadDashboard();
  } catch {
    alert('Transfer request failed. Check server connection.');
  }
}

document.getElementById('transferForm').onsubmit = async (e) => {
  e.preventDefault();
  const payload = {
    beneficiaryAccountNumber: document.getElementById('recAccInput').value.trim().toUpperCase(),
    amount: Number(document.getElementById('payAmount').value),
    merchantCategory: document.getElementById('payCategory').value,
    description: document.getElementById('payDesc').value.trim(),
    location: liveTelemetry.location,
    deviceType: liveTelemetry.deviceType,
    deviceId: getDeviceId(),
    idempotencyKey: 'IDEMP-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)
  };

  try {
    const checkRes = await fetch('/api/customer/scam-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        beneficiaryAccountNumber: payload.beneficiaryAccountNumber,
        amount: payload.amount,
        description: payload.description
      })
    });
    const checkData = await checkRes.json();
    if (!checkRes.ok) return alert(checkData.message || 'Recipient validation failed.');

    if (checkData.shouldWarn) {
      pendingScamPayload = payload;
      document.getElementById('scamSubtext').textContent =
        `Sending ₹${payload.amount.toLocaleString('en-IN')} to ${checkData.recipientName} (${checkData.recipientAccount})`;
      document.getElementById('scamWarningList').innerHTML = checkData.warnings
        .map(w => `<li><strong>${w.title}</strong><span>${w.detail}</span></li>`)
        .join('');
      document.getElementById('scamModalBackdrop').classList.remove('hidden');
      return;
    }

    await executeTransfer(payload);
  } catch {
    alert('Could not run ScamShield check.');
  }
};

document.getElementById('scamCancelBtn').onclick = () => {
  pendingScamPayload = null;
  document.getElementById('scamModalBackdrop').classList.add('hidden');
};

document.getElementById('scamProceedBtn').onclick = async () => {
  const payload = pendingScamPayload;
  pendingScamPayload = null;
  document.getElementById('scamModalBackdrop').classList.add('hidden');
  if (payload) await executeTransfer(payload);
};

document.getElementById('verifyOtpBtn').onclick = async () => {
  const entered = document.getElementById('otpInput').value.trim();
  const errEl = document.getElementById('otpErr');
  errEl.classList.add('hidden');
  if (entered !== currentOtp) {
    errEl.textContent = 'Invalid OTP. Enter ' + currentOtp;
    errEl.classList.remove('hidden');
    return;
  }
  const res = await fetch(`/api/customer/transfer/${pendingTransfer.id}/step-up`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'verify',
      receiverAccountNumber: pendingTransfer.receiverAccountNumber,
      description: pendingTransfer.description,
      idempotencyKey: pendingTransfer.idempotencyKey
    })
  });
  const data = await res.json();
  if (!res.ok) {
    errEl.textContent = data.message;
    errEl.classList.remove('hidden');
    return;
  }
  document.getElementById('otpBox').classList.add('hidden');
  document.getElementById('outcomeBanner').className = 'banner safe';
  document.getElementById('outcomeTitle').textContent = 'OTP Verified — Transfer Completed';
  document.getElementById('outcomeMsg').textContent = 'Ledger updated atomically.';
  loadDashboard();
};

document.getElementById('denyOtpBtn').onclick = async () => {
  await fetch(`/api/customer/transfer/${pendingTransfer.id}/step-up`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'deny' })
  });
  document.getElementById('otpBox').classList.add('hidden');
  document.getElementById('outcomeBanner').className = 'banner fraudulent';
  document.getElementById('outcomeTitle').textContent = 'Transfer Cancelled & Device Watchlisted';
  loadDashboard();
};

async function loadSecurityCenter() {
  const res = await fetch('/api/customer/security');
  const data = await res.json();

  document.getElementById('secDevices').innerHTML = (data.trustedDevices || []).length
    ? data.trustedDevices.map(d => `
        <div class="tx-item">
          <div><strong>${d.deviceId}</strong><div style="font-size:0.74rem;color:#64748b;">${d.label}</div></div>
          <button class="btn-outline" onclick="removeDevice('${d.deviceId}')">Remove</button>
        </div>`).join('')
    : '<p style="color:#64748b;font-size:0.84rem;">No trusted devices saved.</p>';

  document.getElementById('secAlerts').innerHTML = (data.alerts || []).length
    ? data.alerts.map(a => `
        <div class="tx-item">
          <div>
            <strong>${a.category.replace('_', ' ')}</strong>
            <div style="font-size:0.78rem;color:#475569;">${a.message}</div>
          </div>
          <span class="badge ${a.severity === 'high' ? 'badge-Fraudulent' : 'badge-Suspicious'}">${a.severity}</span>
        </div>`).join('')
    : '<p style="color:#64748b;font-size:0.84rem;">No security events recorded.</p>';
}

window.removeDevice = async (devId) => {
  await fetch('/api/customer/security/devices/' + devId, { method: 'DELETE' });
  loadSecurityCenter();
};

document.getElementById('logoutAllBtn').onclick = async () => {
  const res = await fetch('/api/customer/security/logout-all', { method: 'POST' });
  const data = await res.json();
  alert(data.message);
};

document.getElementById('changePassForm').onsubmit = async (e) => {
  e.preventDefault();
  const msg = document.getElementById('passMsg');
  const res = await fetch('/api/customer/security/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      currentPassword: document.getElementById('currPass').value,
      newPassword: document.getElementById('newPass').value
    })
  });
  const data = await res.json();
  msg.style.color = res.ok ? '#137333' : '#d93025';
  msg.textContent = data.message;
  if (res.ok) e.target.reset();
};

document.getElementById('tabLogin').onclick = () => {
  isRegister = false;
  document.getElementById('tabLogin').classList.add('active');
  document.getElementById('tabRegister').classList.remove('active');
  document.getElementById('nameWrap').classList.add('hidden');
  document.getElementById('authBtn').textContent = 'Sign In';
};

document.getElementById('tabRegister').onclick = () => {
  isRegister = true;
  document.getElementById('tabRegister').classList.add('active');
  document.getElementById('tabLogin').classList.remove('active');
  document.getElementById('nameWrap').classList.remove('hidden');
  document.getElementById('authBtn').textContent = 'Open Simulated Account';
};

document.getElementById('authForm').onsubmit = async (e) => {
  e.preventDefault();
  const errEl = document.getElementById('authError');
  errEl.classList.add('hidden');
  const url = isRegister ? '/api/auth/customer/register' : '/api/auth/customer/login';
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: document.getElementById('authName').value,
      email: document.getElementById('authEmail').value,
      password: document.getElementById('authPassword').value,
      deviceId: getDeviceId(),
      location: liveTelemetry.location
    })
  });
  const data = await res.json();
  if (!res.ok) {
    errEl.textContent = data.message || 'Authentication failed.';
    errEl.classList.remove('hidden');
    return;
  }
  showApp();
};

document.getElementById('logoutBtn').onclick = async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
  location.reload();
};

checkSession();