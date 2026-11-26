let isRegisterMode = false;
let allTransactions = [];
let allWatchlist = [];
let activeFilter = 'All';
let statusChartInstance = null;
let categoryChartInstance = null;

// Step-Up OTP State
let pendingOtpTxId = null;
let generatedOtp = null;
let pendingMerchantName = '';
let pendingAmountValue = 0;

const presets = {
  safe: { userId: 'USR_1042', deviceId: 'DEV-8841', amount: 2400, hourOfDay: 15, merchantCategory: 'Groceries', location: 'India', accountAgeDays: 210, deviceType: 'Mobile App' },
  suspicious: { userId: 'USR_3319', deviceId: 'DEV-4410', amount: 22000, hourOfDay: 2, merchantCategory: 'Retail', location: 'Singapore', accountAgeDays: 45, deviceType: 'Web Browser' },
  fraud: { userId: 'USR_9904', deviceId: 'DEV-9900', amount: 85000, hourOfDay: 3, merchantCategory: 'Crypto', location: 'Russia', accountAgeDays: 2, deviceType: 'Unknown/VPN' },
  ring: { userId: 'USR_BURNER_2', deviceId: 'DEV-9900', amount: 18000, hourOfDay: 14, merchantCategory: 'Wire Transfer', location: 'India', accountAgeDays: 3, deviceType: 'Web Browser' }
};

// --- AUTH LOGIC ---
function showApp(user) {
  localStorage.setItem('fs_user', JSON.stringify(user));
  document.getElementById('analystName').textContent = user.name;
  document.getElementById('analystEmail').textContent = user.email;
  document.getElementById('authScreen').classList.add('hidden');
  document.getElementById('appShell').classList.remove('hidden');
  loadDashboard();
  loadMlStatus();
}

const savedUser = localStorage.getItem('fs_user');
if (savedUser) showApp(JSON.parse(savedUser));

document.getElementById('tabLogin').addEventListener('click', () => {
  isRegisterMode = false;
  document.getElementById('tabLogin').classList.add('active');
  document.getElementById('tabRegister').classList.remove('active');
  document.getElementById('nameField').classList.add('hidden');
  document.getElementById('authSubmitBtn').textContent = 'Sign In';
});

document.getElementById('tabRegister').addEventListener('click', () => {
  isRegisterMode = true;
  document.getElementById('tabRegister').classList.add('active');
  document.getElementById('tabLogin').classList.remove('active');
  document.getElementById('nameField').classList.remove('hidden');
  document.getElementById('authSubmitBtn').textContent = 'Create Analyst Account';
});

document.getElementById('authForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById('authError');
  errorEl.classList.add('hidden');

  const endpoint = isRegisterMode ? '/api/auth/register' : '/api/auth/login';
  const payload = {
    name: document.getElementById('authName').value,
    email: document.getElementById('authEmail').value,
    password: document.getElementById('authPassword').value
  };

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      errorEl.textContent = data.message || 'Authentication failed';
      errorEl.classList.remove('hidden');
      return;
    }
    showApp(data);
  } catch (err) {
    errorEl.textContent = 'Cannot connect to server.';
    errorEl.classList.remove('hidden');
  }
});

document.getElementById('logoutBtn').addEventListener('click', () => {
  localStorage.removeItem('fs_user');
  document.getElementById('appShell').classList.add('hidden');
  document.getElementById('authScreen').classList.remove('hidden');
});

// --- NAVIGATION ---
function switchView(viewName) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  document.getElementById('view-' + viewName).classList.add('active');
  document.querySelector('.nav-item[data-view="' + viewName + '"]').classList.add('active');
}

document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

function getBadgeClass(status) {
  if (status === 'Fraudulent') return 'badge badge-fraudulent';
  if (status === 'Suspicious') return 'badge badge-suspicious';
  return 'badge badge-safe';
}

function getBarColor(status) {
  if (status === 'Fraudulent') return '#dc2626';
  if (status === 'Suspicious') return '#d97706';
  return '#059669';
}

// --- CHARTS & DASHBOARD ---
function updateCharts(metrics, categoryStats) {
  const ctx1 = document.getElementById('statusChart').getContext('2d');
  if (statusChartInstance) statusChartInstance.destroy();
  statusChartInstance = new Chart(ctx1, {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Suspicious', 'Fraudulent'],
      datasets: [{ data: [metrics.safeCount, metrics.suspiciousCount, metrics.fraudCount], backgroundColor: ['#059669', '#d97706', '#dc2626'] }]
    },
    options: { responsive: true, maintainAspectRatio: false }
  });

  const ctx2 = document.getElementById('categoryChart').getContext('2d');
  if (categoryChartInstance) categoryChartInstance.destroy();
  categoryChartInstance = new Chart(ctx2, {
    type: 'bar',
    data: {
      labels: Object.keys(categoryStats).length ? Object.keys(categoryStats) : ['No Flagged Data'],
      datasets: [{ label: 'Flagged Cases', data: Object.keys(categoryStats).length ? Object.values(categoryStats) : [0], backgroundColor: '#1d4ed8', borderRadius: 6 }]
    },
    options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } }
  });
}

// --- WATCHLIST TABLE ---
function renderWatchlist() {
  const tbody = document.getElementById('watchlistBody');
  if (!allWatchlist.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-msg">No learned patterns yet.</td></tr>';
    return;
  }
  tbody.innerHTML = allWatchlist.map(w => {
    const badgeClass = w.action === 'watchlist' ? 'badge-fraudulent' : 'badge-safe';
    const badgeText = w.action === 'watchlist' ? 'Watchlist (+25)' : 'Trusted (-20)';
    return (
      '<tr>' +
        '<td style="text-transform:uppercase;font-size:0.76rem;font-weight:600;">' + w.type + '</td>' +
        '<td class="mono">' + w.value + '</td>' +
        '<td><span class="badge ' + badgeClass + '">' + badgeText + '</span></td>' +
        '<td><button class="action-btn btn-del" onclick="deleteWatchlist(\'' + w._id + '\')">Remove</button></td>' +
      '</tr>'
    );
  }).join('');
}

// --- AUTOMATED AUDIT LOG (ZERO MANUAL APPROVALS) ---
function renderTable() {
  const query = document.getElementById('searchInput').value.toLowerCase();
  const filtered = allTransactions.filter(tx => {
    const matchesStatus = activeFilter === 'All' || tx.status === activeFilter;
    const matchesSearch =
      tx.transactionId.toLowerCase().includes(query) ||
      tx.userId.toLowerCase().includes(query) ||
      (tx.deviceId || '').toLowerCase().includes(query) ||
      tx.location.toLowerCase().includes(query);
    return matchesStatus && matchesSearch;
  });

  const tbody = document.getElementById('txTableBody');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-msg">No matching transactions found.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(tx => {
    const ringBadge = tx.ringLinkedUsers && tx.ringLinkedUsers.length
      ? ' <span class="badge badge-fraudulent" style="font-size:0.68rem;">Ring</span>'
      : '';

    let autoAction = 'Auto-Cleared (Zero Friction)';
    if (tx.analystReview === 'Customer OTP Verified') {
      autoAction = 'Auto-Approved via Customer OTP';
    } else if (tx.analystReview === 'Customer Denied (Auto-Blocked)') {
      autoAction = 'Auto-Blocked & Device Blacklisted';
    } else if (tx.status === 'Suspicious') {
      autoAction = 'Step-Up OTP Sent to Customer';
    } else if (tx.status === 'Fraudulent') {
      autoAction = 'Auto-Blocked & Device Blacklisted';
    }

    return (
      '<tr>' +
        '<td class="mono"><strong>' + tx.transactionId + '</strong></td>' +
        '<td class="mono">' + tx.userId + '<br/><span style="font-size:0.74rem;color:#64748b;">' + (tx.deviceId || 'N/A') + '</span>' + ringBadge + '</td>' +
        '<td class="mono">₹' + tx.amount.toLocaleString('en-IN') + '</td>' +
        '<td class="mono">' + tx.riskScore + '/100</td>' +
        '<td><span class="' + getBadgeClass(tx.status) + '">' + tx.status + '</span></td>' +
        '<td style="font-size:0.8rem;font-weight:600;color:#334155;">' + autoAction + '</td>' +
      '</tr>'
    );
  }).join('');
}

async function loadDashboard() {
  try {
    const res = await fetch('/api/transactions');
    const data = await res.json();
    allTransactions = data.transactions || [];
    allWatchlist = data.watchlist || [];

    document.getElementById('totalCount').textContent = data.metrics.totalCount;
    document.getElementById('fraudCount').textContent = data.metrics.fraudCount;
    document.getElementById('suspiciousCount').textContent = data.metrics.suspiciousCount;
    document.getElementById('blockedAmount').textContent = '₹' + data.metrics.blockedAmount.toLocaleString('en-IN');

    updateCharts(data.metrics, data.categoryStats || {});
    renderTable();
    renderWatchlist();
  } catch (err) {
    console.error('Error loading dashboard:', err);
  }
}

async function deleteWatchlist(id) {
  await fetch('/api/watchlist/' + id, { method: 'DELETE' });
  loadDashboard();
}

document.querySelectorAll('.preset-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const p = presets[btn.dataset.preset];
    document.getElementById('userId').value = p.userId;
    document.getElementById('deviceId').value = p.deviceId;
    document.getElementById('amount').value = p.amount;
    document.getElementById('hourOfDay').value = p.hourOfDay;
    document.getElementById('merchantCategory').value = p.merchantCategory;
    document.getElementById('location').value = p.location;
    document.getElementById('accountAgeDays').value = p.accountAgeDays;
    document.getElementById('deviceType').value = p.deviceType;
  });
});

document.getElementById('searchInput').addEventListener('input', renderTable);

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    renderTable();
  });
});

document.getElementById('exportCsvBtn').addEventListener('click', () => {
  if (!allTransactions.length) return alert('No data to export.');
  const headers = ['TransactionID,UserID,DeviceID,Amount,ZScore,MLConfidence,RiskScore,Status,AutomatedAction'];
  const rows = allTransactions.map(t =>
    [t.transactionId, t.userId, t.deviceId || '', t.amount, t.zScore || 0, t.mlProbability || 0, t.riskScore, t.status, t.analystReview].join(',')
  );
  const blob = new Blob([headers.concat(rows).join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'fraudshield_audit_log.csv';
  a.click();
});

document.getElementById('txForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = {
    userId: document.getElementById('userId').value,
    deviceId: document.getElementById('deviceId').value,
    amount: document.getElementById('amount').value,
    hourOfDay: document.getElementById('hourOfDay').value,
    merchantCategory: document.getElementById('merchantCategory').value,
    location: document.getElementById('location').value,
    accountAgeDays: document.getElementById('accountAgeDays').value,
    deviceType: document.getElementById('deviceType').value
  };

  try {
    const res = await fetch('/api/transactions/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const result = await res.json();

    document.getElementById('emptyResult').classList.add('hidden');
    document.getElementById('resultCard').classList.remove('hidden');
    document.getElementById('resultTitle').textContent = result.transactionId + ' (' + result.userId + ')';

    const badge = document.getElementById('resultBadge');
    badge.className = getBadgeClass(result.status);
    badge.textContent = result.status;

    document.getElementById('resultScoreText').textContent = result.riskScore + ' / 100';
    const fill = document.getElementById('riskBarFill');
    fill.style.width = result.riskScore + '%';
    fill.style.backgroundColor = getBarColor(result.status);

    let tagsHtml = '<span class="info-tag">Device: ' + result.deviceId + '</span>';
    if (result.mlProbability !== undefined) {
      tagsHtml += '<span class="info-tag">ML Confidence: ' + result.mlProbability + '%</span>';
    }
    if (result.zScore) tagsHtml += '<span class="info-tag">Behavioral Z-Score: ' + result.zScore + 'σ</span>';
    if (result.ringLinkedUsers && result.ringLinkedUsers.length) {
      tagsHtml += '<span class="info-tag ring-tag">Fraud Ring Linked: ' + result.ringLinkedUsers.join(', ') + '</span>';
    }
    document.getElementById('extraTags').innerHTML = tagsHtml;

    document.getElementById('resultReasons').innerHTML = result.flaggedReasons.length
      ? result.flaggedReasons.map(r => '<li>' + r + '</li>').join('')
      : '<li>No anomalies detected. Transaction auto-cleared.</li>';

    loadDashboard();
  } catch (err) {
    alert('Server error. Ensure MongoDB and Node.js are running.');
  }
});

// --- CUSTOMER PAYMENT PORTAL (LIVE AUTO-TELEMETRY + STEP-UP OTP) ---
let liveTelemetry = {
  location: 'India',
  deviceType: 'Web Browser'
};

function getOrCreateBrowserDeviceId() {
  let devId = localStorage.getItem('fs_device_id');
  if (!devId) {
    devId = 'DEV-WEB-' + Math.floor(1000 + Math.random() * 9000);
    localStorage.setItem('fs_device_id', devId);
  }
  return devId;
}

async function initCustomerTelemetry() {
  const devEl = document.getElementById('autoDeviceDisplay');
  const timeEl = document.getElementById('autoTimeDisplay');
  const locEl = document.getElementById('autoLocationDisplay');
  const netEl = document.getElementById('autoNetworkDisplay');

  if (devEl) devEl.textContent = getOrCreateBrowserDeviceId();
  if (timeEl) timeEl.textContent = new Date().toTimeString().slice(0, 5);

  try {
    const res = await fetch('https://free.freeipapi.com/api/v1/json/');
    const geo = await res.json();
    liveTelemetry.location = geo.countryName || 'India';
    liveTelemetry.deviceType = geo.isProxy ? 'Unknown/VPN' : 'Web Browser';

    if (locEl) locEl.textContent = liveTelemetry.location;
    if (netEl) netEl.textContent = geo.isProxy ? 'VPN / Proxy Detected' : 'Standard Browser';
  } catch (err) {
    if (locEl) locEl.textContent = liveTelemetry.location;
    if (netEl) netEl.textContent = 'Standard Browser';
  }
}

initCustomerTelemetry();

const customerPayForm = document.getElementById('customerPayForm');
if (customerPayForm) {
  customerPayForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const merchant = document.getElementById('payMerchant').value.trim();
    const amount = Number(document.getElementById('payAmount').value);
    const now = new Date();

    pendingMerchantName = merchant;
    pendingAmountValue = amount;

    const payload = {
      userId: document.getElementById('payUserId').value.trim(),
      deviceId: getOrCreateBrowserDeviceId(),
      amount,
      merchantCategory: document.getElementById('payCategory').value,
      location: liveTelemetry.location,
      deviceType: liveTelemetry.deviceType,
      hourOfDay: now.getHours(),
      accountAgeDays: null
    };

    try {
      const res = await fetch('/api/transactions/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await res.json();
      if (!res.ok) {
        alert(result.message || 'Analysis failed on server.');
        return;
      }

      document.getElementById('payEmptyState').classList.add('hidden');
      document.getElementById('payOutcomeCard').classList.remove('hidden');

      const banner = document.getElementById('payStatusBanner');
      const title = document.getElementById('payStatusTitle');
      const msg = document.getElementById('payStatusMsg');
      const otpBox = document.getElementById('stepUpOtpBox');
      const otpErr = document.getElementById('otpErrorMsg');

      otpErr.classList.add('hidden');
      document.getElementById('otpInput').value = '';

      banner.className = 'pay-banner ' + result.status.toLowerCase();
      if (result.status === 'Safe') {
        otpBox.classList.add('hidden');
        title.textContent = 'Payment Auto-Approved';
        msg.textContent = '₹' + amount.toLocaleString('en-IN') + ' paid to ' + merchant + '. Cleared automatically.';
      } else if (result.status === 'Suspicious') {
        pendingOtpTxId = result._id;
        generatedOtp = String(Math.floor(100000 + Math.random() * 900000));
        document.getElementById('demoOtpCode').textContent = 'SMS OTP: ' + generatedOtp;
        otpBox.classList.remove('hidden');
        title.textContent = 'Step-Up Verification Required';
        msg.textContent = 'Unusual activity detected. Verify with OTP below to auto-approve instantly.';
      } else {
        otpBox.classList.add('hidden');
        title.textContent = 'Payment Auto-Blocked (Fraudulent)';
        msg.textContent = 'High-risk fraud pattern detected. Transaction blocked and device blacklisted automatically.';
      }

      document.getElementById('payResId').textContent = result.transactionId;
      document.getElementById('payResMerchant').textContent = merchant;
      document.getElementById('payResAmount').textContent = '₹' + amount.toLocaleString('en-IN');
      document.getElementById('payResCategory').textContent = result.status;
      document.getElementById('payResScore').textContent = result.riskScore + ' / 100';

      loadDashboard();
    } catch (err) {
      alert('Payment failed to reach server.');
    }
  });
}

// Handle Automated OTP Verify
const verifyOtpBtn = document.getElementById('verifyOtpBtn');
if (verifyOtpBtn) {
  verifyOtpBtn.addEventListener('click', async () => {
    const entered = document.getElementById('otpInput').value.trim();
    const otpErr = document.getElementById('otpErrorMsg');
    otpErr.classList.add('hidden');

    if (!pendingOtpTxId) {
      otpErr.textContent = 'No pending transaction found. Please submit a payment first.';
      otpErr.classList.remove('hidden');
      return;
    }

    if (entered !== generatedOtp) {
      otpErr.textContent = 'Invalid OTP. Please enter ' + generatedOtp;
      otpErr.classList.remove('hidden');
      return;
    }

    try {
      const res = await fetch('/api/transactions/' + pendingOtpTxId + '/step-up', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'verify' })
      });
      const updated = await res.json();
      if (!res.ok) {
        otpErr.textContent = updated.message || 'Verification failed on server. Restart npm start.';
        otpErr.classList.remove('hidden');
        return;
      }

      document.getElementById('stepUpOtpBox').classList.add('hidden');
      document.getElementById('payStatusBanner').className = 'pay-banner safe';
      document.getElementById('payStatusTitle').textContent = 'OTP Verified — Payment Completed';
      document.getElementById('payStatusMsg').textContent = '₹' + pendingAmountValue.toLocaleString('en-IN') + ' paid to ' + pendingMerchantName + '. Auto-resolved with zero banker effort.';
      document.getElementById('payResCategory').textContent = updated.status + ' (OTP Verified)';
      pendingOtpTxId = null;
      loadDashboard();
    } catch (err) {
      otpErr.textContent = 'Server connection error. Make sure npm start is running.';
      otpErr.classList.remove('hidden');
    }
  });
}

// Handle Customer Deny ("Not Me")
const denyTxBtn = document.getElementById('denyTxBtn');
if (denyTxBtn) {
  denyTxBtn.addEventListener('click', async () => {
    const otpErr = document.getElementById('otpErrorMsg');
    otpErr.classList.add('hidden');

    if (!pendingOtpTxId) return;

    try {
      const res = await fetch('/api/transactions/' + pendingOtpTxId + '/step-up', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'deny' })
      });
      const updated = await res.json();
      if (!res.ok) {
        otpErr.textContent = updated.message || 'Could not block transaction.';
        otpErr.classList.remove('hidden');
        return;
      }

      document.getElementById('stepUpOtpBox').classList.add('hidden');
      document.getElementById('payStatusBanner').className = 'pay-banner fraudulent';
      document.getElementById('payStatusTitle').textContent = 'Payment Blocked & Device Blacklisted';
      document.getElementById('payStatusMsg').textContent = 'You denied this payment. Device added to Watchlist automatically.';
      document.getElementById('payResCategory').textContent = updated.status + ' (Customer Denied)';
      pendingOtpTxId = null;
      loadDashboard();
    } catch (err) {
      otpErr.textContent = 'Server connection error.';
      otpErr.classList.remove('hidden');
    }
  });
}

// --- ML MODEL STATUS & LIVE RETRAINING ---
async function loadMlStatus() {
  try {
    const res = await fetch('/api/ml/status');
    const meta = await res.json();
    const el = document.getElementById('mlStatusText');
    if (el && meta.trained) {
      el.textContent = `Trained on ${meta.totalSamples} samples (${meta.kaggleSamples} Kaggle + ${meta.dbSamples} MongoDB)`;
    }
  } catch (err) {
    console.error('ML status error:', err);
  }
}

const retrainBtn = document.getElementById('retrainMlBtn');
if (retrainBtn) {
  retrainBtn.addEventListener('click', async () => {
    retrainBtn.textContent = 'Retraining...';
    try {
      const res = await fetch('/api/ml/retrain', { method: 'POST' });
      const meta = await res.json();
      document.getElementById('mlStatusText').textContent =
        `Retrained on ${meta.totalSamples} samples (${meta.kaggleSamples} Kaggle + ${meta.dbSamples} MongoDB)`;
    } catch (err) {
      alert('Retraining failed. Check server terminal.');
    }
    retrainBtn.textContent = 'Retrain on Live Data';
  });
}