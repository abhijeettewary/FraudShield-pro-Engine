let isRegister = false;
let allTx = [];
let statusChart = null;
let catChart = null;
let visNetworkInstance = null;
let activeDossier = null;

function switchView(viewName) {
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === viewName));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + viewName));
  if (viewName === 'graph') loadFraudGraph();
  if (viewName === 'ato') loadAtoIntel();
}

async function checkSession() {
  try {
    const res = await fetch('/api/auth/me');
    if (!res.ok) return;
    const user = await res.json();
    if (user.role === 'analyst') {
      document.getElementById('analystInfo').textContent = `${user.name} (${user.email})`;
      showApp();
    }
  } catch {}
}

function showApp() {
  document.getElementById('authSection').classList.add('hidden');
  document.getElementById('appSection').classList.remove('hidden');
  loadData();
  loadMlStatus();
  loadEvaluation();
}

async function loadData() {
  const res = await fetch('/api/transactions');
  if (res.status === 401 || res.status === 403) {
    document.getElementById('appSection').classList.add('hidden');
    document.getElementById('authSection').classList.remove('hidden');
    return;
  }
  const data = await res.json();
  allTx = data.transactions || [];

  document.getElementById('kpiTotal').textContent = data.metrics.totalCount;
  document.getElementById('kpiFraud').textContent = data.metrics.fraudCount;
  document.getElementById('kpiSusp').textContent = data.metrics.suspiciousCount;
  document.getElementById('kpiSaved').textContent = '₹' + data.metrics.blockedAmount.toLocaleString('en-IN');

  renderCharts(data.metrics, data.categoryStats || {});
  renderAudit();
  renderWatchlist(data.watchlist || []);
  populateInvestigatorSelect();
}

function populateInvestigatorSelect() {
  const sel = document.getElementById('invTxSelect');
  const current = sel.value;
  sel.innerHTML = '<option value="">-- Select a transaction --</option>' +
    allTx.map(t => `<option value="${t._id}">${t.transactionId} • ${t.userId} • ₹${t.amount.toLocaleString('en-IN')} (${t.status})</option>`).join('');
  if (current) sel.value = current;
}

function renderCharts(m, cats) {
  if (statusChart) statusChart.destroy();
  statusChart = new Chart(document.getElementById('statusChart'), {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Suspicious', 'Fraudulent'],
      datasets: [{ data: [m.safeCount, m.suspiciousCount, m.fraudCount], backgroundColor: ['#059669', '#f59e0b', '#dc2626'], borderWidth: 0 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#334155', font: { weight: '600' } } } }
    }
  });

  if (catChart) catChart.destroy();
  catChart = new Chart(document.getElementById('catChart'), {
    type: 'bar',
    data: {
      labels: Object.keys(cats).length ? Object.keys(cats) : ['None'],
      datasets: [{ label: 'Flagged', data: Object.keys(cats).length ? Object.values(cats) : [0], backgroundColor: '#047857', borderRadius: 6 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#334155' } } },
      scales: {
        y: { ticks: { color: '#475569' }, grid: { color: '#f1f5f9' } },
        x: { ticks: { color: '#475569' }, grid: { display: false } }
      }
    }
  });
}

function renderAudit() {
  document.getElementById('auditBody').innerHTML = allTx.map(t => `
    <tr>
      <td style="font-family:monospace;font-weight:600;">${t.transactionId}</td>
      <td><strong>${t.userId}</strong><br><span style="font-size:0.74rem;color:#64748b;">${t.deviceId || 'N/A'}</span></td>
      <td>₹${t.amount.toLocaleString('en-IN')}</td>
      <td><strong>${t.riskScore}/100</strong></td>
      <td><span class="badge badge-${t.status}">${t.status}</span></td>
      <td style="font-size:0.78rem;color:#475569;">${t.analystReview}</td>
      <td><button class="btn-secondary" style="padding:4px 10px;font-size:0.74rem;" onclick="openInvestigator('${t._id}')">Investigate</button></td>
    </tr>
  `).join('');
}

window.openInvestigator = async (txId) => {
  switchView('investigator');
  document.getElementById('invTxSelect').value = txId;
  await loadInvestigation(txId);
};

async function loadInvestigation(txId) {
  if (!txId) {
    document.getElementById('invEmpty').classList.remove('hidden');
    document.getElementById('invContent').classList.add('hidden');
    document.getElementById('downloadSarBtn').classList.add('hidden');
    return;
  }
  const res = await fetch('/api/analyst/investigate/' + txId);
  if (!res.ok) return;
  const d = await res.json();
  activeDossier = d;

  document.getElementById('invEmpty').classList.add('hidden');
  document.getElementById('invContent').classList.remove('hidden');
  document.getElementById('downloadSarBtn').classList.remove('hidden');

  const tx = d.transaction;
  document.getElementById('invTitle').textContent = `${tx.transactionId} — ₹${tx.amount.toLocaleString('en-IN')} (${tx.userId})`;
  document.getElementById('invMeta').textContent = `Device: ${tx.deviceId} • ${tx.location} (${tx.deviceType}) • ${tx.merchantCategory} • Status: ${tx.analystReview}`;
  const badge = document.getElementById('invBadge');
  badge.className = 'badge badge-' + tx.status;
  badge.textContent = `${tx.status} • ${tx.riskScore}/100`;

  document.getElementById('invSummary').textContent = d.summary;

  document.getElementById('invAttributions').innerHTML = d.attributions.map(a => {
    const pct = Math.min(100, Math.abs(a.impact) * 2.5);
    const barColor = a.direction === 'risk' ? '#dc2626' : '#047857';
    return `
      <div>
        <div style="display:flex;justify-content:space-between;font-size:0.82rem;margin-bottom:4px;">
          <strong style="color:#0f172a;">${a.label}</strong>
          <span style="color:${barColor};font-weight:700;">${a.impact > 0 ? '+' : ''}${a.impact} pts</span>
        </div>
        <div style="height:8px;background:#e2e8f0;border-radius:999px;overflow:hidden;margin-bottom:4px;">
          <div style="width:${pct}%;height:100%;background:${barColor};"></div>
        </div>
        <div style="font-size:0.75rem;color:#475569;">${a.detail}</div>
      </div>`;
  }).join('');

  document.getElementById('invCounterfactuals').innerHTML = d.counterfactuals.map(c => `<li>${c}</li>`).join('');
  document.getElementById('invRecs').innerHTML = d.recommendations.map(r => `<li>${r}</li>`).join('');
}

document.getElementById('invTxSelect').onchange = (e) => loadInvestigation(e.target.value);

document.getElementById('downloadSarBtn').onclick = () => {
  if (!activeDossier) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([activeDossier.sarText], { type: 'text/plain' }));
  a.download = `SAR_${activeDossier.transaction.transactionId}.txt`;
  a.click();
};

async function resolveCase(decision) {
  if (!activeDossier) return;
  const txId = activeDossier.transaction._id;
  const res = await fetch(`/api/analyst/cases/${txId}/resolve`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision })
  });
  const data = await res.json();
  if (res.ok) {
    alert(data.message);
    await loadData();
    await loadInvestigation(txId);
  }
}

document.getElementById('btnConfirmFraud').onclick = () => resolveCase('confirm_fraud');
document.getElementById('btnFalsePos').onclick = () => resolveCase('false_positive');

function renderWatchlist(list) {
  document.getElementById('watchBody').innerHTML = list.length
    ? list.map(w => `
      <tr>
        <td style="text-transform:uppercase;font-weight:600;">${w.type}</td>
        <td style="font-family:monospace;">${w.value}</td>
        <td><span class="badge ${w.action === 'watchlist' ? 'badge-Fraudulent' : 'badge-Safe'}">${w.action}</span></td>
        <td><button class="btn-secondary" onclick="removeWatch('${w._id}')">Remove</button></td>
      </tr>`).join('')
    : '<tr><td colspan="4" style="color:#64748b;">No learned rules yet.</td></tr>';
}

window.removeWatch = async (id) => {
  await fetch('/api/watchlist/' + id, { method: 'DELETE' });
  loadData();
};

async function loadMlStatus() {
  const res = await fetch('/api/ml/status');
  if (!res.ok) return;
  const m = await res.json();
  document.getElementById('mlStatus').textContent = `Trained on ${m.totalSamples} samples (${m.kaggleSamples} Kaggle + ${m.dbSamples} MongoDB)`;
}

async function loadEvaluation() {
  const res = await fetch('/api/ml/evaluation');
  if (!res.ok) return;
  const { evaluation } = await res.json();
  if (!evaluation) return;

  document.getElementById('evalSummary').textContent =
    `Evaluated on ${evaluation.testSize} held-out chronological transactions (Trained on ${evaluation.trainSize} samples, zero data leakage).`;

  const rows = [
    ['1. Rule-Only Detection', evaluation.models.ruleOnly],
    ['2. ML-Only (Random Forest)', evaluation.models.mlOnly],
    ['3. Legacy 50/50 Hybrid', evaluation.models.legacyHybrid],
    ['4. Improved Weighted Hybrid', evaluation.models.improvedHybrid]
  ];

  document.getElementById('evalBody').innerHTML = rows.map(([name, m]) => `
    <tr>
      <td><strong>${name}</strong></td>
      <td>${m.accuracy}%</td>
      <td>${m.precision}%</td>
      <td>${m.recall}%</td>
      <td style="color:#047857;font-weight:700;">${m.f1}%</td>
      <td>${m.fpr}%</td>
      <td style="font-family:monospace;font-size:0.78rem;color:#475569;">TP:${m.confusionMatrix.tp} FP:${m.confusionMatrix.fp} TN:${m.confusionMatrix.tn} FN:${m.confusionMatrix.fn}</td>
    </tr>
  `).join('');
}

async function loadFraudGraph() {
  try {
    const res = await fetch('/api/analyst/graph');
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('gNodes').textContent = data.summary.totalNodes;
    document.getElementById('gRings').textContent = data.summary.deviceRingCount;
    document.getElementById('gMules').textContent = data.summary.muleCount;
    document.getElementById('gLoops').textContent = data.summary.circularCount;

    const alertsEl = document.getElementById('graphAlerts');
    alertsEl.innerHTML = data.alerts.length
      ? data.alerts.map(a => `
          <div style="padding:10px 12px;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:8px;background:#f8fafc;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
              <strong style="color:#0f172a;">${a.title}</strong>
              <span class="badge ${a.severity === 'high' ? 'badge-Fraudulent' : 'badge-Suspicious'}">${a.severity}</span>
            </div>
            <div style="color:#475569;line-height:1.4;">${a.description}</div>
          </div>`).join('')
      : '<p style="color:#64748b;">No suspicious networks detected yet.</p>';

    const nodeMap = new Map();
    const visNodes = data.nodes.map(n => {
      nodeMap.set(n.id, n);
      const color =
        n.riskLevel === 'high'
          ? { background: '#dc2626', border: '#991b1b' }
          : n.riskLevel === 'medium'
          ? { background: '#d97706', border: '#b45309' }
          : n.type === 'device'
          ? { background: '#0284c7', border: '#0369a1' }
          : { background: '#047857', border: '#065f46' };

      return {
        id: n.id,
        label: n.label,
        shape: n.type === 'device' ? 'diamond' : 'dot',
        size: n.riskLevel === 'high' ? 22 : 16,
        color,
        font: { color: '#0f172a', size: 11, face: 'Inter' }
      };
    });

    const visEdges = data.edges.map(e => ({
      from: e.from,
      to: e.to,
      label: e.label,
      arrows: e.arrows || '',
      dashes: Boolean(e.dashes),
      color: { color: e.type === 'transfer' ? '#047857' : '#94a3b8' },
      font: { color: '#475569', size: 10, strokeWidth: 2, strokeColor: '#f8fafc' }
    }));

    const container = document.getElementById('networkCanvas');
    if (visNetworkInstance) visNetworkInstance.destroy();
    visNetworkInstance = new vis.Network(
      container,
      { nodes: new vis.DataSet(visNodes), edges: new vis.DataSet(visEdges) },
      {
        physics: { stabilization: true, barnesHut: { gravitationalConstant: -3000 } },
        interaction: { hover: true }
      }
    );

    visNetworkInstance.on('click', (params) => {
      if (!params.nodes.length) return;
      const n = nodeMap.get(params.nodes[0]);
      if (!n) return;
      const insp = document.getElementById('nodeInspector');
      if (n.type === 'account') {
        insp.innerHTML = `
          <div style="margin-bottom:8px;"><strong style="color:#0f172a;font-size:0.95rem;">Account: ${n.id}</strong></div>
          <div style="line-height:1.7;color:#334155;">
            <div>Risk Level: <span class="badge ${n.riskLevel === 'high' ? 'badge-Fraudulent' : n.riskLevel === 'medium' ? 'badge-Suspicious' : 'badge-Safe'}">${n.riskLevel.toUpperCase()}</span></div>
            <div>Transactions: <strong>${n.meta.txCount}</strong> (Fraud: <strong style="color:#dc2626;">${n.meta.fraudCount}</strong>)</div>
            <div>Total Volume: <strong>₹${n.meta.totalVolume.toLocaleString('en-IN')}</strong></div>
            <div>Linked Devices: <span style="font-family:monospace;">${n.meta.linkedDevices.join(', ') || 'None'}</span></div>
          </div>`;
      } else {
        insp.innerHTML = `
          <div style="margin-bottom:8px;"><strong style="color:#0f172a;font-size:0.95rem;">Device: ${n.id}</strong></div>
          <div style="line-height:1.7;color:#334155;">
            <div>Risk Level: <span class="badge ${n.riskLevel === 'high' ? 'badge-Fraudulent' : n.riskLevel === 'medium' ? 'badge-Suspicious' : 'badge-Safe'}">${n.riskLevel.toUpperCase()}</span></div>
            <div>Fraud Hits: <strong style="color:#dc2626;">${n.meta.fraudHits}</strong></div>
            <div>Linked Accounts (${n.meta.linkedAccounts.length}):<br><span style="font-family:monospace;">${n.meta.linkedAccounts.join(', ')}</span></div>
          </div>`;
      }
    });
  } catch (err) {
    console.error('Graph load error:', err);
  }
}

async function loadAtoIntel() {
  try {
    const res = await fetch('/api/analyst/ato');
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('atoDevTotal').textContent = data.summary.totalDevices;
    document.getElementById('atoDevRisk').textContent = data.summary.highRiskDevices;
    document.getElementById('atoAlertsCount').textContent = data.summary.atoAlerts;
    document.getElementById('atoRestrictedCount').textContent = data.summary.restrictedCount;

    document.getElementById('atoDeviceBody').innerHTML = data.devices.length
      ? data.devices.map(d => `
          <tr>
            <td style="font-family:monospace;font-weight:600;">${d.deviceId}</td>
            <td style="font-size:0.76rem;color:#475569;">${d.associatedAccounts.join(', ') || 'None'}</td>
            <td><span style="color:#047857;font-weight:600;">${d.legitimateCount}</span> / <span style="color:#dc2626;font-weight:600;">${d.fraudIncidents}</span> / <span style="color:#d97706;font-weight:600;">${d.failedLoginCount}</span></td>
            <td><strong>${d.riskScore}/100</strong></td>
            <td><span class="badge ${d.trustStatus === 'Blacklisted' ? 'badge-Fraudulent' : d.trustStatus === 'Suspicious' ? 'badge-Suspicious' : 'badge-Safe'}">${d.trustStatus}</span></td>
            <td>
              <button class="btn-secondary" style="padding:4px 8px;font-size:0.74rem;" onclick="setDevStatus('${d.deviceId}','Trusted')">Trust</button>
              <button class="btn-secondary" style="padding:4px 8px;font-size:0.74rem;color:#dc2626;border-color:#fecaca;" onclick="setDevStatus('${d.deviceId}','Blacklisted')">Blacklist</button>
            </td>
          </tr>`).join('')
      : '<tr><td colspan="6" style="color:#64748b;">No device reputation profiles recorded yet.</td></tr>';

    document.getElementById('atoEventsBody').innerHTML = data.events.length
      ? data.events.map(e => `
          <tr>
            <td style="font-family:monospace;font-weight:600;">${e.accountNumber}</td>
            <td><strong>${e.category.replace('_', ' ')}</strong></td>
            <td><span class="badge ${e.severity === 'high' ? 'badge-Fraudulent' : 'badge-Suspicious'}">${e.severity}</span></td>
            <td style="font-size:0.8rem;color:#334155;">${e.message}</td>
          </tr>`).join('')
      : '<tr><td colspan="4" style="color:#64748b;">No security events recorded yet.</td></tr>';
  } catch (err) {
    console.error('ATO load error:', err);
  }
}

window.setDevStatus = async (deviceId, trustStatus) => {
  await fetch(`/api/analyst/devices/${encodeURIComponent(deviceId)}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ trustStatus })
  });
  loadAtoIntel();
};

document.getElementById('refreshGraphBtn').onclick = loadFraudGraph;
document.getElementById('refreshAtoBtn').onclick = loadAtoIntel;

document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.onclick = () => switchView(btn.dataset.view);
});

document.getElementById('retrainBtn').onclick = async () => {
  const res = await fetch('/api/ml/retrain', { method: 'POST' });
  const m = await res.json();
  document.getElementById('mlStatus').textContent = `Retrained on ${m.totalSamples} samples (${m.kaggleSamples} Kaggle + ${m.dbSamples} MongoDB)`;
  loadEvaluation();
};

document.getElementById('exportCsvBtn').onclick = () => {
  if (!allTx.length) return;
  const rows = ['TXN,User,Device,Amount,RiskScore,Status,Action'].concat(
    allTx.map(t => [t.transactionId, t.userId, t.deviceId, t.amount, t.riskScore, t.status, t.analystReview].join(','))
  );
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([rows.join('\n')], { type: 'text/csv' }));
  a.download = 'fraudshield_audit.csv';
  a.click();
};

document.getElementById('tabLogin').onclick = () => {
  isRegister = false;
  document.getElementById('tabLogin').classList.add('active');
  document.getElementById('tabRegister').classList.remove('active');
  document.getElementById('nameWrap').classList.add('hidden');
  document.getElementById('authBtn').textContent = 'Sign In to SOC';
};

document.getElementById('tabRegister').onclick = () => {
  isRegister = true;
  document.getElementById('tabRegister').classList.add('active');
  document.getElementById('tabLogin').classList.remove('active');
  document.getElementById('nameWrap').classList.remove('hidden');
  document.getElementById('authBtn').textContent = 'Register Analyst';
};

document.getElementById('authForm').onsubmit = async (e) => {
  e.preventDefault();
  const errEl = document.getElementById('authError');
  errEl.classList.add('hidden');
  const url = isRegister ? '/api/auth/analyst/register' : '/api/auth/analyst/login';
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: document.getElementById('authName').value,
      email: document.getElementById('authEmail').value,
      password: document.getElementById('authPassword').value
    })
  });
  const data = await res.json();
  if (!res.ok) {
    errEl.textContent = data.message || 'Authentication failed.';
    errEl.classList.remove('hidden');
    return;
  }
  document.getElementById('analystInfo').textContent = `${data.name} (${data.email})`;
  showApp();
};

document.getElementById('logoutBtn').onclick = async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
  location.reload();
};

checkSession();