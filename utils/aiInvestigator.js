function buildAttribution(tx, deviceRep) {
  const factors = [];

  // 1. ML Model Contribution
  const mlPoints = Math.round((tx.mlProbability || 0) * 0.4);
  if (mlPoints > 0) {
    factors.push({
      label: 'Random Forest ML Model',
      impact: mlPoints,
      direction: 'risk',
      detail: `Model predicted ${tx.mlProbability || 0}% fraud probability based on amount, hour, category, and account age.`
    });
  }

  // 2. Behavioral / Z-Score
  if ((tx.zScore || 0) >= 2.0) {
    const pts = tx.zScore >= 3.0 ? 22 : 12;
    factors.push({
      label: 'Behavioral Spending Anomaly',
      impact: pts,
      direction: 'risk',
      detail: `Transaction deviated ${tx.zScore}σ from the customer's historical spending baseline.`
    });
  }

  // 3. Fraud Ring / Shared Device
  const ringCount = (tx.ringLinkedUsers || []).length;
  if (ringCount >= 1) {
    const pts = ringCount >= 2 ? 32 : 16;
    factors.push({
      label: 'Device Graph / Fraud Ring',
      impact: pts,
      direction: 'risk',
      detail: `Device ${tx.deviceId} is shared across ${ringCount + 1} distinct accounts.`
    });
  }

  // 4. Network / Location / VPN
  if (tx.deviceType === 'Unknown/VPN') {
    factors.push({
      label: 'VPN / Proxy Anonymizer',
      impact: 15,
      direction: 'risk',
      detail: 'Connection originated from a masked VPN or proxy network.'
    });
  }
  if ((tx.location || 'India').toLowerCase() !== 'india') {
    factors.push({
      label: 'Cross-Border / Foreign Geo',
      impact: 12,
      direction: 'risk',
      detail: `Originating location (${tx.location}) differs from domestic baseline.`
    });
  }

  // 5. High-Risk Category or Odd Hour
  if (['Crypto', 'Gambling', 'Wire Transfer', 'Luxury Goods'].includes(tx.merchantCategory)) {
    factors.push({
      label: 'High-Risk Merchant Category',
      impact: 10,
      direction: 'risk',
      detail: `Category "${tx.merchantCategory}" carries elevated chargeback and laundering risk.`
    });
  }
  if (tx.hourOfDay >= 0 && tx.hourOfDay <= 5) {
    factors.push({
      label: 'Odd-Hour Activity',
      impact: 8,
      direction: 'risk',
      detail: `Initiated at ${String(tx.hourOfDay).padStart(2, '0')}:00 local time.`
    });
  }

  // 6. Device Reputation
  if (deviceRep) {
    if (deviceRep.trustStatus === 'Blacklisted') {
      factors.push({
        label: 'Blacklisted Device Reputation',
        impact: 25,
        direction: 'risk',
        detail: `${deviceRep.deviceId} has ${deviceRep.fraudIncidents} prior fraud incident(s).`
      });
    } else if (deviceRep.trustStatus === 'Trusted') {
      factors.push({
        label: 'Trusted Device History',
        impact: -15,
        direction: 'safe',
        detail: `${deviceRep.deviceId} has ${deviceRep.legitimateCount} verified legitimate transactions.`
      });
    }
  }

  // Fallback if clean transaction
  if (factors.length === 0) {
    factors.push({
      label: 'Normal Behavioral Baseline',
      impact: -10,
      direction: 'safe',
      detail: 'Amount, location, device, and timing align with standard customer behavior.'
    });
  }

  return factors.sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact));
}

function buildCounterfactuals(tx, deviceRep) {
  const whatIfs = [];

  if ((tx.ringLinkedUsers || []).length >= 1) {
    whatIfs.push(
      `If this payment had been initiated from a dedicated personal device instead of shared device ${tx.deviceId}, the risk score would drop by ~25–35 points.`
    );
  }
  if (tx.deviceType === 'Unknown/VPN') {
    whatIfs.push(
      'Disabling the VPN/Proxy network would reduce the network risk sub-score by ~15 points.'
    );
  }
  if (tx.hourOfDay >= 0 && tx.hourOfDay <= 5) {
    whatIfs.push(
      'Executing this transfer during standard daytime hours (08:00–22:00) would remove the odd-hour anomaly penalty.'
    );
  }
  if ((tx.zScore || 0) >= 2.0) {
    whatIfs.push(
      'A transaction amount closer to the customer’s historical average would eliminate the Z-score behavioral spike.'
    );
  }
  if (deviceRep && deviceRep.trustStatus === 'Blacklisted') {
    whatIfs.push(
      `Clearing device ${deviceRep.deviceId} from the blacklist would remove the +25 device reputation penalty.`
    );
  }

  if (whatIfs.length === 0) {
    whatIfs.push('No major risk overrides were triggered; this transaction already falls within safe operating parameters.');
  }

  return whatIfs;
}

function generateInvestigationDossier({ tx, deviceRep, recentEvents = [], userHistoryCount = 0 }) {
  const attributions = buildAttribution(tx, deviceRep);
  const counterfactuals = buildCounterfactuals(tx, deviceRep);
  const topDriver = attributions[0];

  // Executive Summary Narrative
  let summary = '';
  if (tx.status === 'Fraudulent') {
    summary = `Transaction ${tx.transactionId} (₹${tx.amount.toLocaleString('en-IN')}) by ${tx.userId} was classified as HIGH-RISK FRAUD (${tx.riskScore}/100). The primary driver was "${topDriver.label}" (${topDriver.detail}). Immediate confirmation and device/account containment are recommended.`;
  } else if (tx.status === 'Suspicious') {
    summary = `Transaction ${tx.transactionId} (₹${tx.amount.toLocaleString('en-IN')}) by ${tx.userId} triggered a MEDIUM-RISK alert (${tx.riskScore}/100). The strongest signal was "${topDriver.label}". Review customer verification status and recent login events before clearing.`;
  } else {
    summary = `Transaction ${tx.transactionId} (₹${tx.amount.toLocaleString('en-IN')}) by ${tx.userId} cleared with LOW RISK (${tx.riskScore}/100). Behavioral, device, and ML signals remained within acceptable thresholds across ${userHistoryCount} historical account transactions.`;
  }

  // Recommended SOC Playbook
  const recommendations = [];
  if (tx.status === 'Fraudulent') {
    recommendations.push('Confirm Fraud to permanently train the Random Forest model and keep the device blacklisted.');
    if ((tx.ringLinkedUsers || []).length >= 1) {
      recommendations.push(`Inspect linked accounts (${tx.ringLinkedUsers.join(', ')}) in the Fraud Network Graph for coordinated mule activity.`);
    }
    recommendations.push('Export the SAR (Suspicious Activity Report) dossier for compliance archiving.');
  } else if (tx.status === 'Suspicious') {
    recommendations.push('Verify whether the customer completed Step-Up OTP or reported the transaction as unauthorized.');
    recommendations.push('Mark as False Positive (Safe) if the customer confirms legitimacy to reduce future friction.');
  } else {
    recommendations.push('No action required unless the customer submits an unauthorized transaction dispute.');
  }

  // Plain-text SAR Report for export
  const sarText = [
    '====================================================',
    'FRAUDSHIELD PRO — SUSPICIOUS ACTIVITY REPORT (SAR)',
    '====================================================',
    `Generated At     : ${new Date().toISOString()}`,
    `Transaction ID   : ${tx.transactionId}`,
    `Account / User   : ${tx.userId}`,
    `Amount           : INR ${tx.amount.toLocaleString('en-IN')}`,
    `Category         : ${tx.merchantCategory}`,
    `Location / Net   : ${tx.location} (${tx.deviceType})`,
    `Device ID        : ${tx.deviceId}`,
    `Hybrid Risk Score: ${tx.riskScore}/100 (${tx.status.toUpperCase()})`,
    `ML Confidence    : ${tx.mlProbability || 0}%`,
    `Current Action   : ${tx.analystReview}`,
    '',
    '--- EXECUTIVE SUMMARY ---',
    summary,
    '',
    '--- TOP RISK ATTRIBUTIONS ---',
    ...attributions.map((a, i) => `${i + 1}. ${a.label} (${a.impact > 0 ? '+' : ''}${a.impact} pts): ${a.detail}`),
    '',
    '--- FLAGGED ENGINE SIGNALS ---',
    ...(tx.flaggedReasons || []).map((r) => `- ${r}`),
    '',
    '--- COUNTERFACTUAL ANALYSIS ---',
    ...counterfactuals.map((c) => `- ${c}`),
    '',
    '--- RECOMMENDED SOC ACTIONS ---',
    ...recommendations.map((r) => `- ${r}`),
    '===================================================='
  ].join('\n');

  return {
    transaction: tx,
    deviceReputation: deviceRep || null,
    relatedSecurityEvents: recentEvents,
    summary,
    attributions,
    counterfactuals,
    recommendations,
    sarText
  };
}

module.exports = { generateInvestigationDossier };