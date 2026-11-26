const { computeFeatures } = require('./featureEngineer');

// Configurable risk policy (updatable by Analysts in SOC)
let riskPolicy = {
  suspiciousThreshold: 40,
  fraudThreshold: 65,
  weights: {
    ml: 0.40,
    behavioral: 0.25,
    velocity: 0.15,
    networkDevice: 0.20
  }
};

function getRiskPolicy() {
  return riskPolicy;
}

function updateRiskPolicy(newPolicy) {
  if (newPolicy.suspiciousThreshold) riskPolicy.suspiciousThreshold = Number(newPolicy.suspiciousThreshold);
  if (newPolicy.fraudThreshold) riskPolicy.fraudThreshold = Number(newPolicy.fraudThreshold);
  return riskPolicy;
}

function evaluateTransaction(tx, context = {}, mlProbability = 0) {
  const f = computeFeatures(tx, context);
  const reasons = [];

  // 1. Behavioral Sub-Score (0-100)
  let behavioralScore = 0;
  if (f.zScore >= 3.0) {
    behavioralScore += 55;
    reasons.push(`Extreme behavioral spending spike (Z-Score: ${f.zScore}σ, ${f.amountDeviationRatio}x normal)`);
  } else if (f.zScore >= 2.0) {
    behavioralScore += 30;
    reasons.push(`Elevated spending deviation (Z-Score: ${f.zScore}σ)`);
  }
  if (f.balanceDepletionRatio >= 0.8) {
    behavioralScore += 35;
    reasons.push(`Rapid account draining (${Math.round(f.balanceDepletionRatio * 100)}% of balance)`);
  }
  if (f.isOddHour) {
    behavioralScore += 20;
    reasons.push(`Unusual transaction hour (${f.hourOfDay}:00)`);
  }
  if (f.isHighRiskCat) {
    behavioralScore += 25;
    reasons.push(`High-risk merchant category (${tx.merchantCategory})`);
  }
  if (f.isNewBeneficiary) {
    behavioralScore += 20;
    reasons.push('New or unestablished beneficiary');
  }
  behavioralScore = Math.min(100, behavioralScore);

  // 2. Velocity & Structuring Sub-Score (0-100)
  let velocityScore = 0;
  if (f.txPerMin >= 3) {
    velocityScore += 70;
    reasons.push(`High-frequency burst (${f.txPerMin} transactions in 1 min)`);
  } else if (f.txPerHour >= 6) {
    velocityScore += 45;
    reasons.push(`Elevated hourly velocity (${f.txPerHour} transactions in 1 hr)`);
  }
  if (f.microTxCount1Hour >= 4) {
    velocityScore += 40;
    reasons.push(`Multiple small structuring transactions (${f.microTxCount1Hour} in 1 hr)`);
  }
  velocityScore = Math.min(100, velocityScore);

  // 3. Device, Location & Network Sub-Score (0-100)
  let networkDeviceScore = 0;
  if (f.isVPN) {
    networkDeviceScore += 45;
    reasons.push('VPN / Proxy network detected');
  }
  if (f.isForeign) {
    networkDeviceScore += 35;
    reasons.push(`Foreign location (${tx.location})`);
  }
  if (f.impossibleTravel) {
    networkDeviceScore += 60;
    reasons.push('Impossible travel: country changed within 1 hour');
  }
  if (f.isNewDevice) {
    networkDeviceScore += 25;
    reasons.push('Unfamiliar device fingerprint');
  }
  if (f.accountAgeDays <= 3) {
    networkDeviceScore += 25;
    reasons.push(`Newly created account (${f.accountAgeDays} days old)`);
  }
  if (f.ringLinkedCount >= 2) {
    networkDeviceScore += 80;
    reasons.push(`Fraud Ring detected: device linked to ${f.ringLinkedCount + 1} accounts`);
  } else if (f.ringLinkedCount === 1) {
    networkDeviceScore += 45;
    reasons.push('Shared device linked to another account');
  }
  if (f.isWatchlisted) {
    networkDeviceScore += 40;
    reasons.push('Entity matched Self-Learning Watchlist');
  }
  if (f.isTrusted && !f.isWatchlisted) {
    networkDeviceScore = Math.max(0, networkDeviceScore - 25);
    reasons.push('Trusted customer pattern (-25 network risk)');
  }
  networkDeviceScore = Math.min(100, networkDeviceScore);

  // 4. Weighted Hybrid Aggregation
  const w = riskPolicy.weights;
  let finalScore = Math.round(
    mlProbability * w.ml +
    behavioralScore * w.behavioral +
    velocityScore * w.velocity +
    networkDeviceScore * w.networkDevice
  );

  // 5. Policy-Based Critical Overrides (Low ML cannot cancel confirmed high-severity threats)
  if (f.ringLinkedCount >= 2 || f.impossibleTravel) {
    finalScore = Math.max(finalScore, 78);
  } else if (f.ringLinkedCount === 1 || (f.isWatchlisted && f.isVPN)) {
    finalScore = Math.max(finalScore, 50);
  }

  finalScore = Math.min(100, Math.max(0, finalScore));
  const status =
    finalScore >= riskPolicy.fraudThreshold
      ? 'Fraudulent'
      : finalScore >= riskPolicy.suspiciousThreshold
      ? 'Suspicious'
      : 'Safe';

  reasons.unshift(`Random Forest ML Confidence: ${mlProbability}%`);

  return {
    riskScore: finalScore,
    status,
    zScore: f.zScore,
    subScores: { ml: mlProbability, behavioral: behavioralScore, velocity: velocityScore, networkDevice: networkDeviceScore },
    flaggedReasons: reasons
  };
}

module.exports = { evaluateTransaction, getRiskPolicy, updateRiskPolicy };