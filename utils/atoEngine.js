const DeviceReputation = require('../models/deviceReputation');

async function upsertDeviceReputation(deviceId, accountNumber, eventType = 'seen') {
  if (!deviceId || deviceId === 'DEV-UNKNOWN') return null;

  let doc = await DeviceReputation.findOne({ deviceId });
  if (!doc) {
    doc = new DeviceReputation({
      deviceId,
      associatedAccounts: accountNumber ? [accountNumber] : []
    });
  } else {
    doc.lastSeen = new Date();
    if (accountNumber && !doc.associatedAccounts.includes(accountNumber)) {
      doc.associatedAccounts.push(accountNumber);
    }
  }

  if (eventType === 'legit') doc.legitimateCount += 1;
  if (eventType === 'fraud') doc.fraudIncidents += 1;
  if (eventType === 'failed_login') doc.failedLoginCount += 1;

  // Recalculate device risk score (0-100)
  let score = 10;
  if (doc.associatedAccounts.length >= 3) score += 45;
  else if (doc.associatedAccounts.length === 2) score += 20;
  score += Math.min(40, doc.fraudIncidents * 20);
  score += Math.min(25, doc.failedLoginCount * 5);
  score -= Math.min(20, doc.legitimateCount * 3);

  doc.riskScore = Math.max(0, Math.min(100, score));

  if (doc.trustStatus !== 'Blacklisted') {
    if (doc.riskScore >= 65 || doc.fraudIncidents >= 2) doc.trustStatus = 'Blacklisted';
    else if (doc.riskScore >= 35) doc.trustStatus = 'Suspicious';
    else if (doc.legitimateCount >= 3 && doc.fraudIncidents === 0) doc.trustStatus = 'Trusted';
    else doc.trustStatus = 'Neutral';
  }

  await doc.save();
  return doc;
}

function evaluateLoginATO(user, { deviceId, location, deviceRep }) {
  let atoRisk = 0;
  const reasons = [];

  const isKnownDevice = (user.trustedDevices || []).some((d) => d.deviceId === deviceId);
  if (!isKnownDevice && (user.trustedDevices || []).length > 0) {
    atoRisk += 30;
    reasons.push(`Login from unfamiliar device (${deviceId})`);
  }

  if (user.failedLoginAttempts >= 3) {
    atoRisk += 30;
    reasons.push(`Preceded by ${user.failedLoginAttempts} failed login attempts`);
  }

  if (user.lastLoginAt && user.lastLoginLocation && location) {
    const minsSinceLast = (Date.now() - new Date(user.lastLoginAt).getTime()) / (1000 * 60);
    if (minsSinceLast < 60 && user.lastLoginLocation.toLowerCase() !== location.toLowerCase()) {
      atoRisk += 45;
      reasons.push(`Rapid geographical jump: ${user.lastLoginLocation} → ${location} in ${Math.round(minsSinceLast)} mins`);
    }
  }

  if (deviceRep && (deviceRep.trustStatus === 'Blacklisted' || deviceRep.trustStatus === 'Suspicious')) {
    atoRisk += deviceRep.trustStatus === 'Blacklisted' ? 40 : 20;
    reasons.push(`Device reputation is ${deviceRep.trustStatus} (Score ${deviceRep.riskScore}/100)`);
  }

  return { atoRisk: Math.min(100, atoRisk), reasons };
}

function evaluateSessionPaymentATO(user, amount, deviceRep) {
  let atoBoost = 0;
  const reasons = [];
  const now = Date.now();

  // 1. Login followed by immediate high-value transfer (< 3 mins & >= ₹10,000)
  if (user.lastLoginAt && amount >= 10000) {
    const minsSinceLogin = (now - new Date(user.lastLoginAt).getTime()) / (1000 * 60);
    if (minsSinceLogin <= 3) {
      atoBoost += 18;
      reasons.push(`ATO Signal: High-value transfer ₹${amount.toLocaleString('en-IN')} within ${Math.max(1, Math.round(minsSinceLogin))} min of login`);
    }
  }

  // 2. Password change followed by immediate transfer (< 10 mins)
  if (user.lastPasswordChangeAt) {
    const minsSincePass = (now - new Date(user.lastPasswordChangeAt).getTime()) / (1000 * 60);
    if (minsSincePass <= 10) {
      atoBoost += 22;
      reasons.push(`ATO Signal: Transfer initiated ${Math.max(1, Math.round(minsSincePass))} min after password change`);
    }
  }

  // 3. New beneficiary added followed immediately by transfer (< 5 mins)
  if (user.lastBeneficiaryAddedAt) {
    const minsSinceBen = (now - new Date(user.lastBeneficiaryAddedAt).getTime()) / (1000 * 60);
    if (minsSinceBen <= 5) {
      atoBoost += 15;
      reasons.push(`ATO Signal: Transfer within ${Math.max(1, Math.round(minsSinceBen))} min of adding a new beneficiary`);
    }
  }

  // 4. Device Reputation risk boost
  if (deviceRep && deviceRep.trustStatus === 'Blacklisted') {
    atoBoost += 25;
    reasons.push(`Device Reputation: ${deviceRep.deviceId} is Blacklisted (${deviceRep.fraudIncidents} prior fraud hits)`);
  } else if (deviceRep && deviceRep.trustStatus === 'Suspicious') {
    atoBoost += 12;
    reasons.push(`Device Reputation: ${deviceRep.deviceId} is flagged Suspicious`);
  }

  return { atoBoost, reasons };
}

module.exports = {
  upsertDeviceReputation,
  evaluateLoginATO,
  evaluateSessionPaymentATO
};