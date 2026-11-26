const URGENCY_KEYWORDS = [
  'urgent', 'emergency', 'police', 'cbi', 'customs', 'arrest',
  'kyc', 'verify', 'lottery', 'prize', 'refund', 'fine', 'penalty',
  'double', 'guaranteed', 'crypto', 'investment', 'otp', 'unlock'
];

function evaluateScamRisk({
  sender,
  receiver,
  savedBen,
  amount,
  description = '',
  userHistory = [],
  recentToBenCount = 0,
  receiverInboundSenders = 0,
  receiverFlaggedCount = 0
}) {
  const warnings = [];
  let score = 0;

  const isNewBeneficiary = !savedBen || savedBen.trustLevel === 'New';
  const descLower = (description || '').toLowerCase();

  // 1. New or unsaved beneficiary
  if (isNewBeneficiary) {
    score += 20;
    warnings.push({
      title: 'Newly added or unverified beneficiary',
      detail: `${receiver.name} (${receiver.accountNumber}) is not an established recipient in your account yet.`
    });
  }

  // 2. Unusually large payment compared to personal history
  if (userHistory.length >= 2) {
    const avg = userHistory.reduce((sum, t) => sum + (Number(t.amount) || 0), 0) / userHistory.length;
    if (avg > 0 && amount >= avg * 2.5 && amount >= 3000) {
      score += 25;
      warnings.push({
        title: 'Unusually large payment',
        detail: `₹${amount.toLocaleString('en-IN')} is significantly larger than your typical transfer average (₹${Math.round(avg).toLocaleString('en-IN')}).`
      });
    }
  } else if (isNewBeneficiary && amount >= 15000) {
    score += 25;
    warnings.push({
      title: 'High-value transfer to a new recipient',
      detail: `You are sending ₹${amount.toLocaleString('en-IN')} to a recipient with no prior transfer history.`
    });
  }

  // 3. High balance depletion
  if (sender.balance > 0 && amount / sender.balance >= 0.6) {
    score += 20;
    warnings.push({
      title: 'Large portion of your balance',
      detail: `This transfer uses ${Math.round((amount / sender.balance) * 100)}% of your available simulated balance.`
    });
  }

  // 4. Repeated payments to a newly added beneficiary
  if (isNewBeneficiary && recentToBenCount >= 1) {
    score += 25;
    warnings.push({
      title: 'Repeated payments to a new beneficiary',
      detail: `You have already sent ${recentToBenCount} payment(s) to this new recipient in the last 24 hours. Scammers often ask for multiple transfers.`
    });
  }

  // 5. Urgency or social-engineering keywords in payment note
  const matchedKeyword = URGENCY_KEYWORDS.find((kw) => descLower.includes(kw));
  if (matchedKeyword) {
    score += 30;
    warnings.push({
      title: 'Possible urgency or social-engineering pattern',
      detail: `Your payment note contains "${matchedKeyword}". Legitimate agencies and banks never demand urgent transfers.`
    });
  }

  // 6. Unusual recipient activity (phrased carefully without claiming fraud)
  if (receiverInboundSenders >= 2 || receiverFlaggedCount >= 1) {
    score += 30;
    warnings.push({
      title: 'Unusual recipient account activity',
      detail: 'This recipient account has unusual recent transaction patterns. Please independently verify their identity before proceeding.'
    });
  }

  const riskLevel = score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low';

  return {
    shouldWarn: warnings.length > 0,
    riskLevel,
    recipientName: receiver.name,
    recipientAccount: receiver.accountNumber,
    warnings
  };
}

module.exports = { evaluateScamRisk };