const HIGH_RISK_CATEGORIES = ['Crypto', 'Gambling', 'Wire Transfer', 'Luxury Goods'];

function computeFeatures(tx, context = {}) {
  const {
    userHistory = [],
    recent1MinTx = [],
    recent1HourTx = [],
    ringLinkedUsers = [],
    learnedRules = [],
    userBalance = null,
    isNewBeneficiary = false,
    knownDevices = []
  } = context;

  const amount = Number(tx.amount) || 0;
  const hourOfDay = Number(tx.hourOfDay) ?? new Date().getHours();
  const accountAgeDays = Number(tx.accountAgeDays) || 0;
  const location = (tx.location || 'India').trim();
  const deviceType = tx.deviceType || 'Web Browser';
  const deviceId = tx.deviceId || 'DEV-UNKNOWN';

  // 1. Velocity & Time-Window Features
  const txPerMin = recent1MinTx.length;
  const txPerHour = recent1HourTx.length;
  const totalAmount1Hour = recent1HourTx.reduce((sum, t) => sum + (Number(t.amount) || 0), 0);
  const microTxCount1Hour = recent1HourTx.filter((t) => Number(t.amount) <= 1000).length;

  // Time since previous transaction (in seconds)
  let secondsSinceLastTx = null;
  if (userHistory.length > 0) {
    const sorted = [...userHistory].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    secondsSinceLastTx = Math.max(0, Math.floor((Date.now() - new Date(sorted[0].createdAt).getTime()) / 1000));
  }

  // 2. Balance Depletion Ratio (if simulated balance is known)
  const balanceDepletionRatio =
    userBalance && userBalance > 0 ? Number((amount / userBalance).toFixed(3)) : 0;

  // 3. Behavioral Z-Score (Safe Cold-Start Handling: requires >= 3 past transactions)
  let zScore = 0;
  let amountDeviationRatio = 1;
  if (userHistory.length >= 3) {
    const amounts = userHistory.map((t) => Number(t.amount) || 0);
    const mean = amounts.reduce((a, b) => a + b, 0) / amounts.length;
    const variance = amounts.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / amounts.length;
    const stdDev = Math.sqrt(variance);

    amountDeviationRatio = mean > 0 ? Number((amount / mean).toFixed(2)) : 1;
    if (stdDev > 10) {
      zScore = Number(((amount - mean) / stdDev).toFixed(2));
    } else if (amount > mean * 2.5) {
      zScore = 3.5; // Low-variance user suddenly making a much larger payment
    }
  }

  // 4. Country Mismatch / Impossible Travel
  const lastTx = userHistory.length > 0 ? userHistory[0] : null;
  const countryMismatch = lastTx && lastTx.location && lastTx.location.toLowerCase() !== location.toLowerCase();
  const impossibleTravel = Boolean(countryMismatch && secondsSinceLastTx !== null && secondsSinceLastTx < 3600);

  // 5. Device & Beneficiary Familiarity
  const isForeign = location.toLowerCase() !== 'india' ? 1 : 0;
  const isVPN = deviceType === 'Unknown/VPN' ? 1 : 0;
  const isHighRiskCat = HIGH_RISK_CATEGORIES.includes(tx.merchantCategory) ? 1 : 0;
  const isOddHour = hourOfDay >= 0 && hourOfDay <= 5 ? 1 : 0;
  const isNewDevice = knownDevices.length > 0 && !knownDevices.some((d) => d.deviceId === deviceId);

  // 6. Watchlist / Reputation Flags
  const isWatchlisted = learnedRules.some((r) => r.action === 'watchlist');
  const isTrusted = learnedRules.some((r) => r.action === 'trusted');

  return {
    amount,
    hourOfDay,
    accountAgeDays,
    isHighRiskCat,
    isForeign,
    isVPN,
    isOddHour,
    txPerMin,
    txPerHour,
    totalAmount1Hour,
    microTxCount1Hour,
    secondsSinceLastTx,
    balanceDepletionRatio,
    zScore,
    amountDeviationRatio,
    countryMismatch: Boolean(countryMismatch),
    impossibleTravel,
    isNewBeneficiary: Boolean(isNewBeneficiary),
    isNewDevice: Boolean(isNewDevice),
    ringLinkedCount: ringLinkedUsers.length,
    isWatchlisted,
    isTrusted
  };
}

module.exports = { computeFeatures };