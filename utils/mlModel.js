const fs = require('fs');
const path = require('path');
const { RandomForestClassifier } = require('ml-random-forest');

const HIGH_RISK_CATEGORIES = ['Crypto', 'Gambling', 'Wire Transfer', 'Luxury Goods'];
let classifier = null;
let modelMeta = { trained: false, totalSamples: 0, kaggleSamples: 0, dbSamples: 0, lastTrainedAt: null };
let evaluationReport = null;

function extractFeatures(tx) {
  const amount = Number(tx.amount) || 0;
  const hourOfDay = Number(tx.hourOfDay) || 12;
  const accountAgeDays = Number(tx.accountAgeDays) || 30;
  const isHighRiskCat = HIGH_RISK_CATEGORIES.includes(tx.merchantCategory) ? 1 : 0;
  const isForeign = (tx.location || 'India').toLowerCase() !== 'india' ? 1 : 0;
  const isVPN = tx.deviceType === 'Unknown/VPN' ? 1 : 0;
  return [amount, hourOfDay, accountAgeDays, isHighRiskCat, isForeign, isVPN];
}

function parseKaggleCSV() {
  const csvPath = path.join(__dirname, '..', 'data', 'kaggle_fraud.csv');
  if (!fs.existsSync(csvPath)) return [];

  const content = fs.readFileSync(csvPath, 'utf8');
  const rows = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (ch === '"') inQuotes = !inQuotes;
    if ((ch === '\n' || ch === '\r') && !inQuotes) {
      if (current.trim()) rows.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) rows.push(current);

  const safeRows = [];
  const fraudRows = [];

  for (let i = 1; i < rows.length; i++) {
    const cols = rows[i].split(',');
    if (cols.length < 15) continue;
    const isFraud = Number(cols[10]) === 1 ? 1 : 0;
    const amount = Number(cols[2]) || 0;
    const hourOfDay = Number(cols[15]) || 12;
    const accountAgeDays = Number(cols[14]) || 30;
    const cat = (cols[5] || '').toLowerCase();
    const isHighRiskCat = cat.includes('electronics') || cat.includes('crypto') ? 1 : 0;
    const isForeign = (cols[9] || '').toLowerCase().includes('india') ? 0 : 1;
    const isVPN = (cols[6] || '').toLowerCase().includes('desktop') ? 0 : 1;

    const record = { features: [amount, hourOfDay, accountAgeDays, isHighRiskCat, isForeign, isVPN], label: isFraud };
    if (isFraud === 1 && fraudRows.length < 500) fraudRows.push(record);
    else if (isFraud === 0 && safeRows.length < 500) safeRows.push(record);
    if (fraudRows.length >= 500 && safeRows.length >= 500) break;
  }

  // Interleave chronologically so 80/20 split preserves class balance without leakage
  const combined = [];
  const maxLen = Math.max(safeRows.length, fraudRows.length);
  for (let i = 0; i < maxLen; i++) {
    if (safeRows[i]) combined.push(safeRows[i]);
    if (fraudRows[i]) combined.push(fraudRows[i]);
  }
  return combined;
}

function computeMetrics(yTrue, yPred) {
  let tp = 0, tn = 0, fp = 0, fn = 0;
  for (let i = 0; i < yTrue.length; i++) {
    if (yTrue[i] === 1 && yPred[i] === 1) tp++;
    else if (yTrue[i] === 0 && yPred[i] === 0) tn++;
    else if (yTrue[i] === 0 && yPred[i] === 1) fp++;
    else fn++;
  }
  const accuracy = (tp + tn) / (yTrue.length || 1);
  const precision = tp / (tp + fp || 1);
  const recall = tp / (tp + fn || 1);
  const f1 = (2 * precision * recall) / (precision + recall || 1);
  const specificity = tn / (tn + fp || 1);
  const fpr = fp / (fp + tn || 1);

  return {
    accuracy: Number((accuracy * 100).toFixed(1)),
    precision: Number((precision * 100).toFixed(1)),
    recall: Number((recall * 100).toFixed(1)),
    f1: Number((f1 * 100).toFixed(1)),
    specificity: Number((specificity * 100).toFixed(1)),
    fpr: Number((fpr * 100).toFixed(1)),
    confusionMatrix: { tp, tn, fp, fn }
  };
}

function simpleRuleScore(f) {
  let s = 0;
  if (f[0] > 20000) s += 30;
  if (f[1] <= 5) s += 20;
  if (f[2] <= 5) s += 25;
  if (f[3] === 1) s += 20;
  if (f[4] === 1) s += 20;
  if (f[5] === 1) s += 25;
  return Math.min(100, s);
}

function trainModel(dbTransactions = []) {
  const kaggleData = parseKaggleCSV();
  const dbData = dbTransactions.map((tx) => ({
    features: extractFeatures(tx),
    label: tx.status === 'Fraudulent' ? 1 : 0
  }));

  const fullDataset = [...kaggleData, ...dbData];
  if (fullDataset.length < 20) return modelMeta;

  // Chronological 80/20 Train/Test Split (no random shuffling leakage)
  const splitIdx = Math.floor(fullDataset.length * 0.8);
  const trainSet = fullDataset.slice(0, splitIdx);
  const testSet = fullDataset.slice(splitIdx);

  const X_train = trainSet.map((d) => d.features);
  const y_train = trainSet.map((d) => d.label);

  classifier = new RandomForestClassifier({
    seed: 42,
    maxFeatures: 0.8,
    replacement: true,
    nEstimators: 30
  });
  classifier.train(X_train, y_train);

  // Evaluate 4 Detection Modes on Held-Out Test Set
  const yTrue = testSet.map((d) => d.label);
  const rulePreds = [];
  const mlPreds = [];
  const legacyHybridPreds = [];
  const improvedHybridPreds = [];

  testSet.forEach((d) => {
    const rScore = simpleRuleScore(d.features);
    const votes = classifier.estimators.reduce((acc, tree) => acc + (tree.predict([d.features])[0] === 1 ? 1 : 0), 0);
    const mlProb = Math.round((votes / classifier.estimators.length) * 100);

    const legacyScore = Math.round(rScore * 0.5 + mlProb * 0.5);
    const improvedScore = Math.round(rScore * 0.4 + mlProb * 0.6);

    rulePreds.push(rScore >= 60 ? 1 : 0);
    mlPreds.push(mlProb >= 55 ? 1 : 0);
    legacyHybridPreds.push(legacyScore >= 60 ? 1 : 0);
    improvedHybridPreds.push(improvedScore >= 55 ? 1 : 0);
  });

  evaluationReport = {
    trainSize: trainSet.length,
    testSize: testSet.length,
    models: {
      ruleOnly: computeMetrics(yTrue, rulePreds),
      mlOnly: computeMetrics(yTrue, mlPreds),
      legacyHybrid: computeMetrics(yTrue, legacyHybridPreds),
      improvedHybrid: computeMetrics(yTrue, improvedHybridPreds)
    }
  };

  modelMeta = {
    trained: true,
    totalSamples: fullDataset.length,
    kaggleSamples: kaggleData.length,
    dbSamples: dbData.length,
    lastTrainedAt: new Date().toISOString()
  };

  return modelMeta;
}

function predictFraudProbability(tx) {
  if (!classifier) return 0;
  const features = extractFeatures(tx);
  const votes = classifier.estimators.reduce((acc, tree) => acc + (tree.predict([features])[0] === 1 ? 1 : 0), 0);
  return Math.round((votes / classifier.estimators.length) * 100);
}

function getModelMeta() {
  return modelMeta;
}

function getEvaluationReport() {
  return evaluationReport;
}

module.exports = { trainModel, predictFraudProbability, getModelMeta, getEvaluationReport };