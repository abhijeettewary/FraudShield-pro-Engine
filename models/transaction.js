const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  transactionId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  amount: { type: Number, required: true },
  merchantCategory: { type: String, required: true },
  location: { type: String, required: true },
  deviceType: { type: String, required: true },
  deviceId: { type: String, default: 'DEV-UNKNOWN' },
  hourOfDay: { type: Number, required: true },
  accountAgeDays: { type: Number, default: 0 },
  zScore: { type: Number, default: 0 },
  ringLinkedUsers: { type: [String], default: [] },
  riskScore: { type: Number, required: true },
  mlProbability: { type: Number, default: 0 },
  status: {
    type: String,
    enum: ['Safe', 'Suspicious', 'Fraudulent'],
    required: true
  },
  analystReview: {
    type: String,
    default: 'Pending Review'
  },
  flaggedReasons: { type: [String], default: [] },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Transaction', transactionSchema);