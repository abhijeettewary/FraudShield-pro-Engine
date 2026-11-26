const mongoose = require('mongoose');

const securityEventSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  accountNumber: { type: String, required: true },
  category: {
    type: String,
    enum: [
      'BLOCKED_TRANSACTION',
      'RESTRICTED_PAYMENT',
      'SUSPICIOUS_LOGIN',
      'TEMPORARY_RESTRICTION',
      'UNAUTHORIZED_REPORT'
    ],
    required: true
  },
  severity: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  message: { type: String, required: true },
  transactionRef: { type: String, default: null },
  deviceId: { type: String, default: 'Unknown' },
  location: { type: String, default: 'Unknown' },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('SecurityEvent', securityEventSchema);