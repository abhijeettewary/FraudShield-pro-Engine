const mongoose = require('mongoose');

const deviceReputationSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, unique: true, index: true },
  firstSeen: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  associatedAccounts: [{ type: String }],
  legitimateCount: { type: Number, default: 0 },
  fraudIncidents: { type: Number, default: 0 },
  failedLoginCount: { type: Number, default: 0 },
  riskScore: { type: Number, default: 10, min: 0, max: 100 },
  trustStatus: {
    type: String,
    enum: ['Trusted', 'Neutral', 'Suspicious', 'Blacklisted'],
    default: 'Neutral'
  }
});

module.exports = mongoose.model('DeviceReputation', deviceReputationSchema);