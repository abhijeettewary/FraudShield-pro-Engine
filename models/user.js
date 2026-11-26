const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['customer', 'analyst'], required: true },
  accountNumber: { type: String, unique: true, sparse: true },
  balance: { type: Number, default: 50000, min: 0 },
  tokenVersion: { type: Number, default: 0 },
  failedLoginAttempts: { type: Number, default: 0 },
  lastFailedLoginAt: { type: Date, default: null },
  lastLoginAt: { type: Date, default: null },
  lastLoginLocation: { type: String, default: 'India' },
  lastPasswordChangeAt: { type: Date, default: null },
  lastBeneficiaryAddedAt: { type: Date, default: null },
  trustedDevices: [
    {
      deviceId: String,
      label: String,
      addedAt: { type: Date, default: Date.now },
      lastUsedAt: { type: Date, default: Date.now }
    }
  ],
  loginHistory: [
    {
      deviceId: String,
      location: String,
      timestamp: { type: Date, default: Date.now },
      suspicious: { type: Boolean, default: false }
    }
  ],
  restriction: {
    status: { type: String, enum: ['NONE', 'TEMP_RESTRICTED', 'COMPROMISED'], default: 'NONE' },
    reason: { type: String, default: '' },
    expiresAt: { type: Date, default: null }
  },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);