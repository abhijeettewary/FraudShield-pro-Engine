const mongoose = require('mongoose');

const beneficiarySchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  beneficiaryUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  beneficiaryName: { type: String, required: true },
  beneficiaryAccountNumber: { type: String, required: true },
  nickname: { type: String, default: '' },
  trustLevel: { type: String, enum: ['New', 'Established'], default: 'New' },
  successfulTxCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

beneficiarySchema.index({ ownerId: 1, beneficiaryAccountNumber: 1 }, { unique: true });

module.exports = mongoose.model('Beneficiary', beneficiarySchema);