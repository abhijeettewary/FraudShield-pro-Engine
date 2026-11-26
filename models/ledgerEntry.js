const mongoose = require('mongoose');

const ledgerEntrySchema = new mongoose.Schema({
  transactionRef: { type: String, required: true },
  idempotencyKey: { type: String, index: true },
  accountNumber: { type: String, required: true, index: true },
  counterpartyAccount: { type: String, required: true },
  counterpartyName: { type: String, required: true },
  type: { type: String, enum: ['DEBIT', 'CREDIT'], required: true },
  amount: { type: Number, required: true },
  balanceAfter: { type: Number, required: true },
  description: { type: String, default: 'Simulated Bank Transfer' },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('LedgerEntry', ledgerEntrySchema);