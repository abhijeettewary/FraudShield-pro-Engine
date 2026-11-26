const mongoose = require('mongoose');

const watchlistSchema = new mongoose.Schema({
  type: { type: String, enum: ['user', 'device', 'location'], required: true },
  value: { type: String, required: true },
  action: { type: String, enum: ['watchlist', 'trusted'], required: true },
  reason: { type: String, default: 'Analyst feedback' },
  hits: { type: Number, default: 1 },
  updatedAt: { type: Date, default: Date.now }
});

watchlistSchema.index({ type: 1, value: 1 }, { unique: true });

module.exports = mongoose.model('Watchlist', watchlistSchema);