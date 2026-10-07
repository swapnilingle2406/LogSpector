const mongoose = require('mongoose');

module.exports = mongoose.model('Analysis', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  filename: String,
  format: String,
  total: Number,
  suspiciousCount: Number,
  statusCounts: mongoose.Schema.Types.Mixed,
  entries: [mongoose.Schema.Types.Mixed],
  intel: [mongoose.Schema.Types.Mixed],
}, { timestamps: true }));
