const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true, trim: true },
  usernameLower: { type: String, required: true, unique: true },
  email: { type: String, default: '' },
  password: { type: String, required: true, alias: 'passwordHash' },
  role: { type: String, enum: ['user', 'player', 'admin'], default: 'user' },
  subscription: { type: Number, default: 0, alias: 'subDays' },
  twoFactorEnabled: { type: Boolean, default: false, alias: 'is2FAEnabled' },
  trialUsed: { type: Boolean, default: false },
  bootstrapPasswordVersion: { type: String, default: '' }
});

userSchema.index({ email: 1 }, { unique: true, partialFilterExpression: { email: { $type: 'string', $gt: '' } } });

module.exports = mongoose.model('User', userSchema);
