const test = require('node:test');
const assert = require('node:assert/strict');
const User = require('../models/User');

test('legacy account fields map to the MongoDB user schema', async () => {
  const user = new User({
    id: '123456', username: 'TestUser', usernameLower: 'testuser',
    passwordHash: 'scrypt$salt$hash', subDays: 30, is2FAEnabled: true,
    role: 'player', trialUsed: true, bootstrapPasswordVersion: 'v3'
  });
  await user.validate();
  const stored = user.toObject();
  assert.equal(stored.password, user.passwordHash);
  assert.equal(stored.subscription, user.subDays);
  assert.equal(stored.twoFactorEnabled, user.is2FAEnabled);
  assert.equal(stored.trialUsed, true);
  assert.equal(stored.bootstrapPasswordVersion, 'v3');
});
