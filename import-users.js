// One-time import of the former users.json store. Existing MongoDB IDs are left untouched.
require('dotenv').config();
const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const mongoose = require('mongoose');
const User = require('./models/User');

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `scrypt$${salt}$${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}

async function main() {
  if (!process.env.MONGO_URI) throw new Error('Задайте MONGO_URI перед импортом.');
  const file = process.argv[2] || 'users.json';
  const users = JSON.parse(await fs.readFile(file, 'utf8'));
  if (!Array.isArray(users)) throw new Error('Ожидался JSON-массив пользователей.');
  await mongoose.connect(process.env.MONGO_URI);
  await User.init();
  let imported = 0;
  let skipped = 0;
  for (const source of users) {
    if (!source || !/^\d{6}$/.test(String(source.id)) || typeof source.username !== 'string') {
      throw new Error('Запись без корректного ID или имени пользователя. Исправьте её перед импортом.');
    }
    const password = source.passwordHash || (source.password || source.pass ? hashPassword(source.password || source.pass) : '');
    if (!password) throw new Error(`У пользователя ${source.id} нет пароля.`);
    const exists = await User.exists({ id: String(source.id) });
    if (exists) { skipped++; continue; }
    const fields = {
      id: String(source.id), username: source.username,
      usernameLower: source.username.toLowerCase(),
      email: typeof source.email === 'string' ? source.email.trim().toLowerCase() : '',
      password,
      role: ['user', 'player', 'admin'].includes(source.role) ? source.role : (Number(source.subDays) > 0 ? 'player' : 'user'),
      subscription: Number.isFinite(Number(source.subDays)) ? Math.max(0, Number(source.subDays)) : 0,
      twoFactorEnabled: source.is2FAEnabled === true,
      trialUsed: source.trialUsed === true,
      bootstrapPasswordVersion: source.bootstrapPasswordVersion || ''
    };
    const sameName = await User.findOne({ usernameLower: fields.usernameLower });
    if (sameName) {
      // A first server start may have created this empty admin before the import.
      if (fields.role !== 'admin' || sameName.role !== 'admin' || sameName.email !== '' ||
          sameName.bootstrapPasswordVersion !== 'env-managed-admin-v3') {
        throw new Error(`Имя пользователя ${source.username} уже занято другой записью.`);
      }
      Object.assign(sameName, fields);
      await sameName.save();
    } else {
      await User.create(fields);
    }
    imported++;
  }
  console.log(`Импортировано: ${imported}; уже существовали: ${skipped}.`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; })
  .finally(() => mongoose.disconnect());
