require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { sendVerificationEmail, sendPasswordResetEmail, sendLoginCodeEmail } = require('./mailer');

const app = express();
app.use(cors());
app.use(express.json({ limit: '16kb' }));

const DB_FILE = path.join(__dirname, 'users.json');
const SECRET_FILE = path.join(__dirname, '.auth-secret');
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30;
const ADMIN_USERNAME = process.env.LENIKS_ADMIN_USERNAME || '';
const ADMIN_PASSWORD = process.env.LENIKS_ADMIN_PASSWORD || '';
const ADMIN_BOOTSTRAP_VERSION = 'env-managed-admin-v3';
const CODE_TTL_MS = 10 * 60 * 1000;
const CODE_RESEND_MS = 60 * 1000;
const PASSWORD_ERROR = 'Пароль должен быть не менее 8 символов и содержать хотя бы одну букву и одну цифру';
const pendingRegistrations = new Map();
const pendingResets = new Map();
const pendingLogins = new Map();
let users = [];

function validPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128 && /\p{L}/u.test(password) && /\p{Nd}/u.test(password);
}

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function validEmail(email) {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function newCode() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function codeMatches(entry, code) {
  if (!entry || entry.expiresAt <= Date.now() || entry.attempts >= 5 || !/^\d{6}$/.test(code)) return false;
  entry.attempts++;
  return crypto.timingSafeEqual(Buffer.from(entry.code), Buffer.from(code));
}

function canResend(entry) {
  return !entry || entry.createdAt + CODE_RESEND_MS <= Date.now();
}

function mailError(res, error) {
  console.error('Не удалось отправить письмо:', error);
  const message = error?.code === 'EAUTH'
    ? 'Gmail отклонил авторизацию почты сервера. Проверьте EMAIL_USER и EMAIL_PASS.'
    : 'Не удалось отправить письмо. Попробуйте позже.';
  return res.status(503).json({ error: message });
}

function readSecret() {
  if (process.env.LENIKS_TOKEN_SECRET) return process.env.LENIKS_TOKEN_SECRET;
  if (fs.existsSync(SECRET_FILE)) return fs.readFileSync(SECRET_FILE, 'utf8').trim();
  const secret = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(SECRET_FILE, secret, { mode: 0o600 });
  return secret;
}
const tokenSecret = readSecret();

function saveDB() {
  const temporary = `${DB_FILE}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(users, null, 2), { mode: 0o600 });
  fs.renameSync(temporary, DB_FILE);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (typeof stored !== 'string' || !stored.startsWith('scrypt$')) return false;
  const [, salt, expectedHex] = stored.split('$');
  const expected = Buffer.from(expectedHex || '', 'hex');
  const actual = crypto.scryptSync(password, salt, 64);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function publicUser(user) {
  return { id: user.id, username: user.username, email: user.email || '', role: user.role, subDays: user.subDays, is2FAEnabled: user.is2FAEnabled === true };
}

function makeToken(user) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub: user.id, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS })).toString('base64url');
  const signature = crypto.createHmac('sha256', tokenSecret).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function getTokenUser(req) {
  const token = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  const expected = crypto.createHmac('sha256', tokenSecret).update(`${header}.${payload}`).digest();
  let actual;
  try { actual = Buffer.from(signature, 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!claims.sub || claims.exp < Date.now() / 1000) return null;
    return users.find((user) => user.id === String(claims.sub)) || null;
  } catch { return null; }
}

function requireAuth(req, res, next) {
  const user = getTokenUser(req);
  if (!user) return res.status(401).json({ error: 'Требуется войти в аккаунт' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ только для администратора' });
  next();
}

function generateId() {
  let id;
  do { id = String(crypto.randomInt(100000, 1000000)); }
  while (users.some((user) => user.id === id));
  return id;
}

function initializeUsers() {
  try {
    const saved = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (Array.isArray(saved)) users = saved;
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error(`Не удалось прочитать users.json: ${error.message}`);
  }

  // Convert accounts made by the previous server format and assign missing IDs.
  const seenIds = new Set();
  users = users.filter((user) => user && typeof user.username === 'string').map((user) => {
    const migrated = { ...user };
    if (!/^\d{6}$/.test(String(migrated.id)) || seenIds.has(String(migrated.id))) migrated.id = generateId();
    migrated.id = String(migrated.id);
    seenIds.add(migrated.id);
    migrated.role = ['user', 'player', 'admin'].includes(migrated.role) ? migrated.role : (Number(migrated.subDays) > 0 ? 'player' : 'user');
    migrated.subDays = Number.isFinite(Number(migrated.subDays)) ? Math.max(0, Number(migrated.subDays)) : 0;
    migrated.trialUsed = migrated.trialUsed === true;
    migrated.is2FAEnabled = migrated.is2FAEnabled === true;
    if (!migrated.passwordHash) {
      const legacyPassword = typeof migrated.password === 'string' ? migrated.password : typeof migrated.pass === 'string' ? migrated.pass : '';
      if (legacyPassword) migrated.passwordHash = hashPassword(legacyPassword);
    }
    delete migrated.password;
    delete migrated.pass;
    return migrated;
  });

  let admin = users.find((user) => user.role === 'admin');
  if (!admin && ADMIN_USERNAME) {
    admin = users.find((user) => user.username.toLowerCase() === ADMIN_USERNAME.toLowerCase());
  }
  if (!admin) {
    if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
      throw new Error('Задайте LENIKS_ADMIN_USERNAME и LENIKS_ADMIN_PASSWORD в окружении для первого создания администратора.');
    }
    admin = { id: generateId(), username: ADMIN_USERNAME, email: '', is2FAEnabled: false, role: 'admin', subDays: 99999, passwordHash: hashPassword(ADMIN_PASSWORD), bootstrapPasswordVersion: ADMIN_BOOTSTRAP_VERSION };
    users.push(admin);
  } else {
    admin.role = 'admin';
    admin.subDays = 99999;
    if (admin.bootstrapPasswordVersion !== ADMIN_BOOTSTRAP_VERSION) {
      if (!ADMIN_PASSWORD) {
        throw new Error('Для безопасной смены пароля администратора задайте LENIKS_ADMIN_PASSWORD в окружении.');
      }
      admin.passwordHash = hashPassword(ADMIN_PASSWORD);
      admin.bootstrapPasswordVersion = ADMIN_BOOTSTRAP_VERSION;
    }
  }
  saveDB();
}

app.post('/api/register', async (req, res) => {
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const email = normalizeEmail(req.body.email);
  if (!/^[A-Za-z0-9_]{3,16}$/.test(username)) return res.status(400).json({ error: 'Ник: 3–16 символов A–Z, цифр или _.' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Укажите корректный Email' });
  if (!validPassword(password)) return res.status(400).json({ error: PASSWORD_ERROR });
  if (users.some((user) => user.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: 'Это имя пользователя уже занято' });
  }
  if (users.some((user) => user.email === email)) return res.status(409).json({ error: 'Этот Email уже используется' });
  if (!canResend(pendingRegistrations.get(email))) return res.status(429).json({ error: 'Подождите минуту перед повторной отправкой кода' });
  const code = newCode();
  try { await sendVerificationEmail(email, code); } catch (error) { return mailError(res, error); }
  pendingRegistrations.set(email, { username, email, passwordHash: hashPassword(password), code, createdAt: Date.now(), expiresAt: Date.now() + CODE_TTL_MS, attempts: 0 });
  res.json({ success: true, message: 'Код подтверждения отправлен на Email', sender: process.env.EMAIL_USER });
});

app.post('/api/register/resend', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const entry = pendingRegistrations.get(email);
  if (!entry || entry.expiresAt <= Date.now()) return res.status(404).json({ error: 'Запрос регистрации истёк. Начните регистрацию заново.' });
  if (!canResend(entry)) return res.status(429).json({ error: 'Подождите минуту перед повторной отправкой кода' });
  const code = newCode();
  try { await sendVerificationEmail(email, code); } catch (error) { return mailError(res, error); }
  Object.assign(entry, { code, createdAt: Date.now(), expiresAt: Date.now() + CODE_TTL_MS, attempts: 0 });
  res.json({ success: true, message: 'Новый код отправлен на Email', sender: process.env.EMAIL_USER });
});

app.post('/api/register/verify', (req, res) => {
  const email = normalizeEmail(req.body.email);
  const code = typeof req.body.code === 'string' ? req.body.code : '';
  const entry = pendingRegistrations.get(email);
  if (!codeMatches(entry, code)) return res.status(400).json({ error: 'Неверный или просроченный код' });
  if (users.some((user) => user.username.toLowerCase() === entry.username.toLowerCase() || user.email === email)) {
    pendingRegistrations.delete(email);
    return res.status(409).json({ error: 'Имя пользователя или Email уже заняты' });
  }
  const user = { id: generateId(), username: entry.username, email, passwordHash: entry.passwordHash, role: 'user', subDays: 0, is2FAEnabled: false, trialUsed: false };
  users.push(user);
  saveDB();
  pendingRegistrations.delete(email);
  res.status(201).json({ success: true, token: makeToken(user), user: publicUser(user) });
});

app.post('/api/forgot-password', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  if (!validEmail(email)) return res.status(400).json({ error: 'Укажите корректный Email' });
  const user = users.find((entry) => entry.email === email);
  if (!user) return res.status(404).json({ error: 'Аккаунт с этим Email не найден' });
  if (!canResend(pendingResets.get(email))) return res.status(429).json({ error: 'Подождите минуту перед повторной отправкой кода' });
  const code = newCode();
  try { await sendPasswordResetEmail(email, code); } catch (error) { return mailError(res, error); }
  pendingResets.set(email, { code, createdAt: Date.now(), expiresAt: Date.now() + CODE_TTL_MS, attempts: 0 });
  res.json({ success: true, message: 'Код восстановления отправлен на Email' });
});

app.post('/api/reset-password', (req, res) => {
  const email = normalizeEmail(req.body.email);
  const code = typeof req.body.code === 'string' ? req.body.code : '';
  const password = req.body.newPassword;
  if (!validPassword(password)) return res.status(400).json({ error: PASSWORD_ERROR });
  const entry = pendingResets.get(email);
  if (!codeMatches(entry, code)) return res.status(400).json({ error: 'Неверный или просроченный код' });
  const user = users.find((item) => item.email === email);
  if (!user) return res.status(404).json({ error: 'Аккаунт не найден' });
  user.passwordHash = hashPassword(password);
  pendingLogins.delete(user.id);
  saveDB();
  pendingResets.delete(email);
  res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
  const login = typeof req.body.login === 'string' ? req.body.login.trim() : typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const user = users.find((entry) => entry.username.toLowerCase() === login.toLowerCase());
  if (!user || !user.passwordHash || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
  }
  if (user.is2FAEnabled === true) {
    if (!validEmail(user.email || '')) return res.status(409).json({ error: 'Для двухфакторного входа нужна почта в профиле' });
    if (!canResend(pendingLogins.get(user.id))) return res.status(429).json({ error: 'Подождите минуту перед повторной отправкой кода' });
    const code = newCode();
    try { await sendLoginCodeEmail(user.email, code); } catch (error) { return mailError(res, error); }
    pendingLogins.set(user.id, { code, createdAt: Date.now(), expiresAt: Date.now() + CODE_TTL_MS, attempts: 0 });
    return res.json({ require2FA: true, username: user.username });
  }
  res.json({ success: true, token: makeToken(user), user: publicUser(user) });
});

app.post('/api/2fa/verify', (req, res) => {
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const code = typeof req.body.code === 'string' ? req.body.code.trim() : '';
  const user = users.find((entry) => entry.username.toLowerCase() === username.toLowerCase());
  const pending = user && pendingLogins.get(user.id);
  if (!user || user.is2FAEnabled !== true || !codeMatches(pending, code)) {
    return res.status(400).json({ error: 'Неверный или просроченный код' });
  }
  pendingLogins.delete(user.id);
  res.json({ success: true, token: makeToken(user), user: publicUser(user) });
});

app.post('/api/2fa/toggle', requireAuth, (req, res) => {
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const enabled = req.body.enabled;
  if (username.toLowerCase() !== req.user.username.toLowerCase()) return res.status(403).json({ error: 'Нельзя изменить чужой аккаунт' });
  if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'Передайте boolean в поле enabled' });
  if (enabled && !validEmail(req.user.email || '')) return res.status(409).json({ error: 'Сначала укажите Email для аккаунта' });
  req.user.is2FAEnabled = enabled;
  pendingLogins.delete(req.user.id);
  saveDB();
  res.json({ success: true, user: publicUser(req.user) });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/buy', requireAuth, (req, res) => {
  const days = Number(req.body.days);
  if (!Number.isInteger(days) || days < 1 || days > 36500) return res.status(400).json({ error: 'Количество дней должно быть от 1 до 36500' });
  req.user.subDays = Math.min(99999, req.user.subDays + days);
  req.user.role = 'player';
  saveDB();
  res.json({ success: true, user: publicUser(req.user) });
});

app.post('/api/trial/start', requireAuth, (req, res) => {
  if (req.user.trialUsed === true) return res.status(409).json({ error: 'Пробная версия уже была использована' });
  req.user.trialUsed = true;
  req.user.subDays = Math.min(99999, req.user.subDays + 3);
  req.user.role = 'player';
  saveDB();
  res.json({ success: true, user: publicUser(req.user) });
});

app.get('/api/admin/users', requireAuth, requireAdmin, (_req, res) => {
  res.json(users.map(({ id, username, email, role, subDays }) => ({
    id, username, email: email || '', role, subDays
  })));
});

app.get('/api/admin/find/:id', requireAuth, requireAdmin, (req, res) => {
  const user = users.find((entry) => entry.id === String(req.params.id));
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  // Passwords are never returned; the admin can reset one via change-password.
  res.json({ id: user.id, username: user.username, subDays: user.subDays, role: user.role });
});

app.post('/api/admin/change-password', requireAuth, requireAdmin, (req, res) => {
  const id = String(req.body.id || '');
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const user = users.find((entry) => entry.id === id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (!validPassword(password)) return res.status(400).json({ error: PASSWORD_ERROR });
  user.passwordHash = hashPassword(password);
  pendingLogins.delete(user.id);
  saveDB();
  res.json({ success: true });
});

app.post('/api/admin/give-sub', requireAuth, requireAdmin, (req, res) => {
  const id = String(req.body.id || '');
  const days = Number(req.body.days);
  const user = users.find((entry) => entry.id === id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (!Number.isInteger(days) || days < -1 || days > 36500) return res.status(400).json({ error: 'Передайте положительное количество дней или -1 для навсегда' });
  user.subDays = days === -1 ? 99999 : Math.min(99999, user.subDays + days);
  if (user.subDays > 0) user.role = 'player';
  else if (user.role === 'player') user.role = 'user';
  saveDB();
  res.json({ success: true, user: publicUser(user) });
});

initializeUsers();
const port = Number(process.env.PORT) || 3000;
app.listen(port, '0.0.0.0', () => console.log(`✅ Leniks API запущен на порту ${port}`));
