const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

test('registration verification and password recovery', { skip: !process.env.MONGO_TEST_URI && 'Set MONGO_TEST_URI to run the MongoDB integration test' }, async () => {
  const directory = fs.mkdtempSync(path.join(__dirname, 'auth-temp-'));
  const port = await freePort();
  const adminUsername = `test_admin_${crypto.randomBytes(4).toString('hex')}`;
  const adminPassword = crypto.randomBytes(24).toString('base64url');
  const mongoUrl = new URL(process.env.MONGO_TEST_URI);
  mongoUrl.pathname = `/leniks_test_${crypto.randomBytes(8).toString('hex')}`;
  const mongoUri = mongoUrl.toString();
  fs.copyFileSync(path.join(__dirname, '..', 'server.js'), path.join(directory, 'server.js'));
  fs.mkdirSync(path.join(directory, 'models'));
  fs.copyFileSync(path.join(__dirname, '..', 'models', 'User.js'), path.join(directory, 'models', 'User.js'));
  fs.writeFileSync(path.join(directory, 'mailer.js'), "const fs = require('node:fs'); const send = purpose => async (email, code) => { if (email === 'fail@example.com') { const error = new Error('Invalid login'); error.code = 'EAUTH'; throw error; } fs.writeFileSync(__dirname + '/mail.json', JSON.stringify({ email, code, purpose })); }; exports.sendVerificationEmail = send('register'); exports.sendPasswordResetEmail = send('reset'); exports.sendLoginCodeEmail = send('login');\n");
  const child = spawn(process.execPath, ['server.js'], {
    cwd: directory,
    env: { ...process.env, MONGO_URI: mongoUri, PORT: String(port), LENIKS_TOKEN_SECRET: 'test-secret', LENIKS_ADMIN_USERNAME: adminUsername, LENIKS_ADMIN_PASSWORD: adminPassword, NODE_PATH: path.join(__dirname, '..', 'node_modules') },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  const base = `http://127.0.0.1:${port}`;
  const post = async (route, body, token = '') => {
    const response = await fetch(base + route, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  const get = async (route, token = '') => {
    const response = await fetch(base + route, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    return { status: response.status, body: await response.json() };
  };
  try {
    let ready = false;
    let lastError = '';
    for (let attempt = 0; attempt < 50; attempt++) {
      if (child.exitCode !== null) throw new Error(output || `Server exited: ${child.exitCode}`);
      try { await fetch(base + '/api/me'); ready = true; break; } catch (error) { lastError = String(error.cause || error); await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.ok(ready, `Server did not start: ${output}; ${lastError}`);

    const registration = { username: 'test_user', email: 'Test@Example.com', password: 'секрет123' };
    assert.equal((await post('/api/register', { ...registration, password: 'weak' })).status, 400);
    const rejectedMail = await post('/api/register', { username: 'mail_failure', email: 'fail@example.com', password: 'секрет123' });
    assert.equal(rejectedMail.status, 503);
    assert.match(rejectedMail.body.error, /Gmail отклонил авторизацию/);
    assert.equal((await post('/api/register', registration)).status, 200);
    assert.equal((await post('/api/register/resend', { email: registration.email })).status, 429);
    assert.equal((await post('/api/register/resend', { email: 'missing@example.com' })).status, 404);
    const firstMail = JSON.parse(fs.readFileSync(path.join(directory, 'mail.json'), 'utf8'));
    assert.equal(firstMail.email, 'test@example.com');
    assert.equal(firstMail.purpose, 'register');
    assert.equal((await post('/api/register/verify', { email: registration.email, code: 'abcdef' })).status, 400);
    const verified = await post('/api/register/verify', { email: registration.email, code: firstMail.code });
    assert.equal(verified.status, 201);
    assert.ok(verified.body.token);
    assert.equal(verified.body.user.email, 'test@example.com');
    assert.equal(verified.body.user.is2FAEnabled, false);
    assert.equal((await post('/api/register/verify', { email: registration.email, code: firstMail.code })).status, 400);
    assert.equal((await post('/api/login', { login: registration.username, password: registration.password })).status, 200);

    assert.equal((await get('/api/admin/users')).status, 401);
    assert.equal((await get('/api/admin/users', verified.body.token)).status, 403);
    const adminLogin = await post('/api/login', { login: adminUsername, password: adminPassword });
    assert.equal(adminLogin.status, 200);
    const adminUsers = await get('/api/admin/users', adminLogin.body.token);
    assert.equal(adminUsers.status, 200);
    assert.equal(adminUsers.body.length, 2);
    const listedUser = adminUsers.body.find(user => user.username === registration.username);
    assert.deepEqual(Object.keys(listedUser).sort(), ['id', 'username', 'email', 'role', 'subDays'].sort());
    assert.equal(listedUser.email, 'test@example.com');

    assert.equal((await post('/api/2fa/toggle', { username: registration.username, enabled: true })).status, 401);
    assert.equal((await post('/api/2fa/toggle', { username: adminUsername, enabled: true }, verified.body.token)).status, 403);
    const toggled = await post('/api/2fa/toggle', { username: registration.username, enabled: true }, verified.body.token);
    assert.equal(toggled.status, 200);
    assert.equal(toggled.body.user.is2FAEnabled, true);
    const loginWithCode = await post('/api/login', { login: registration.username, password: registration.password });
    assert.equal(loginWithCode.body.require2FA, true);
    assert.equal(loginWithCode.body.token, undefined);
    const loginMail = JSON.parse(fs.readFileSync(path.join(directory, 'mail.json'), 'utf8'));
    assert.equal(loginMail.purpose, 'login');
    assert.equal((await post('/api/2fa/verify', { username: registration.username, code: 'abcdef' })).status, 400);
    const confirmedLogin = await post('/api/2fa/verify', { username: registration.username, code: loginMail.code });
    assert.equal(confirmedLogin.status, 200);
    assert.ok(confirmedLogin.body.token);
    assert.equal((await post('/api/2fa/verify', { username: registration.username, code: loginMail.code })).status, 400);
    assert.equal((await post('/api/2fa/toggle', { username: registration.username, enabled: false }, confirmedLogin.body.token)).status, 200);

    assert.equal((await post('/api/forgot-password', { email: registration.email })).status, 200);
    const secondMail = JSON.parse(fs.readFileSync(path.join(directory, 'mail.json'), 'utf8'));
    assert.equal(secondMail.purpose, 'reset');
    assert.equal((await post('/api/reset-password', { email: registration.email, code: '123', newPassword: 'новыйпароль123' })).status, 400);
    assert.equal((await post('/api/reset-password', { email: registration.email, code: secondMail.code, newPassword: 'новыйпароль123' })).status, 200);
    assert.equal((await post('/api/login', { login: registration.username, password: registration.password })).status, 401);
    assert.equal((await post('/api/login', { login: registration.username, password: 'новыйпароль123' })).status, 200);
  } finally {
    if (child.exitCode === null) {
      const exited = new Promise(resolve => child.once('exit', resolve));
      child.kill();
      await exited;
    }
    assert.ok(path.resolve(directory).startsWith(path.resolve(__dirname) + path.sep + 'auth-temp-'));
    fs.rmSync(directory, { recursive: true, force: true });
    const mongoose = require('mongoose');
    await mongoose.connect(mongoUri);
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  }
});
