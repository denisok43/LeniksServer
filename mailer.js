require('dotenv').config();
const nodemailer = require('nodemailer');

const GMAIL_USER = process.env.EMAIL_USER || '';
const GMAIL_APP_PASSWORD = process.env.EMAIL_PASS || '';
const BRAND_NAME = 'Leniks Client';

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

async function sendCode(email, code, subject) {
  try {
    if (!GMAIL_USER || !GMAIL_APP_PASSWORD) throw new Error('Почта сервера не настроена');
    const result = await transporter.sendMail({
      from: { name: BRAND_NAME, address: GMAIL_USER },
      to: email,
      subject,
      text: `${BRAND_NAME}\n\nКод подтверждения: ${code}\n\nКод действует 10 минут. Если вы не запрашивали его, просто проигнорируйте это письмо.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#202124"><h1 style="font-size:22px">${BRAND_NAME}</h1><p>${subject}</p><p style="font-size:32px;font-weight:700;letter-spacing:6px">${code}</p><p>Код действует 10 минут.</p><p style="color:#666;font-size:13px">Если вы не запрашивали код, просто проигнорируйте это письмо.</p></div>`
    });
    if (!result.accepted?.some((address) => address.toLowerCase() === email.toLowerCase())) {
      throw new Error(`SMTP не подтвердил получателя ${email}`);
    }
    console.log('Gmail принял письмо:', { recipient: email, messageId: result.messageId, response: result.response });
  } catch (error) {
    console.error("Ошибка отправки почты:", error);
    throw error;
  }
}

function sendVerificationEmail(email, code) {
  return sendCode(email, code, `Подтверждение регистрации ${BRAND_NAME}`);
}

function sendPasswordResetEmail(email, code) {
  return sendCode(email, code, `Восстановление пароля ${BRAND_NAME}`);
}

function sendLoginCodeEmail(email, code) {
  return sendCode(email, code, `Код входа ${BRAND_NAME}`);
}

module.exports = { sendVerificationEmail, sendPasswordResetEmail, sendLoginCodeEmail };
