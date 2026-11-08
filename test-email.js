require('dotenv').config({ path: require('node:path').join(__dirname, '.env'), quiet: true });
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function main() {
  try {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      throw new Error('EMAIL_USER или EMAIL_PASS не задан в .env');
    }
    const result = await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: 'deniscelik82@gmail.com',
      subject: 'Проверка почты Leniks Client',
      text: 'Тестовое письмо от Leniks Client.'
    });
    console.log('Письмо принято SMTP:', {
      accepted: result.accepted,
      rejected: result.rejected,
      response: result.response,
      messageId: result.messageId
    });
  } catch (error) {
    console.log('Ошибка отправки почты:', error.message);
    if (error.response) console.log('Ответ SMTP:', error.response);
    if (error.code) console.log('Код ошибки:', error.code);
    process.exitCode = 1;
  }
}

main();
