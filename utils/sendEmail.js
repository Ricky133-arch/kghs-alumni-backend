const brevo = require('@getbrevo/brevo');

const apiInstance = new brevo.TransactionalEmailsApi();
apiInstance.setApiKey(brevo.TransactionalEmailsApiApiKeys.apiKey, process.env.BREVO_API_KEY);

const sendEmail = async ({ to, toName, subject, htmlContent }) => {
  const sendSmtpEmail = new brevo.SendSmtpEmail();

  sendSmtpEmail.subject = subject;
  sendSmtpEmail.htmlContent = htmlContent;
  sendSmtpEmail.sender = { name: 'KGHS Alumni Team', email: process.env.EMAIL_USER };
  sendSmtpEmail.to = [{ email: to, name: toName || '' }];

  try {
    const data = await apiInstance.sendTransacEmail(sendSmtpEmail);
    console.log('Email sent via Brevo API:', data);
  } catch (error) {
    console.error('Brevo API failed:', error.body || error);
    throw error;
  }
};

module.exports = sendEmail;