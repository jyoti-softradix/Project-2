require("dotenv").config();
import nodemailer from "nodemailer";
module.exports = {
  async sendMail(to, subject, html) {
    const transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      secure: false,
      port: process.env.MAIL_PORT,
      auth: {
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.MAIL_FROM,
      to: to,
      subject: subject,
      html: html,
    };
    transporter.sendMail(mailOptions, function (err, info) {
      if (err) console.log("error", err.message);
      else console.log(info);
    });
  },
};
