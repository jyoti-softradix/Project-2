require("dotenv").config();
export const sendMessage = async (data) => {
    try {
        const accountSid = process.env.TWILIO_ACCOUNT_SID;
        const authToken = process.env.TWILIO_AUTH_TOKEN;
        const client = require('twilio')(accountSid, authToken);

        const message = client.messages.create({
            body: data.message,
            from: process.env.TWILIO_PHONE,
            to: data.to
        })
        console.log("data", data)
        console.log("message", message)
        if (message) {
            return message.sid;
        } else {
            return null
        }
    }catch (err) {
      console.log("twilio errorrr====",err)
      return null
    }
}

