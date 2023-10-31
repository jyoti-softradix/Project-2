export const userInvite = async (inviteUserLink) => {
  const result = ` <body style="font-family: 'Roboto', sans-serif;">
        <div style="max-width: 500px;margin:30px auto;">
            <div style="background:#E9E9E9;padding:20px 15px 15px 15px;box-shadow: 0px 0px 24px rgba(0, 0, 0, 0.03);">
                <div style="padding-bottom: 15px;text-align: center;">
                    <img src="https://ren-ath-dev.s3.us-east-2.amazonaws.com/emailTemplates/1679477742679-renAthletics.png" alt="">
                </div>
                <div style="background: #fff;text-align: center;padding:90px 20px">
                    <img src="https://ren-ath-dev.s3.us-east-2.amazonaws.com/emailTemplates/1679478767315-renAthletics.png" alt="">
                    <h4 style="font-weight: 700; font-size: 30px;color: #898888;margin:30px 0px 20px 0px">
                        Set Profile</h4>
                    <p style="font-size: 16px;font-weight: 500;margin: 0px;color: #898888;padding: 0px 20px;">Click on the
                        button below to <br>
                        set your profile.</p>
                        <a href="${inviteUserLink}"><button
                        style="font-family: 'Roboto', sans-serif;border:0px;background: #E9E9E9;border-radius: 8px;max-width: 350px;width:100%;height: 45px;color: #898888;font-weight: 600;margin: 30px 0px;">Set
                        Your Profile</button></a>
                    
                </div>
    
            </div>
        </div>
    </body>`;
  return result;
};
