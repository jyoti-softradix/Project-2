require("dotenv").config();
import Services from "./auth.services";
import bcrypt from "bcrypt";
import { RESPONSE_CODES, ROLES, TOKEN_TYPE } from "../../../config/constants";
import { successResponse, errorResponse } from "../../../config/responseHelper";
import { AuthMessages } from "../../../constants/message/auth";
import { CommonMessages } from "../../../constants/message/common";
import { refreshToken } from "../helpers/jwt";
import nodemailer from "../helpers/mail";
import randomstring from "randomstring";
import moment from "moment";
import { forgetPassword } from "../EmailTemplates/forget-password";
import { sendMessage } from "../helpers/sms";
import {generateOTP} from "../helpers/commonFunction"

export default class Auth {
  async init(db) {
    this.services = new Services();
    this.Models = db.models;
    await this.services.init(db);
  }

  /* login */
  async login(req, res) {
    const { email, password } = req.body;
    try {
      /** check user email */
      const checkEmail = await this.services.getByEmail(email);
      if (!checkEmail) {
        return res.status(400)
          .send(errorResponse(
            AuthMessages.INVALID_EMAIL,
            null,
            RESPONSE_CODES.BAD_REQUEST
          )
          );
      }
      /** check user password */
      const checkPassword = await bcrypt.compare(password, checkEmail.password);
      if (!checkPassword) {
        return res
          .status(400)
          .send(
            errorResponse(
              AuthMessages.INVALID_PASSWORD,
              null,
              RESPONSE_CODES.BAD_REQUEST
            )
          );
      }
      const loginTime = moment(new Date()).unix();
      const createData = { user_id: checkEmail.id, login_time: loginTime };
      await this.services.createLoginTime(createData);
      const getUser = await this.services.getUserById(checkEmail.id);
      console.log(getUser, "getUser")
      //twilio sms sent here
      const OTP = await generateOTP();
      const userMobNumber = getUser.country_code.trim() + getUser.phone_number.trim()
      const name = getUser.first_name + " " + getUser.last_name;
      console.log(name, "name")
      const twiloParams = {
        to: userMobNumber,
        message: AuthMessages.TWILIO_OTP_MESSAGE_PARA1 + name + AuthMessages.TWILIO_OTP_MESSAGE_PARA2 + OTP + AuthMessages.TWILIO_OTP_MESSAGE_PARA3,
      }
      console.log(twiloParams, "twiloParams")
      await sendMessage(twiloParams)
      /** generate token */
      const token = refreshToken(getUser);
      return res
        .status(201)
        .send(
          successResponse(AuthMessages.LOGIN_SUCCESS, token, RESPONSE_CODES.POST)
        );
    } catch (error) {
      console.log(error, "===============")
      return res.status(500).send(errorResponse(CommonMessages.ERROR, null, RESPONSE_CODES.POST));
    }
  }

  /* forgot password */
  async forgotPassword(req, res) {
    try {
      const { body } = req;
      /** check email */
      const checkEmail = await this.services.getByEmail(body.email);
      if (!checkEmail) {
        return res
          .status(404)
          .send(
            errorResponse(
              AuthMessages.EMAIL_NOT_FOUND,
              null,
              null,
              RESPONSE_CODES.NOT_FOUND
            )
          );
      }
      const token = randomstring.generate(64);
      await checkEmail.update({ reset_password_token: token });
      /** forgot password link */
      const forgotPasswordLink = `${process.env.BASE_URL}reset-password/${token}`;
      console.log(forgotPasswordLink)
      const emailTemplate = await forgetPassword(forgotPasswordLink);

      const subject = "Forgot password link";

      const emailResult = await nodemailer.sendMail(
        checkEmail.email,
        subject,
        emailTemplate
      );
      console.log("emailResult", emailResult);
      return res
        .status(201)
        .send(
          successResponse(
            AuthMessages.FORGOT_PASSWORD_LINK,
            null,
            null,
            RESPONSE_CODES.POST
          )
        );
    } catch (error) {
      return res
        .status(500)
        .send(
          errorResponse(
            CommonMessages.ERROR,
            null,
            null,
            RESPONSE_CODES.SERVER_ERROR
          )
        );
    }
  }

  /* reset password */
  async resetPassword(req, res) {
    try {
      const { body } = req;
      const user = await this.services.getBytoken(body.token);
      if (!user) {
        return res
          .status(400)
          .send(
            errorResponse(
              AuthMessages.INVALID_TOKEN,
              null,
              null,
              RESPONSE_CODES.BAD_REQUEST
            )
          );
      }
      await this.Models.Users.update(
        {
          reset_password_token: "",
          password: body.password,
        },
        {
          where: {
            reset_password_token: body.token,
          },
        }
      );
      return res
        .status(201)
        .send(
          successResponse(
            AuthMessages.RESET_PASSWORD,
            null,
            null,
            RESPONSE_CODES.POST
          )
        );
    } catch (error) {
      return res
        .status(500)
        .send(
          errorResponse(
            CommonMessages.ERROR,
            null,
            null,
            RESPONSE_CODES.SERVER_ERROR
          )
        );
    }
  }

  /* change password */
  async changePassword(req, res) {
    try {
      const { user, body, headers } = req;
      const passwordMatch = await bcrypt.compare(
        body.old_password,
        user.password
      );
      if (!passwordMatch) {
        return res
          .status(400)
          .send(
            errorResponse(
              AuthMessages.WRONG_PASSWORD,
              null,
              RESPONSE_CODES.BAD_REQUEST
            )
          );
      }
      if (body.old_password === body.new_password) {
        return res
          .status(400)
          .send(
            errorResponse(
              AuthMessages.NEW_PASSWORD_COMPARISON,
              null,
              RESPONSE_CODES.BAD_REQUEST
            )
          );
      }
      await this.services.updateUser({ password: body.new_password }, user.id);
      await this.services.logoutAdmin(headers.authorization);
      return res
        .status(201)
        .send(
          successResponse(
            AuthMessages.PASSWORD_CHANGE_SUCCESS,
            {},
            RESPONSE_CODES.POST
          )
        );
    } catch (error) {
      return res
        .status(500)
        .send(
          errorResponse(CommonMessages.ERROR, null, RESPONSE_CODES.SERVER_ERROR)
        );
    }
  }

  /* get Profile */
  async getProfile(req, res) {
    try {
      const { user } = req;
      const findUser = await this.services.getUserById(user.id);
      if (!findUser) {
        return res
          .status(400)
          .send(
            errorResponse(
              AuthMessages.INVALID_USER,
              null,
              RESPONSE_CODES.BAD_REQUEST
            )
          );
      }
      return res
        .status(201)
        .send(
          successResponse(
            AuthMessages.GET_SUCCESS,
            findUser,
            RESPONSE_CODES.POST
          )
        );
    } catch (error) {
      return res
        .status(500)
        .send(
          errorResponse(CommonMessages.ERROR, null, RESPONSE_CODES.SERVER_ERROR)
        );
    }
  }

  /* update Profile */
  async updateProfile(req, res) {
    try {
      const { user, body } = req;
      const findUser = await this.services.getUserById(user.id);
      if (!findUser) {
        return res
          .status(400)
          .send(
            errorResponse(
              AuthMessages.INVALID_USER,
              null,
              RESPONSE_CODES.BAD_REQUEST
            )
          );
      }
      await this.services.updateUser(body, findUser.id);
      return res
        .status(201)
        .send(
          successResponse(AuthMessages.UPDATE_INFO, {}, RESPONSE_CODES.POST)
        );
    } catch (error) {
      return res
        .status(500)
        .send(
          errorResponse(CommonMessages.ERROR, null, RESPONSE_CODES.SERVER_ERROR)
        );
    }
  }

  /* verify token */
  async verifyToken(req, res) {
    try {
      const { body } = req;
      let whereCondition = {};
      if (body.type === TOKEN_TYPE.FORGOT) {
        whereCondition = {
          reset_password_token: req.body.token,
        };
      } else if (body.type === TOKEN_TYPE.SET_PROFILE) {
        whereCondition = {
          invite_token: req.body.token,
        };
      }
      const findToken = await this.Models.Users.findOne({
        where: whereCondition,
        raw: true,
      });

      if (!findToken) {
        return res
          .status(404)
          .send(
            errorResponse(
              AuthMessages.DATA_NOT_FOUND,
              null,
              RESPONSE_CODES.NOT_FOUND
            )
          );
      }
      return res
        .status(200)
        .send(successResponse(AuthMessages.VALID, null, RESPONSE_CODES.GET));
    } catch (error) {
      return res
        .status(500)
        .send(
          errorResponse(CommonMessages.ERROR, null, RESPONSE_CODES.SERVER_ERROR)
        );
    }
  }
}
