require("dotenv").config();
import Services from "./user.services";
import { RESPONSE_CODES, ROLES } from "../../../config/constants.js";
import {
  successResponse,
  errorResponse,
} from "../../../config/responseHelper.js";
import { CommonMessages } from "../../../constants/message/common";
import { UserMessages } from "../../../constants/message/user";
import nodemailer from "../helpers/mail";
import randomstring from "randomstring";
import moment from "moment";
import { userInvite } from '../EmailTemplates/invite-user'
export default class User {
  async init(db) {
    this.services = new Services();
    this.Models = db.models;
    await this.services.init(db);
  }

  /* invite user */
  async inviteUser(req, res) {
    try {
      const { body, user } = req;
      /** check email exist or not */
      const checkEmail = await this.services.getUserByMail(body.email);
      if (checkEmail) {
        return res
          .status(400)
          .send(
            errorResponse(
              UserMessages.INVITE_ALREADY,
              null,
              null,
              RESPONSE_CODES.BAD_REQUEST
            )
          );
      }
      if ((body.role_id !== ROLES.ADMIN) && (body.role_id !== ROLES.SALES_REPRESTATIVE)) {
        return res
          .status(400)
          .send(
            errorResponse(
              CommonMessages.INVALID_USER,
              null,
              null,
              RESPONSE_CODES.POST
            )
          );
      }
      (body.org_id = user.org_id), (body.status = 0), (body.invite_status = 0);
      await this.services.createUser(body);
      const token = randomstring.generate(64);
      await this.Models.Users.update(
        { invite_token: token },
        { where: { email: body.email } }
      );
      const to = body.email.toLowerCase();
      const inviteUserLink = `${process.env.BASE_URL}set-profile/${token}`;
      const emailTemplate = await userInvite(inviteUserLink)
      const subject = "User Invite link";
      await nodemailer.sendMail(to, subject, emailTemplate);
      return res
        .status(201)
        .send(
          successResponse(
            UserMessages.INVITE_LINK,
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
  };

  /* set profile */
  async serProfile(req, res) {
    try {
      const { body } = req;
      /** check invite_token valid or not */
      const user = await this.services.getUserBytoken(body.token);
      if (!user) {
        return res
          .status(400)
          .send(
            errorResponse(
              UserMessages.INVALID_TOKEN,
              null,
              null,
              RESPONSE_CODES.POST
            )
          );
      }
      (body.status = 1), (body.invite_status = 1), (body.invite_token = null);
      await this.services.updateProfile(body, user.invite_token);
      return res
        .status(201)
        .send(
          successResponse(
            UserMessages.SET_PROFILE,
            null,
            {},
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
  };

  /* user's list */
  async listUser(req, res) {
    try {
      const { user, query } = req;
      const list = await this.services.getUserList(query, user.org_id);
      return res
        .status(200)
        .send(
          successResponse(UserMessages.LIST_USER, list, RESPONSE_CODES.GET)
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
  };

  /* pending user's list */
  async getAllPendingUser(req, res) {
    try {
      const { user, query } = req;
      const userList = await this.services.getAllPendingUsersList(
        query,
        user.org_id
      );

      return res
        .status(200)
        .send(
          successResponse(
            UserMessages.PENGDING_USER,
            userList,
            RESPONSE_CODES.GET
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
  };

  /* delete user */
  async deleteUser(req, res) {
    try {
      const { body, user } = req;
      if (body.id === 1) {
        return res
          .status(400)
          .send(
            errorResponse(
              UserMessages.NOT_DELETE_USER,
              null,
              null,
              RESPONSE_CODES.BAD_REQUEST
            )
          );
      }
      /** check user exist or not */
      const getUserById = await this.services.getById(body.id, user.org_id);
      if (!getUserById) {
        return res
          .status(404)
          .send(
            errorResponse(
              UserMessages.USER_NOT_FOUND,
              null,
              null,
              RESPONSE_CODES.NOT_FOUND
            )
          );
      }
      const updateData = {
        deleted_at: moment(new Date()).unix(),
      };
      await this.services.removeUser(updateData, body.id);
      return res
        .status(201)
        .send(
          successResponse(UserMessages.DELETE_USER, {}, RESPONSE_CODES.POST)
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
  };

  /** resend invite */
  async resendInvite(req, res) {
    try {
      const { body } = req;
      /** check email exist or not */
      const checkEmail = await this.services.getUserByMail(body.email);
      if (!checkEmail) {
        return res
          .status(404)
          .send(
            errorResponse(
              UserMessages.USER_NOT_FOUND,
              null,
              null,
              RESPONSE_CODES.NOT_FOUND
            )
          );
      }
      if (checkEmail.invite_status != 0 && checkEmail.invite_token == null) {
        return res.status(400).send(errorResponse(UserMessages.ALREADY_ACCEPTED_INVITE, null, null, RESPONSE_CODES.BAD_REQUEST))
      }

      const token = randomstring.generate(64);
      await this.Models.Users.update(
        { invite_token: token },
        { where: { email: body.email } }
      );
      const to = body.email.toLowerCase();
      const inviteUserLink = `${process.env.BASE_URL}set-profile/${token}`;
      const emailTemplate = await userInvite(inviteUserLink)
      const subject = "User Invite link";
      await nodemailer.sendMail(to, subject, emailTemplate);
      return res
        .status(201)
        .send(
          successResponse(
            UserMessages.INVITE_LINK,
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
  };

}
