const { sequelize, Op, QueryTypes } = require("sequelize");
import { ROLES } from "../../../config/constants";
import { verifyToken } from "../../V1/helpers/jwt";

export default class Auth {
  async init(db) {
    this.Models = db.models;
    this.sql = db.sqlClient
  }
  /**
   * find User by email
   * @param {string} email 
   * @returns user detail
   */

  /* find User by email  */
  getByEmail = async (email) => {
    return this.Models.Users.findOne({ where: { email: email} });
  };

  /* find User by token */
  getBytoken = async (token) => {
    return this.Models.Users.findOne({ where: { reset_password_token: token } });
  }

  /* find User by Id  */
  getUserById = async (userId) => {
    return this.Models.Users.findOne({
      attributes: { exclude: ['password', 'reset_password_token'] },
      where: {
        id: userId,
        deleted_at: null
      },
      raw: true,
    });
  };

  /* create login time */
  createLoginTime = async (data) => {
    return this.Models.UserLoginTime.create(data);
  }

  /* update User by Id  */
  updateUser = async (data, userId) => {
    return this.Models.Users.update(data, { where: { id: userId } });
  }

  /* find by email and logout Admin by Id  */
  logoutAdmin = async (data) => {
    const decoded = verifyToken(data);
    let getUser = await this.getByEmail(decoded.email);
    return this.Models.UserLoginTime.destroy({
      where: {
        user_id: getUser.id,
        login_time: {
          [Op.ne]: decoded.login_time,
        }
      },
    });
  }
}
