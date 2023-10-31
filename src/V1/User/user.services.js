import sequelize from 'sequelize';
const Op = sequelize.Op;
import { PAGINATION, RESPONSE_CODES } from '../../../config/constants';
import { UserMessages } from '../../../constants/message/user';
export default class User {
  async init(db) {
    this.Models = db.models;
  }

  /** create user */
  createUser = async (data) => {
    await this.Models.Users.create(data);
    await this.Models.Users.update({
      status: 0,
      invite_status: 0
    }, {
      where: {
        email: data.email
      }
    });
  };

  /** check user by invite_token */
  getUserBytoken = async (token) => {
    return this.Models.Users.findOne({ where: { invite_token: token } });
  };

  /** update user's profile by invite_token*/
  updateProfile = async (data, token) => {
    await this.Models.Users.update(data, { where: { invite_token: token } });
  };

  /** get user by email*/
  getUserByMail = async (email) => {
    return this.Models.Users.findOne({ where: { email: email }, raw: true });
  };

  /** get all users list with pagination and search filter and total count*/
  getUserList = async (query, orgId) => {
    let whereCondition = {
      org_id: orgId,
      deleted_at: null,
      role_id: { [Op.ne]: 3 },
      invite_status: 1,
    };
    const allUserCount = await this.Models.Users.count({
      where: whereCondition,
    });
    if (query.search) {
      whereCondition = {
        [Op.or]: [{ first_name: { [Op.like]: `%${query.search}%` } },
        { last_name: { [Op.like]: `%${query.search}%` } }],
        org_id: orgId,
        deleted_at: null,
        role_id: { [Op.ne]: 3 },
        invite_status: 1
      }
    }
    const allUsers = await this.Models.Users.findAll({
      where: whereCondition,
      order: [
        ['id', 'DESC'],
      ],
      offset: (parseInt(query.start) == 0) ? 0 : (parseInt(query.start) || PAGINATION.START) * (parseInt(query.limit) || PAGINATION.LIMIT) || PAGINATION.START,
      limit: (query.limit == -1) ? allUserCount : parseInt(query.limit) || PAGINATION.LIMIT,
      raw: true,
    });

    return { list: allUsers, total_records: allUserCount, filtered_records: allUsers.length }
  };

  /** get all pending users list with pagination and total count*/
  getAllPendingUsersList = async (query, orgId) => {
    let data = {
      org_id: orgId,
      role_id: { [Op.ne]: 3 },
      invite_status: 0
    }
    const allPendingUserCount = await this.Models.Users.count({
      where: data,
    });
    const allPendingUsers = await this.Models.Users.findAll({
      where: data,
      attributes: {
        exclude: ["password", "invite_token", "reset_password_token"],
      },
      order: [
        ['id', 'DESC'],
      ],
      offset: (parseInt(query.start) == 0) ? 0 : (parseInt(query.start) || PAGINATION.START) * (parseInt(query.limit) || PAGINATION.LIMIT) || PAGINATION.START,
      limit: (query.limit == -1) ? allPendingUserCount : parseInt(query.limit) || PAGINATION.LIMIT,
      raw: true,
    });
    return { list: allPendingUsers, total_records: allPendingUserCount, filtered_records: allPendingUsers.length }

  };

  /** get user detail by user id */
  getById = async (Id, orgId) => {
    return this.Models.Users.findOne({
      where: {
        id: Id,
        org_id: orgId,
        deleted_at:null
      }
    });
  };

  /** delete user by user id */
  removeUser = async (data, Id) => {
    return this.Models.Users.update(data, { where: { id: Id } });
  };

}

