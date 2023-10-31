import config from "config";
import { Sequelize, DataTypes } from "sequelize";

export default class DB {
  constructor() {
    this.seqClient = null;
    this.dbConfig = config.db;
    this.mysqlConfigClient = this.dbConfig.mysql.client;
    this.db = {};
    this.isDbRunning = true;
  }

  async connectMySQLClient() {
    try {
      this.seqClient = new Sequelize(
        this.mysqlConfigClient.database,
        this.mysqlConfigClient.username,
        this.mysqlConfigClient.password,
        {
          host: this.mysqlConfigClient.host,
          port: this.mysqlConfigClient.port,
          dialect: this.mysqlConfigClient.dialect,
          operatorsAliases: 0,
          logging: true,
          pool: {
            min: this.mysqlConfigClient.pool.min,
            max: this.mysqlConfigClient.pool.max,
            idle: this.mysqlConfigClient.pool.idle,
          },
          define: {
            underscored: true,
          },
          logging: false,
        }
      );
      this.seqClient
        .authenticate()
        .then(() => {
          console.log(
            "Connection to Client DB has been established successfully."
          );
        })
        .catch((err) => {
          console.error("Unable to connect to the Client database:", err);
        });
    } catch (err) {
      throw err;
    }
  }
  async init() {
    await this.connectMySQLClient();
    await this.setupModels();
  }

  async checkConnection() {
    try {
      return this.isDbRunning;
    } catch (error) {
      return !this.isDbRunning;
    }
  }

  async setupModels() {
    this.db.sqlClient = this.seqClient;
    this.db.sequelize = this.seqClient;
    this.db.models = {};
    this.db.models.Users = require("../../../database/models/user")(
      this.seqClient,
      DataTypes
    );
    this.db.models.Roles = require("../../../database/models/roles.js")(
      this.seqClient,
      DataTypes
    );
    this.db.models.UserLoginTime =
      require("../../../database/models/user_login_time.js")(
        this.seqClient,
        DataTypes
      );
    /**Associations */
    
    this.db.sqlClient.sync({ alter: true });
  }

  async getDB() {
    return this.db;
  }
}
