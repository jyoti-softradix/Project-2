require('dotenv').config();

const db = {
  development:{
    mysql: {
      client: {
        host: process.env.DB_HOST,
        username: process.env.DB_USER_NAME,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
        database: process.env.DB_DATABASE,
        dialect: process.env.DB_DIALECT,
        pool: {
          min: 2,
          max: 5,
          acquire: 30000,
          idle: 10000,
        },
      },
    },
  },
};

module.exports = db