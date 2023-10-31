const dotenv =  require('dotenv');


// eslint-disable-next-line no-unused-vars
const env = dotenv.config();
module.exports = {
  development: {
    host: process.env.DB_HOST,
    username: process.env.DB_USER_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    database: process.env.DB_DATABASE,
    dialect: process.env.DB_DIALECT,
  },
};