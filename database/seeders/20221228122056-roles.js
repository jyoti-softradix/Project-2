"use strict";

module.exports = {
  up: (queryInterface, Sequelize) => {
    return Promise.all([
      queryInterface.bulkDelete("roles", null, { truncate: true }),
      queryInterface.bulkInsert(
        "roles",
        [
          {
            id: 1,
            name: "Admin",
            created_at: new Date(),
            updated_at: new Date(),
          },
          {
            id: 2,
            name: "User",
            created_at: new Date(),
            updated_at: new Date(),
          }
        ],
        { truncate: true }
      ),
    ]);
  },

  down: (queryInterface) =>
    queryInterface.bulkDelete("roles", null, { truncate: true }),
};
