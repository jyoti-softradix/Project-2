const swaggerJsdoc = require("swagger-jsdoc");

const options = {
  definition: {
    opneapi: "3.0.0",
    info: {
      description: "Dummy Api's.",
      title: "Dummy Project",
      version: "1.0.0",
    },
   host: process.env.API_BASE_URL,
  },
  apis: [],
};

// '../src/user/index'

const swaggerSpec = swaggerJsdoc(options);
swaggerSpec.tags = ["Admin", "SalesRepresentative"];

swaggerSpec.paths = {
  "/auth/login": {
    post: {
      tags: ["auth"],
      summary: "Login Api",
      parameters: [
        {
          name: "body",
          in: "body",
          required: true,
          type: "object",
          schema: {
            properties: {
              email: {
                type: "string",
                default: "admin@yopmail.com",
              },
              password: {
                type: "string",
                default: "123456",
              },
            },
          },
        },
      ],
      responses: {
        200: {
          description: "ok",
        },
      },
    },
  },
  "/auth/forgot-password": {
    post: {
      tags: ["auth"],
      summary: "APi for forgot password",
      parameters: [
        {
          name: "body",
          in: "body",
          required: true,
          type: "object",
          schema: {
            properties: {
              email: {
                type: "string",
              },
            },
          },
        },
      ],
      responses: {
        200: {
          description: "ok",
        },
      },
    },
  },
  "/auth/reset-password": {
    post: {
      tags: ["auth"],
      summary: "APi for reset password",
      parameters: [
        {
          name: "body",
          in: "body",
          required: true,
          type: "object",
          schema: {
            properties: {
              token: {
                type: "string",
              },
              password: {
                type: "string",
              },
            },
          },
        },
      ],
      responses: {
        200: {
          description: "ok",
        },
      },
    },
  },
  "/auth/change-password": {
    post: {
      tags: ["auth"],
      summary: "APi for change password",
      parameters: [
        {
          name: "body",
          in: "body",
          required: true,
          type: "object",
          schema: {
            properties: {
              old_password: {
                type: "string",
              },
              new_password: {
                type: "string",
              },
            },
          },
        },
      ],
      responses: {
        200: {
          description: "ok",
        },
      },
      security: [
        {
          authorization: [],
        },
      ],
    },
  },

  "/users/list": {
    get: {
      tags: ["user"],
      summary: "APi for get user list/pag",
      description: "search--> first_name or last_name",
      parameters: [
        {
          name: "search",
          in: "query",
          type: "string",
          required: false,
        },
        {
          name: "start",
          in: "query",
          type: "string",
          required: false,
        },
        {
          name: "limit",
          in: "query",
          type: "string",
          required: false,
        },
      ],
      responses: {
        200: {
          description: "ok",
        },
      },
      security: [
        {
          authorization: [],
        },
      ],
    },
  },
  "/users/pending/list": {
    get: {
      tags: ["user"],
      summary: "APi for get pending users list",
      parameters: [
        {
          name: "start",
          in: "query",
          type: "string",
          required: false,
        },
        {
          name: "limit",
          in: "query",
          type: "string",
          required: false,
        },
      ],
      responses: {
        200: {
          description: "ok",
        },
      },
      security: [
        {
          authorization: [],
        },
      ],
    },
  },
  "/user/delete": {
    delete: {
      tags: ["user"],
      summary: "APi for delete user",
      parameters: [
        {
          name: "body",
          in: "body",
          required: true,
          type: "object",
          schema: {
            properties: {
              id: {
                type: "integer",
              },
            },
          },
        },
      ],
      responses: {
        200: {
          description: "ok",
        },
      },
      security: [
        {
          authorization: [],
        },
      ],
    },
  },
  "/auth/my-account-information": {
    get: {
      tags: ["auth"],
      summary: "APi for get my-account-information",
      responses: {
        200: {
          description: "ok",
        },
      },
      security: [
        {
          authorization: [],
        },
      ],
    },
  },
  "/auth/update-account-information": {
    post: {
      tags: ["auth"],
      summary: "APi for update-account-information",
      parameters: [
        {
          name: "body",
          in: "body",
          required: true,
          type: "object",
          schema: {
            properties: {
              first_name: {
                type: "string",
              },
              last_name: {
                type: "string",
              },
              phone_number: {
                type: "string",
              },
            },
          },
        },
      ],
      responses: {
        200: {
          description: "ok",
        },
      },
      security: [
        {
          authorization: [],
        },
      ],
    },
  },

  "/token-verify": {
    post: {
      tags: ["auth"],
      summary: "APi for verify token",
      description: "type---> 1 for FORGOT, 2 for SET_PROFILE",
      parameters: [
        {
          name: "body",
          in: "body",
          required: true,
          type: "object",
          schema: {
            properties: {
              type: {
                type: "number",
              },
              token: {
                type: "string",
              },
            },
          },
        },
      ],
      responses: {
        200: {
          description: "ok",
        },
      },
    },
  },
  "/user/resend-invite": {
    post: {
      tags: ["user"],
      summary: "APi for resend invite email to user",
      parameters: [
        {
          name: "body",
          in: "body",
          required: true,
          type: "object",
          schema: {
            properties: {
              email: {
                type: "string",
              },
            },
          },
        },
      ],
      responses: {
        200: {
          description: "ok",
        },
      },
      security: [
        {
          authorization: [],
        },
      ],
    },
  },
};

swaggerSpec.securityDefinitions = {
  authorization: {
    type: "apiKey",
    name: "authorization",
    in: "header",
  },
};

module.exports = swaggerSpec;
