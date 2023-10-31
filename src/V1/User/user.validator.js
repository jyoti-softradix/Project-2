const Joi = require('@hapi/joi')

export const createUser = Joi.object({
  email: Joi.string().email().max(50).required(),
  role_id: Joi.number().required()
})
export const serProfileValidator = Joi.object({
  token: Joi.string().required(),
  first_name: Joi.string().required(),
  last_name: Joi.string().required(),
  password: Joi.string().min(8).max(20).pattern(new RegExp(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/)).message("Minimum 8 Characters (1 uppercase, lowercase, number and special character). Maximum 20 Characters are allowed.").required()
})

export const listAllUser = Joi.object({
  limit: Joi.number().min(0).max(100),
  length: Joi.number()
})

export const resendInvite = Joi.object({
  email: Joi.string().required().messages({
    "string.empty": "Email cannot be an empty field",
    "any.required": "Email is required"
  })
})