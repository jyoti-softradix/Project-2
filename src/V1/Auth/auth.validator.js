const Joi = require('@hapi/joi')

export const signupValidator = Joi.object({
  first_name: Joi.string().required(),
  last_name: Joi.string().required(),
  email: Joi.string().email().trim().required(),
  password: Joi.string().min(8).max(20).pattern(new RegExp(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/)).message("Minimum 8 Characters (1 uppercase, lowercase, number and special character). Maximum 20 Characters are allowed.").required()
})

const loginValidator = Joi.object({
  email: Joi.string().email().trim().required(),
  password: Joi.string().required().messages({
    "string.empty": `Password cannot be an empty field`,
    "any.required": 'Password is required'
  })
})

const forgotPasswordValidator = Joi.object().keys({
  email: Joi.string().email().max(50).required(),
})

const resetPasswordValidator = Joi.object().keys({
  token: Joi.string().required(),
  password: Joi.string().min(8).max(20).pattern(new RegExp(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/)).message("Minimum 8 Characters (1 uppercase, lowercase, number and special character). Maximum 20 Characters are allowed.").required()
})

const changePasswordValidator = Joi.object().keys({
  old_password: Joi.string().required().error(() => "Old password is required"),
  new_password: Joi.string().min(8).max(20).pattern(new RegExp(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/)).message("Minimum 8 Characters (1 uppercase, lowercase, number and special character). Maximum 20 Characters are allowed.").required()
})

const updateInfoValidator = Joi.object().keys({
  first_name: Joi.string().required(),
  last_name: Joi.string().required(),
  phone_number: Joi.string().optional().allow("", null),
})

module.exports = { loginValidator, forgotPasswordValidator, resetPasswordValidator, changePasswordValidator, updateInfoValidator }
