/** function for return Success Response */
 const successResponse = (msg, data, code) => ({
    status: 1,
    message: msg,
    code,
    data: data || null,
  });
  /** function for return Error Response */
  const errorResponse = (msg, data, code) => ({
    status: 0,
    message: msg,
    code,
    data: data || null,
  });
  
  module.exports = { successResponse, errorResponse }