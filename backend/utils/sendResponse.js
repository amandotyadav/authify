const sendResponse = async (res, statusCode, payload) => {
  return res.status(statusCode).json(payload);
};

export default sendResponse;
