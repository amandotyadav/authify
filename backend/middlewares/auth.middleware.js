import jwt from "jsonwebtoken";
import sendResponse from "../utils/sendResponse.js";

const userAuth = async (req, res, next) => {
  const { auth_token } = req.cookies;
  if (!auth_token) return sendResponse(res, 400, { success: false, message: "Not Authorized. Login Again" });

  try {
    const decodedToken = jwt.verify(auth_token, process.env.JWT_SECRET);
    if (decodedToken.id) {
      req.body.userId = decodedToken.id;
    } else {
      return sendResponse(res, 401, { success: false, message: "Not Authorized. Login Again" });
    }
    next();
  } catch (error) {
    console.log("Error in userAuth middleware", error);
    return sendResponse(res, 500, { success: false, message: "Internal server error" });
  }
};

export default userAuth;
