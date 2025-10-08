import User from "../models/User.model.js";
import sendResponse from "../utils/sendResponse.js";

export const getUserData = async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);
    if (!user) return sendResponse(res, 400, { success: false, message: "User not found" });

    return sendResponse(res, 200, {
      success: true,
      message: "User found successfully",
      data: {
        name: user.name,
        isAccountVerified: user.isAccountVerified,
      },
    });
  } catch (error) {
    console.log("error in getUserData controller", error.message);
    return sendResponse(res, 500, { success: false, message: "Internal server error" });
  }
};
