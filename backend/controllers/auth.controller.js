import transporter from "../config/nodemailer.js";
import User from "../models/User.model.js";
import sendResponse from "../utils/sendResponse.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    // validate the credentials
    if (!name || !email || !password)
      return sendResponse(res, 400, { success: false, message: "Please provide all the credentials" });

    // validate the password
    if (password.length < 6)
      return sendResponse(res, 400, { success: false, message: "Password must be atleast 6 characters long" });

    // check existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) return sendResponse(res, 400, { success: false, message: "User already exists" });

    // hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // save the credentials to database
    const user = await User.create({ name, email, password: hashedPassword });

    // gnerate token and save token to cookie
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    // save token to cookie
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // send welcome email to the user
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "Welcome to Authify",
      text: `Welcome to authify. Your account has been created with email id: ${email}`,
    };
    await transporter.sendMail(mailOptions);

    return sendResponse(res, 201, { success: true, message: "Registered successfully" });
  } catch (error) {
    console.log("error in register controller", error);
    return sendResponse(res, 500, { success: false, message: "Internal server error" });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    // validate the credentials
    if (!email || !password)
      return sendResponse(res, 400, { success: false, message: "Please provide all the credentials" });

    // check user in the database
    const user = await User.findOne({ email });
    if (!user) return sendResponse(res, 404, { success: false, message: "Invalid credentials" });

    // match the password
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) return sendResponse(res, 404, { success: false, message: "Invalid credentials" });

    // gnerate token and save token to cookie
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    // save token to cookie
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return sendResponse(res, 201, { success: true, message: "Logged in successfully" });
  } catch (error) {
    console.log("error in login controller", error);
    return sendResponse(res, 500, { success: false, message: "Internal server error" });
  }
};

export const logout = async (req, res) => {
  try {
    res.clearCookie("auth_token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });
    return sendResponse(res, 200, { success: true, message: "Logged out successfully" });
  } catch (error) {
    console.log("error in logout controller", error);
    return sendResponse(res, 500, { success: false, message: "Internal server error" });
  }
};

export const sendVerifyOTP = async (req, res) => {
  console.log("Inside sendVerifyOTP");
  try {
    const { userId } = req.body;
    const user = await User.findById(userId);

    if (user.isAccountVerified)
      return sendResponse(res, 400, { success: false, message: "Account is already verified" });

    const OTP = String(Math.floor(100000 + Math.random() * 900000));

    user.verifyOTP = OTP;
    user.verifyOTPExpiresAt = Date.now() + 24 * 60 * 60 * 1000;

    await user.save();

    // send otp to user
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      text: `Your OTP is ${OTP}. Verify your account using this OTP.`,
    };
    await transporter.sendMail(mailOptions);
    return sendResponse(res, 200, { success: true, message: "Verification OTP sent on email" });
  } catch (error) {
    console.log("error in logout controller", error);
    return sendResponse(res, 500, { success: false, message: "Internal server error" });
  }
};

export const verifyEmail = async (req, res) => {
  const { userId, OTP } = req.body;
  if (!userId || !OTP) return sendResponse(res, 400, { success: false, message: "Missing Details" });
  try {
    const user = await User.findById(userId);
    // check availability of the user
    if (!user) return sendResponse(res, 404, { success: false, message: "User not found!" });

    // match the OTP
    if (user.verifyOTP === "" || user.verifyOTP !== OTP)
      return sendResponse(res, 400, { success: false, message: "Invalid OTP" });

    // check otp expiry
    if (user.verifyOTPExpiresAt < Date.now()) return sendResponse(res, 400, { success: false, message: "OTP Expired" });

    // verify the user
    user.isAccountVerified = true;
    user.verifyOTP = "";
    user.verifyOTPExpiresAt = 0;

    await user.save();

    return sendResponse(res, 200, { success: true, message: "Email verified successfully" });
  } catch (error) {
    console.log("error in logout controller", error);
    return sendResponse(res, 500, { success: false, message: "Internal server error" });
  }
};

export const isAuthenticated = async (req, res) => {
  try {
    return sendResponse(res, 200, { success: true, message: "User is authenticated" });
  } catch (error) {
    console.log("error in isAuthenticated controller", error);
    return sendResponse(res, 500, { success: false, message: "Internal server error" });
  }
};

export const sendResetOTP = async (req, res) => {
  const { email } = req.body;
  if (!email) return sendResponse(res, 400, { success: false, message: "Email is required" });
  try {
    const user = await User.findOne({ email });
    if (!user) return sendResponse(res, 404, { success: false, message: "User not found" });

    // send OTP to the user
    const OTP = String(Math.floor(100000 + Math.random() * 900000));

    user.resetOTP = OTP;
    user.resetOTPExpiresAt = Date.now() + 15 * 60 * 1000;

    await user.save();

    // send otp to user
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Password Reset OTP",
      text: `Your OTP for resetting your password is ${OTP}. Use this OTP to proceed with resetting your password.`,
    };
    await transporter.sendMail(mailOptions);

    return sendResponse(res, 200, { success: true, message: "Reset otp sent successfully" });
  } catch (error) {
    console.log("error in sendResetOTP controller", error.message);
    return sendResponse(res, 500, { success: false, message: "Internal server error" });
  }
};

export const resetPassword = async (req, res) => {
  const { email, OTP, newPassword } = req.body;
  if (!email || !OTP || !newPassword)
    return sendResponse(res, 400, { success: false, message: "Email, OTP and new password are required" });

  try {
    const user = await User.findOne({ email });
    if (!user) return sendResponse(res, 400, { success: false, message: "User not found" });

    if (user.resetOTP === "" || user.resetOTP !== OTP)
      return sendResponse(res, 400, { success: false, message: "Invalid OTP" });

    if (user.resetOTPExpiresAt < Date.now()) return sendResponse(res, 400, { success: false, message: "OTP expired" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedPassword;
    user.resetOTP = "";
    user.resetOTPExpiresAt = 0;
    await user.save();

    return sendResponse(res, 200, { success: true, message: "Password has been reset successfully" });
  } catch (error) {
    return sendResponse(res, 500, { success: false, message: "Internal server error" });
  }
};
