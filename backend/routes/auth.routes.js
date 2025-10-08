import express from "express";
import {
  isAuthenticated,
  login,
  logout,
  register,
  sendVerifyOTP,
  verifyEmail,
} from "../controllers/auth.controller.js";
import userAuth from "../middlewares/auth.middleware.js";

const authRouter = express.Router();

authRouter.post("/register", register);
authRouter.post("/login", login);
authRouter.post("/logout", logout);
authRouter.post("/send-verify-otp", userAuth, sendVerifyOTP);
authRouter.post("/verify-account", userAuth, verifyEmail);
authRouter.post("/isAuth", userAuth, isAuthenticated);

export default authRouter;
