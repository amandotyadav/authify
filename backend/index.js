import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import connectDB from "./config/db.js";
import authRouter from "./routes/auth.routes.js";
import userRouter from "./routes/user.routes.js";

const app = express();

// middlewares
app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true }));

// routes
app.get("/", (req, res) => res.send("Api is working"));
app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`server is listening to port: ${PORT}`);
  connectDB();
});
