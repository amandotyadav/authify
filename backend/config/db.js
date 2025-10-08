import mongoose from "mongoose";

const connectDB = async () => {
  try {
    await mongoose.connect(`${process.env.MONGODB_URI}/mern-auth`);
    console.log("connected to the database successfully");
  } catch (error) {
    console.log("failed to connect to the database", error.message);
    process.exit(1);
  }
};

export default connectDB;
