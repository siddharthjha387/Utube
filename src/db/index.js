import mongoose from "mongoose";
import "dotenv/config";

import { DB_NAME } from "../contants.js";

export const connectDB = async () => {
  try {
    const connectionInstance = await mongoose.connect(
      `${process.env.MONGODB_URI}/${DB_NAME}`
    );
    console.log(
      `\n MongoDB connected !! DB HOST: ${connectionInstance.connection.host}`
    );
  } catch (err) {
    console.error("Error:", err);
    process.exit(1);
  }
};
