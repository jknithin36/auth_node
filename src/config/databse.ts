import mongoose from "mongoose";

export async function connectDatabase() {
  try {
    const mongoUri = process.env.MONGO_URI;
    if (!mongoUri) {
      throw new Error("MONGO_URI is not defined");
    }

    await mongoose.connect(mongoUri);
    console.log("Successfully connected to database");
  } catch (error) {
    console.error("Database connection failed:", error);
    process.exit(1);
  }
}
