import { Schema, model } from "mongoose";
import { boolean, lowercase } from "zod";
import { required } from "zod/v4/core/util.cjs";
import { fa, tr } from "zod/v4/locales";

const userSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    passwordHash: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    fullName: {
      type: String,
    },
    twoFactorEnabled: {
      type: Boolean,
      default: false,
    },
    towFactorSecret: {
      type: String,
      default: undefined,
    },
    tokenVersion: {
      type: Number,
      default: 0,
    },
    resetPasswordToken: {
      type: String,
      default: undefined,
    },
    resetPasswordExpires: {
      type: Date,
      default: undefined,
    },
  },
  {
    timestamps: true,
  }
);

export const User = model("User", userSchema);
// in db -> users
