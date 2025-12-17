import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.models";
import { checkPassword, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import {
  createRefreshToken,
  createToken,
  verifyRefreshToken,
} from "../../lib/token";
import crypto from "crypto";
function getAppURl() {
  const port = process.env.PORT || 3000;
  return `http://localhost:${port}`;
}

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);

    // Validation using zod

    if (!result.success) {
      return res.status(422).json({
        success: false,
        message: "Invalid Data!",
        errors: result.error.flatten(),
      });
    }

    const { email, password, fullName } = result.data;

    const normalizeEmail = email.toLowerCase().trim(); // removing spaces

    const isUserExists = await User.findOne({ email: normalizeEmail });

    if (isUserExists) {
      return res.status(409).json({
        success: false,
        message: "User Already Exists",
      });
    }

    // password Hash - function in hashPassword

    const passwordHash = await hashPassword(password);

    // user creation

    const newUser = await User.create({
      email: normalizeEmail,
      passwordHash,
      role: "user",
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    // send email verification to User

    const verifyToken = jwt.sign(
      { sub: newUser.id },
      process.env.JWT_ACCESS_SECRET!,
      {
        expiresIn: "1d",
      }
    );

    const verifyUrl = `${getAppURl()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newUser.email,
      "Verify Your Email",
      `<p>Pleaase verify you email by clicking this link : </p> 
      
      <p><a href=${verifyUrl}>${verifyUrl}</a></p>`
    );

    return res.status(201).json({
      success: true,
      message: "User Sucessfully Created",

      user: {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string | undefined;

  if (!token) {
    return res.status(400).json({
      success: false,
      message: "Verfication Failed",
    });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      sub: string;
    };

    const user = await User.findById(payload.sub); // id we stored while creating jwt

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User Not exists" });
    }

    if (user.isEmailVerified) {
      return res
        .status(409)
        .json({ success: false, message: "User Already Verified" });
    }

    user.isEmailVerified = true;
    await user.save();

    return res.status(200).json({ success: true, message: "Email is Verifed" });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(422).json({
        success: false,
        message: "Invalid Data!",
        errors: result.error.flatten(),
      });
    }

    const { email, password } = result.data;

    const normalizeEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizeEmail });

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "Invaild Email or Password" });
    }

    const ok = await checkPassword(password, user.passwordHash);

    if (!ok) {
      return res
        .status(400)
        .json({ status: false, message: "User password is Incorrect" });
    }

    if (!user.isEmailVerified) {
      return res
        .status(403)
        .json({ status: false, message: "Please Verify Before login" });
    }

    const accessToken = createToken(user.id, user.role, user.tokenVersion);

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 1000,
    });

    return res.status(200).json({
      success: true,
      message: "Login is Sucessful",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailverified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}

export async function refreshHandler(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken as string | undefined;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token Missing",
      });
    }

    const payload = verifyRefreshToken(token);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "User Not Found" });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res
        .status(401)
        .json({ success: false, message: "Refresh Token Invalidated" });
    }

    const newAcessToken = createToken(user.id, user.role, user.tokenVersion);

    const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 1000,
    });

    return res.status(200).json({
      success: true,
      message: "Token Refreshed",
      newAcessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailverified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    console.log(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}

export async function logoutHandler(req: Request, res: Response) {
  res.clearCookie("refreshToken", { path: "/" });

  return res.status(200).json({ success: true, message: "Logout Successful" });
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  const { email } = req.body as { email?: string };

  if (!email) {
    return res.status(400).json({
      success: false,
      message: "Email is required",
    });
  }

  const normalizeEmail = email.toLowerCase().trim();

  try {
    const user = await User.findOne({ email: normalizeEmail });

    if (user) {
      const rawToken = crypto.randomBytes(32).toString("hex");

      const tokenHash = crypto
        .createHash("sha256")
        .update(rawToken)
        .digest("hex");

      user.resetPasswordToken = tokenHash;
      user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);

      await user.save();

      const resetUrl = `${getAppURl()}/auth/reset-password?token=${rawToken}`;

      await sendEmail(
        user.email,
        "Reset Your Password",
        `<p>Click the link below to reset your password:</p>
         <p><a href="${resetUrl}">${resetUrl}</a></p>`
      );
    }

    // Always return same response (security best practice)
    return res.status(200).json({
      success: true,
      message: "If account exists, a password reset link has been sent",
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  const { token, password } = req.body as {
    token?: string;
    password?: string;
  };

  if (!token) {
    return res.status(400).json({
      success: false,
      message: "Token is required",
    });
  }

  if (!password || password.length < 6) {
    return res.status(400).json({
      success: false,
      message: "Password must be at least 6 characters long",
    });
  }

  try {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired token",
      });
    }

    // 🔐 Update password
    const newPasswordHash = await hashPassword(password);
    user.passwordHash = newPasswordHash;

    // 🧹 Clear reset fields
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    // 🔄 Invalidate existing refresh tokens
    user.tokenVersion += 1;

    await user.save();

    return res.status(200).json({
      success: true,
      message: "Password reset successful",
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
}
