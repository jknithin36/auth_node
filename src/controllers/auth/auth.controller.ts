// src/controllers/auth/auth.controller.ts
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
import { OAuth2Client } from "google-auth-library";
import { authenticator } from "otplib";

function getAppURL() {
  const port = process.env.PORT || 3000;
  return `http://localhost:${port}`;
}

function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URL;

  if (!clientId || !clientSecret || !redirectUri) {
    throw new Error("Google client config missing");
  }

  return new OAuth2Client({
    clientId,
    clientSecret,
    redirectUri,
  });
}

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);
    console.log(result);
    if (!result.success) {
      return res.status(422).json({
        success: false,
        message: "Invalid Data!",
        errors: result.error.flatten(),
      });
    }

    const { email, password, fullName } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    const existing = await User.findOne({ email: normalizedEmail });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "User Already Exists",
      });
    }

    const passwordHash = await hashPassword(password);

    const newUser = await User.create({
      email: normalizedEmail,
      passwordHash,
      fullName,
      role: "user",
      isEmailVerified: false,
      twoFactorEnabled: false,
      towFactorSecret: undefined,
      tokenVersion: 0,
    });

    const verifyToken = jwt.sign(
      { sub: newUser.id },
      process.env.JWT_ACCESS_SECRET as string,
      { expiresIn: "1d" }
    );

    const verifyUrl = `${getAppURL()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newUser.email,
      "Verify Your Email",
      `
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Verify Email</title>
    </head>
    <body style="margin:0;padding:0;background-color:#f4f6fb;font-family:Arial,Helvetica,sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0" style="padding:24px 12px;">
        <tr>
          <td align="center">
            <table width="600" style="max-width:600px;background:#ffffff;border-radius:12px;overflow:hidden;
                   box-shadow:0 8px 24px rgba(0,0,0,0.08);">
              
              <!-- Header -->
              <tr>
                <td style="background:linear-gradient(135deg,#4f46e5,#7c3aed);
                           padding:20px 24px;color:#ffffff;">
                  <h2 style="margin:0;font-size:20px;">Your App</h2>
                  <p style="margin:6px 0 0;font-size:13px;opacity:0.9;">
                    Email Verification
                  </p>
                </td>
              </tr>

              <!-- Body -->
              <tr>
                <td style="padding:24px;">
                  <h3 style="margin:0 0 10px;font-size:18px;color:#111827;">
                    Verify your email address
                  </h3>

                  <p style="margin:0 0 16px;font-size:14px;color:#374151;line-height:1.6;">
                    Thanks for signing up. Please confirm your email address by clicking the button below.
                  </p>

                  <a href="${verifyUrl}"
                     style="display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;
                            padding:12px 20px;border-radius:8px;font-size:14px;font-weight:600;">
                    Verify Email
                  </a>

                  <p style="margin:18px 0 0;font-size:12px;color:#6b7280;">
                    This link will expire in 24 hours. If you didn’t create this account, you can safely ignore this email.
                  </p>

                  <p style="margin:14px 0 6px;font-size:12px;color:#6b7280;">
                    Or copy and paste this link into your browser:
                  </p>

                  <p style="margin:0;font-size:12px;word-break:break-all;color:#4f46e5;">
                    ${verifyUrl}
                  </p>
                </td>
              </tr>

              <!-- Footer -->
              <tr>
                <td style="padding:14px 24px;background:#fafafa;border-top:1px solid #e5e7eb;">
                  <p style="margin:0;font-size:11px;color:#9ca3af;">
                    © Your App • This is an automated message, please do not reply.
                  </p>
                </td>
              </tr>

            </table>
          </td>
        </tr>
      </table>
    </body>
  </html>
  `
    );

    return res.status(201).json({
      success: true,
      message: "User Successfully Created",
      user: {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
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
    return res.status(401).json({
      success: false,
      message: "Verification Failed",
    });
  }

  try {
    const payload = jwt.verify(
      token,
      process.env.JWT_ACCESS_SECRET as string
    ) as {
      sub: string;
    };

    console.log(payload);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User Not exists",
      });
    }

    if (user.isEmailVerified) {
      return res.status(409).json({
        success: false,
        message: "User Already Verified",
      });
    }

    user.isEmailVerified = true;
    await user.save();

    return res.status(200).json({
      success: true,
      message: "Email is Verified",
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
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

    const { email, password, twoFactorCode } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail }).select(
      "+passwordHash +towFactorSecret"
    );

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid Email or Password",
      });
    }

    if (!user.passwordHash) {
      return res.status(500).json({
        success: false,
        message: "Internal Server Error",
        error:
          "passwordHash missing for this user (select:false not overridden)",
      });
    }

    const ok = await checkPassword(password, user.passwordHash);

    if (!ok) {
      return res.status(400).json({
        success: false,
        message: "Invalid Email or Password",
      });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({
        success: false,
        message: "Please verify before login",
      });
    }

    if (user.twoFactorEnabled) {
      if (!twoFactorCode || typeof twoFactorCode !== "string") {
        return res.status(400).json({
          success: false,
          message: "Two Factor code is required",
        });
      }

      if (!user.towFactorSecret) {
        return res.status(400).json({
          success: false,
          message: "Two Factor misconfigured for this account",
        });
      }

      const isValid = authenticator.check(twoFactorCode, user.towFactorSecret);

      if (!isValid) {
        return res.status(400).json({
          success: false,
          message: "Invalid Two Factor code",
        });
      }
    }

    const accessToken = createToken(user.id, user.role, user.tokenVersion);
    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    return res.status(200).json({
      success: true,
      message: "Login is Successful",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
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
      return res.status(401).json({
        success: false,
        message: "User Not Found",
      });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        success: false,
        message: "Refresh Token Invalidated",
      });
    }

    const accessToken = createToken(user.id, user.role, user.tokenVersion);
    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    return res.status(200).json({
      success: true,
      message: "Token Refreshed",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}

export async function logoutHandler(_req: Request, res: Response) {
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

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const user = await User.findOne({ email: normalizedEmail });

    if (user) {
      const rawToken = crypto.randomBytes(32).toString("hex");

      const tokenHash = crypto
        .createHash("sha256")
        .update(rawToken)
        .digest("hex");

      user.resetPasswordToken = tokenHash;
      user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);

      await user.save();

      const resetUrl = `${getAppURL()}/auth/reset-password?token=${rawToken}`;

      await sendEmail(
        user.email,
        "Reset Your Password",
        `<p>Click the link below to reset your password:</p><p><a href="${resetUrl}">${resetUrl}</a></p>`
      );
    }

    return res.status(200).json({
      success: true,
      message: "If account exists, a password reset link has been sent",
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  const { token, password } = req.body as { token?: string; password?: string };

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

    const newPasswordHash = await hashPassword(password);
    user.passwordHash = newPasswordHash;

    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    user.tokenVersion += 1;
    await user.save();

    return res.status(200).json({
      success: true,
      message: "Password reset successful",
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}

export async function googleAuthStart(_req: Request, res: Response) {
  try {
    const client = getGoogleClient();

    const url = client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
    });

    return res.redirect(url);
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}

export async function googleAuthCallbackHandler(req: Request, res: Response) {
  const googleCode = req.query.code as string | undefined;

  if (!googleCode) {
    return res.status(400).json({
      success: false,
      message: "Missing Google Code",
    });
  }

  try {
    const client = getGoogleClient();

    const { tokens } = await client.getToken(googleCode);

    if (!tokens.id_token) {
      return res.status(400).json({
        success: false,
        message: "No Google ID token present",
      });
    }

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID as string,
    });

    const payload = ticket.getPayload();

    const email = payload?.email;
    const emailVerified = payload?.email_verified;

    if (!email || !emailVerified) {
      return res.status(400).json({
        success: false,
        message: "Google email missing or not verified",
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString("hex");
      const passwordHash = await hashPassword(randomPassword);

      user = await User.create({
        email: normalizedEmail,
        passwordHash,
        role: "user",
        isEmailVerified: true,
        twoFactorEnabled: false,
        towFactorSecret: undefined,
        tokenVersion: 0,
      });
    } else {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }
    }

    const accessToken = createToken(
      user.id,
      user.role as "user" | "admin",
      user.tokenVersion
    );

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    const isProd = process.env.NODE_ENV === "production";

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    return res.status(200).json({
      success: true,
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}

export async function twoFactorSetupHandler(req: Request, res: Response) {
  const authUser = (req as any).user;

  if (!authUser) {
    return res
      .status(401)
      .json({ success: false, message: "User not authenticated" });
  }

  try {
    const user = await User.findById(authUser.id);

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const secret = authenticator.generateSecret();
    const issuer = "NithinAuthPractice";
    const otpAuthUrl = authenticator.keyuri(user.email, issuer, secret);

    user.towFactorSecret = secret;
    user.twoFactorEnabled = false;

    await user.save();

    return res.status(200).json({
      success: true,
      message: "2FA setup created. Verify to enable.",
      otpAuthUrl,
      secret,
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}

export async function twoFactorAuthVerify(req: Request, res: Response) {
  const authUser = (req as any).user;

  if (!authUser) {
    return res
      .status(401)
      .json({ success: false, message: "User not authenticated" });
  }

  try {
    const { code } = req.body as { code?: string };

    if (!code) {
      return res
        .status(400)
        .json({ success: false, message: "2FA code is required" });
    }

    const user = await User.findById(authUser.id);

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    if (!user.towFactorSecret) {
      return res.status(400).json({
        success: false,
        message: "2FA is not setup for this account",
      });
    }

    const isValid = authenticator.check(code, user.towFactorSecret);

    if (!isValid) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid 2FA code" });
    }

    user.twoFactorEnabled = true;
    await user.save();

    return res.status(200).json({
      success: true,
      message: "2FA enabled successfully",
    });
  } catch (e) {
    const error = e instanceof Error ? e : new Error(String(e));
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
  }
}
