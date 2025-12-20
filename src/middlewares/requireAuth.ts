import { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../lib/token";
import { User } from "../models/user.models";

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ success: false, message: "You are Not authenticated" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = verifyAccessToken(token);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "User Not Found" });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res
        .status(401)
        .json({ success: false, message: "Token Invalidated" });
    }

    // ✅ INTENTIONAL any usage (your requirement)
    const authRequest = req as any;

    authRequest.user = {
      id: user.id,
      email: user.email,
      name: user.fullName ?? undefined,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
    };

    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: "Invalid Token" });
  }
}

export default requireAuth;
