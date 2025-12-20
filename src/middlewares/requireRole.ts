import { NextFunction, Request, Response } from "express";

export function requireRole(role: "user" | "admin") {
  return (req: Request, res: Response, next: NextFunction) => {
    const authReq = req as any;

    const authUser = authReq.user;

    if (!authUser) {
      return res
        .status(401)
        .json({ success: false, message: "You are Not authenticated" });
    }

    if (authUser.role !== role) {
      return res
        .status(403)
        .json({ success: false, message: "You are Forbidden" });
    }

    next();
  };
}
