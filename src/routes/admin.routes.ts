import { Router, Request, Response } from "express";
import requireAuth from "../middlewares/requireAuth";
import { requireRole } from "../middlewares/requireRole";
import { User } from "../models/user.models";

const router = Router();

// GET /users  (admin only)
router.get(
  "/users",
  requireAuth,
  requireRole("admin"),
  async (req: Request, res: Response) => {
    // Optional: pagination
    const page = Math.max(parseInt(String(req.query.page || "1"), 10), 1);
    const limit = Math.min(
      Math.max(parseInt(String(req.query.limit || "20"), 10), 1),
      100
    );
    const skip = (page - 1) * limit;

    // Fetch users
    const [users, total] = await Promise.all([
      User.find({})
        .select("_id email fullName role isEmailVerified createdAt updatedAt")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      User.countDocuments(),
    ]);

    return res.status(200).json({
      success: true,
      page,
      limit,
      total,
      users,
    });
  }
);

export default router;
