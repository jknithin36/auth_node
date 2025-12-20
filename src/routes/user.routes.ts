import { Router, Request, Response } from "express";
import requireAuth from "../middlewares/requireAuth";

const router = Router();

router.get("/me", requireAuth, (req: Request, res: Response) => {
  const authRequest = req as any;

  return res.status(200).json({
    success: true,
    user: authRequest.user,
  });
});

export default router;
