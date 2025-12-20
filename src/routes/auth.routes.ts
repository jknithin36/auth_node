import { Router } from "express";
import {
  forgotPasswordHandler,
  googleAuthCallbackHandler,
  googleAuthStart,
  loginHandler,
  logoutHandler,
  refreshHandler,
  registerHandler,
  resetPasswordHandler,
  twoFactorAuthVerify,
  twoFactorSetupHandler,
  verifyEmailHandler,
} from "../controllers/auth/auth.controller";
import requireAuth from "../middlewares/requireAuth";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/refresh", refreshHandler);
router.post("/logout", logoutHandler);
router.post("/forgot-password", forgotPasswordHandler);
router.post("/reset-password", resetPasswordHandler);

router.get("/google", googleAuthStart);
router.get("/google/callback", googleAuthCallbackHandler);

router.post("/2fa/setup", requireAuth, twoFactorSetupHandler);
router.post("/2fa/verify", requireAuth, twoFactorAuthVerify);

export default router;
