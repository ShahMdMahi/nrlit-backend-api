import { Router } from "express";
import { authController } from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validate.middleware.js";
import {
  loginSchema,
  registerSchema,
  resendVerificationSchema,
  verifyEmailSchema,
} from "../schemas/auth.schema.js";

const router = Router();

router.post("/register", validate(registerSchema), authController.register);
router.post(
  "/resend-verification",
  validate(resendVerificationSchema),
  authController.resendVerification
);
router.post(
  "/verify-email",
  validate(verifyEmailSchema),
  authController.verifyEmail
);
router.post("/login", validate(loginSchema), authController.login);

export { router as authRouter };
