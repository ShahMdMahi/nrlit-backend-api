import { Router } from "express";
import { authController } from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validate.middleware.js";
import {
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

export { router as authRouter };
