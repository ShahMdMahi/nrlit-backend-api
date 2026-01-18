import { NextFunction, Request, Response } from "express";
import {
  RegisterUserInput,
  ResendVerificationInput,
  VerifyEmailInput,
} from "../schemas/auth.schema.js";
import { authService } from "../services/auth.service.js";
import { asyncHandler } from "../utils/async-handler.js";
import { sendSuccess } from "../utils/response.js";

class AuthController {
  public register = asyncHandler(
    async (
      req: Request<
        Record<string, never>,
        Record<string, never>,
        RegisterUserInput,
        Record<string, never>
      >,
      res: Response,
      _next: NextFunction
    ) => {
      const userData = req.body;

      const result = await authService.register(userData);

      sendSuccess(res, result, "User registered successfully", 201);
    }
  );

  public resendVerification = asyncHandler(
    async (
      req: Request<
        Record<string, never>,
        Record<string, never>,
        ResendVerificationInput,
        Record<string, never>
      >,
      res: Response,
      _next: NextFunction
    ) => {
      const requestData = req.body;

      const result = await authService.resendVerification(requestData);

      sendSuccess(res, result, "Verification email resent successfully", 200);
    }
  );

  public verifyEmail = asyncHandler(
    async (
      req: Request<
        Record<string, never>,
        Record<string, never>,
        VerifyEmailInput,
        Record<string, never>
      >,
      res: Response,
      _next: NextFunction
    ) => {
      const requestData = req.body;

      const result = await authService.verifyEmail(requestData);

      sendSuccess(res, result, "Email verified successfully", 200);
    }
  );
}

export const authController = new AuthController();
