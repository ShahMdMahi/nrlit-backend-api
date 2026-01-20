import { Request, Response } from "express";
import {
  RegisterUserInput,
  ResendVerificationInput,
  VerifyEmailInput,
  LoginInput,
} from "../schemas/auth.schema.js";
import { authService } from "../services/auth.service.js";
import { asyncHandler } from "../utils/async-handler.js";
import { sendSuccess } from "../utils/response.js";
import { env } from "../libs/env.js";

class AuthController {
  public register = asyncHandler(
    async (
      req: Request<
        Record<string, never>,
        Record<string, never>,
        RegisterUserInput,
        Record<string, never>
      >,
      res: Response
    ) => {
      const userData = req.body;

      const result = await authService.register(userData);

      sendSuccess(
        res,
        {
          email: result.email,
          token: result.token,
        },
        `User registered successfully. Verification email sent to ${result.email}`,
        201
      );
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
      res: Response
    ) => {
      const requestData = req.body;

      const result = await authService.resendVerification(requestData);

      sendSuccess(
        res,
        {
          email: result.email,
          token: result.token,
        },
        `Verification email resent successfully to ${result.email}`,
        200
      );
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
      res: Response
    ) => {
      const requestData = req.body;

      const result = await authService.verifyEmail(requestData);

      sendSuccess(
        res,
        {
          email: result.email,
        },
        `Email verified successfully. Confirmation email sent to ${result.email}`,
        200
      );
    }
  );

  public login = asyncHandler(
    async (
      req: Request<
        Record<string, never>,
        Record<string, never>,
        LoginInput,
        Record<string, never>
      >,
      res: Response
    ) => {
      const requestData = req.body;

      const result = await authService.login(requestData);

      if (result.twoFactorRequired) {
        return sendSuccess(
          res,
          {
            email: result.email,
            twoFactorToken: result.twoFactorToken,
            twoFactorRequired: true,
            token: null,
          },
          `Two-factor authentication required. Please verify to proceed, ${result.email}`,
          200
        );
      }

      res.cookie("session_token", result.token, {
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        signed: true,
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        httpOnly: true,
        path: "*",
        domain: env.COOKIE_DOMAIN,
        secure: env.NODE_ENV === "production",
        sameSite: "lax",
        priority: "high",
      });

      sendSuccess(
        res,
        {
          email: result.email,
          twoFactorToken: null,
          twoFactorRequired: false,
          token: result.token,
        },
        `Logged in successfully. Welcome back, ${result.email}`,
        200
      );
    }
  );
}

export const authController = new AuthController();
