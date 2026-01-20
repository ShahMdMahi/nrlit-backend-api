import * as argon2 from "argon2";
import crypto from "node:crypto";
import { z } from "zod";
import { prisma } from "../libs/db.js";
import {
  LoginInput,
  RegisterUserInput,
  ResendVerificationInput,
  VerifyEmailInput,
  loginSchema,
  registerSchema,
  resendVerificationSchema,
  verifyEmailSchema,
} from "../schemas/auth.schema.js";
import { HttpError } from "../utils/http-error.js";
import { logAuditEvent } from "../utils/log-audit.js";
import { AuditAction, AuditEntity } from "../prisma/enums.js";
import { logger } from "../utils/logger.js";
import { transporter } from "../libs/nodemailer.js";
import { env } from "../libs/env.js";

class AuthService {
  public async register(data: RegisterUserInput) {
    const validate = await registerSchema.safeParseAsync({ body: data });

    if (!validate.success) {
      throw new HttpError("Invalid user data", 400, validate.error.issues);
    }

    const checkUserName = await prisma.user.findUnique({
      where: { username: validate.data.body.username },
      select: { id: true, username: true },
    });

    if (checkUserName) {
      throw new HttpError(
        "Username already taken",
        409,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "username"],
            message: "Username already taken",
          },
        ]).issues
      );
    }

    const checkEmail = await prisma.user.findUnique({
      where: { email: validate.data.body.email },
      select: { id: true, email: true },
    });

    if (checkEmail) {
      throw new HttpError(
        "Email already registered",
        409,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "email"],
            message: "Email already registered",
          },
        ]).issues
      );
    }

    const checkPhone = await prisma.user.findUnique({
      where: { phone: validate.data.body.phone },
      select: { id: true, phone: true },
    });

    if (checkPhone) {
      throw new HttpError(
        "Phone number already registered",
        409,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "phone"],
            message: "Phone number already registered",
          },
        ]).issues
      );
    }

    const userExists = await prisma.user.findFirst({
      where: {
        OR: [
          { username: validate.data.body.username },
          { email: validate.data.body.email },
          { phone: validate.data.body.phone },
        ],
      },
      select: {
        id: true,
        email: true,
        username: true,
        phone: true,
        deletedAt: true,
      },
    });

    if (userExists && !userExists.deletedAt) {
      throw new HttpError("User already exists", 409);
    }

    if (userExists && userExists.deletedAt) {
      throw new HttpError("User previously deleted. Contact support.", 410);
    }

    const hashedPassword = await argon2.hash(validate.data.body.password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });

    if (!hashedPassword) {
      throw new HttpError("Failed to hash password", 500);
    }

    const verificationToken = crypto.randomBytes(64).toString("hex");
    const randomInt = crypto.randomInt(0, 4294967296);
    const code = randomInt % 1000000;
    const verificationCode = code.toString().padStart(6, "0");

    const newUser = await prisma.user.create({
      data: {
        firstName: validate.data.body.firstName,
        lastName: validate.data.body.lastName,
        username: validate.data.body.username,
        email: validate.data.body.email,
        phone: validate.data.body.phone,
        password: hashedPassword,
        verificationToken: verificationToken,
        verificationCode: verificationCode,
        verificationTokenExpiredAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        username: true,
        email: true,
        phone: true,
        verificationToken: true,
        verificationCode: true,
        verificationTokenExpiredAt: true,
        createdAt: true,
      },
    });

    if (!newUser) {
      throw new HttpError("Failed to create user", 500);
    }

    await transporter
      .sendMail({
        from: env.EMAIL_FROM,
        to: newUser.email,
        subject: "Welcome to NRLIT - Please Verify Your Email",
        template: "welcome",
        context: {
          id: newUser.id,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          username: newUser.username,
          email: newUser.email,
          phone: newUser.phone,
          verificationCode: newUser.verificationCode,
          verificationUrl: `${env.FRONTEND_BASE_URL}/auth/verify?token=${newUser.verificationToken}`,
          verificationTokenExpiredAt:
            newUser.verificationTokenExpiredAt?.toLocaleString("en-US", {
              timeZone: "Asia/Dhaka",
            }),
          createdAt: newUser.createdAt.toLocaleString("en-US", {
            timeZone: "Asia/Dhaka",
          }),
        },
      } as never)
      .catch((error) => {
        logger.error("Failed to send welcome email:", { error });
      });

    logAuditEvent({
      entity: AuditEntity.USER,
      action: AuditAction.USER_REGISTERED,
      entityId: newUser.id,
      description: `User registered with email: ${newUser.email}`,
      userId: newUser.id,
    }).catch((err) => {
      logger.error("Failed to log audit event for user registration:", { err });
    });

    return { email: newUser.email, token: newUser.verificationToken };
  }

  public async resendVerification(data: ResendVerificationInput) {
    const validate = await resendVerificationSchema.safeParseAsync({
      body: data,
    });

    if (!validate.success) {
      throw new HttpError("Invalid data", 400, validate.error.issues);
    }

    const userExists = await prisma.user.findFirst({
      where: {
        email: validate.data.body.email,
        bannedAt: null,
        deletedAt: null,
      },
      select: {
        id: true,
        email: true,
        verifiedAt: true,
        deletedAt: true,
      },
    });

    if (!userExists) {
      throw new HttpError(
        "User does not exist",
        404,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "email"],
            message: "User does not exist",
          },
        ]).issues
      );
    }

    if (userExists.verifiedAt) {
      throw new HttpError(
        "Email is already verified",
        400,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "email"],
            message: "Email is already verified",
          },
        ]).issues
      );
    }

    const verificationToken = crypto.randomBytes(64).toString("hex");
    const randomInt = crypto.randomInt(0, 4294967296);
    const code = randomInt % 1000000;
    const verificationCode = code.toString().padStart(6, "0");

    const updatedUser = await prisma.user.update({
      where: { id: userExists.id },
      data: {
        verificationToken: verificationToken,
        verificationCode: verificationCode,
        verificationTokenExpiredAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
      select: {
        id: true,
        email: true,
        verificationCode: true,
        verificationToken: true,
        verificationTokenExpiredAt: true,
        updatedAt: true,
      },
    });

    if (!updatedUser) {
      throw new HttpError(
        "Failed to update user verification info",
        500,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "email"],
            message: "Failed to update user verification info",
          },
        ]).issues
      );
    }

    await transporter
      .sendMail({
        from: env.EMAIL_FROM,
        to: updatedUser.email,
        subject: "Resend Email Verification - NRLIT",
        template: "resend-verification",
        context: {
          id: updatedUser.id,
          email: updatedUser.email,
          verificationCode: updatedUser.verificationCode,
          verificationUrl: `${env.FRONTEND_BASE_URL}/auth/verify?token=${updatedUser.verificationToken}`,
          verificationTokenExpiredAt:
            updatedUser.verificationTokenExpiredAt?.toLocaleString("en-US", {
              timeZone: "Asia/Dhaka",
            }),
          updatedAt: updatedUser.updatedAt.toLocaleString("en-US", {
            timeZone: "Asia/Dhaka",
          }),
        },
      } as never)
      .catch((error) => {
        logger.error("Failed to send resend verification email:", { error });
      });

    logAuditEvent({
      entity: AuditEntity.USER,
      action: AuditAction.USER_RESEND_VERIFICATION,
      entityId: updatedUser.id,
      description: `Resent verification email to: ${updatedUser.email}`,
      userId: updatedUser.id,
    }).catch((err) => {
      logger.error("Failed to log audit event for resending verification:", {
        err,
      });
    });

    return { email: updatedUser.email, token: updatedUser.verificationToken };
  }

  public async verifyEmail(data: VerifyEmailInput) {
    const validate = await verifyEmailSchema.safeParseAsync({ body: data });

    if (!validate.success) {
      throw new HttpError("Invalid data", 400, validate.error.issues);
    }

    const userExists = await prisma.user.findFirst({
      where: {
        verificationToken: validate.data.body.token,
        verificationTokenExpiredAt: {
          gt: new Date(),
        },
        bannedAt: null,
        deletedAt: null,
      },
      select: {
        id: true,
        email: true,
        verificationToken: true,
        verifiedAt: true,
        verificationCode: true,
        verificationTokenExpiredAt: true,
        deletedAt: true,
      },
    });

    if (!userExists) {
      throw new HttpError(
        "Invalid or expired verification token",
        400,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "token"],
            message: "Invalid or expired verification token",
          },
        ]).issues
      );
    }

    if (userExists.verifiedAt) {
      throw new HttpError(
        "Email is already verified",
        400,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "token"],
            message: "Email is already verified",
          },
        ]).issues
      );
    }

    if (userExists.verificationTokenExpiredAt! < new Date()) {
      throw new HttpError(
        "Verification token has expired",
        400,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "token"],
            message: "Verification token has expired",
          },
        ]).issues
      );
    }

    if (userExists.verificationToken !== validate.data.body.token) {
      throw new HttpError(
        "Invalid verification token",
        400,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "token"],
            message: "Invalid verification token",
          },
        ]).issues
      );
    }

    if (userExists.verificationCode !== validate.data.body.code) {
      throw new HttpError(
        "Invalid verification code",
        400,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "code"],
            message: "Invalid verification code",
          },
        ]).issues
      );
    }

    const verifiedUser = await prisma.user.update({
      where: { id: userExists.id },
      data: {
        verifiedAt: new Date(),
        verificationCode: null,
        verificationToken: null,
        verificationTokenExpiredAt: null,
      },
      select: {
        id: true,
        email: true,
        verificationCode: true,
        verificationToken: true,
        verifiedAt: true,
        verificationTokenExpiredAt: true,
      },
    });

    if (!verifiedUser) {
      throw new HttpError(
        "Failed to verify email",
        500,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "token"],
            message: "Failed to verify email",
          },
        ]).issues
      );
    }

    transporter
      .sendMail({
        from: env.EMAIL_FROM,
        to: verifiedUser.email,
        subject: "Email Verification Confirmed - NRLIT",
        template: "verification-confirm",
        context: {
          id: verifiedUser.id,
          email: verifiedUser.email,
          verifiedAt: verifiedUser.verifiedAt?.toLocaleString("en-US", {
            timeZone: "Asia/Dhaka",
          }),
        },
      } as never)
      .catch((error) => {
        logger.error("Failed to send email verification confirmation:", {
          error,
        });
      });

    logAuditEvent({
      entity: AuditEntity.USER,
      action: AuditAction.USER_VERIFIED,
      entityId: verifiedUser.id,
      description: `Email verified for: ${verifiedUser.email}`,
      userId: verifiedUser.id,
    }).catch((err) => {
      logger.error("Failed to log audit event for email verification:", {
        err,
      });
    });

    return { email: verifiedUser.email };
  }

  public async login(data: LoginInput) {
    const validate = await loginSchema.safeParseAsync({ body: data });

    if (!validate.success) {
      throw new HttpError("Invalid data", 400, validate.error.issues);
    }

    const userExists = await prisma.user.findFirst({
      where: {
        OR: [
          { email: validate.data.body.identifier },
          { username: validate.data.body.identifier },
          { phone: validate.data.body.identifier },
        ],
        bannedAt: null,
        deletedAt: null,
      },
      select: {
        id: true,
        email: true,
        username: true,
        phone: true,
        password: true,
        verifiedAt: true,
        approvedAt: true,
        lockedUntil: true,
        suspendedAt: true,
        bannedAt: true,
        twoFactorEnabledAt: true,
        failedLoginAttempts: true,
      },
    });

    if (!userExists) {
      throw new HttpError(
        "Invalid credentials",
        401,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "identifier"],
            message: "Invalid credentials",
          },
        ]).issues
      );
    }

    if (!userExists.verifiedAt) {
      throw new HttpError(
        "Email is not verified",
        403,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "identifier"],
            message: "Email is not verified",
          },
        ]).issues
      );
    }

    if (!userExists.approvedAt) {
      throw new HttpError(
        "User is not approved",
        403,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "identifier"],
            message: "User is not approved",
          },
        ]).issues
      );
    }

    if (userExists.lockedUntil && userExists.lockedUntil > new Date()) {
      throw new HttpError(
        "User is locked until " +
          userExists.lockedUntil.toLocaleString("en-US", {
            timeZone: "Asia/Dhaka",
          }),
        403,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "identifier"],
            message:
              "User is locked until " +
              userExists.lockedUntil.toLocaleString("en-US", {
                timeZone: "Asia/Dhaka",
              }),
          },
        ]).issues
      );
    }

    if (userExists.suspendedAt) {
      throw new HttpError(
        "User is suspended at " +
          userExists.suspendedAt.toLocaleString("en-US", {
            timeZone: "Asia/Dhaka",
          }),
        403,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "identifier"],
            message:
              "User is suspended at " +
              userExists.suspendedAt.toLocaleString("en-US", {
                timeZone: "Asia/Dhaka",
              }),
          },
        ]).issues
      );
    }

    const passwordMatch = await argon2.verify(
      userExists.password,
      validate.data.body.password
    );

    if (!passwordMatch) {
      await prisma.user.update({
        where: { id: userExists.id },
        data: {
          failedLoginAttempts: {
            increment: 1,
          },
          lockedUntil:
            userExists.failedLoginAttempts + 1 >= 5
              ? new Date(Date.now() + 30 * 60 * 1000)
              : null,
          lastFailedLoginAt: new Date(),
        },
        select: {
          id: true,
          failedLoginAttempts: true,
          lastFailedLoginAt: true,
        },
      });

      logAuditEvent({
        entity: AuditEntity.USER,
        action: AuditAction.USER_FAILED_LOGIN,
        entityId: userExists.id,
        description: `Failed login attempt for: ${userExists.email}`,
        userId: userExists.id,
      }).catch((err) => {
        logger.error("Failed to log audit event for failed login:", {
          err,
        });
      });

      throw new HttpError(
        "Invalid credentials",
        401,
        new z.ZodError([
          {
            code: z.ZodIssueCode.custom,
            path: ["body", "identifier"],
            message: "Invalid credentials",
          },
        ]).issues
      );
    }

    if (userExists.twoFactorEnabledAt) {
      const twoFactorToken = crypto.randomBytes(64).toString("hex");
      const randomInt = crypto.randomInt(0, 4294967296);
      const code = randomInt % 1000000;
      const twoFactorCode = code.toString().padStart(6, "0");
      const updatedUser = await prisma.user.update({
        where: { id: userExists.id },
        data: {
          twoFactorToken: twoFactorToken,
          twoFactorCode: twoFactorCode,
          twoFactorCodeExpiresAt: new Date(Date.now() + 10 * 60 * 1000),
        },
        select: {
          id: true,
          email: true,
          twoFactorCode: true,
          twoFactorToken: true,
          twoFactorCodeExpiresAt: true,
          updatedAt: true,
        },
      });

      transporter
        .sendMail({
          from: env.EMAIL_FROM,
          to: updatedUser.email,
          subject: "Two-Factor Authentication Code - NRLIT",
          template: "2fa-code",
          context: {
            code: updatedUser.twoFactorCode,
            email: updatedUser.email,
            updatedAt: updatedUser.updatedAt.toLocaleString("en-US", {
              timeZone: "Asia/Dhaka",
            }),
            expiresAt: updatedUser.twoFactorCodeExpiresAt?.toLocaleString(
              "en-US",
              {
                timeZone: "Asia/Dhaka",
              }
            ),
            loginLink: `${env.FRONTEND_BASE_URL}/auth/2fa?token=${updatedUser.twoFactorToken}`,
          },
        } as never)
        .catch((error) => {
          logger.error("Failed to send email verification confirmation:", {
            error,
          });
        });

      logAuditEvent({
        entity: AuditEntity.USER,
        action: AuditAction.USER_2FA_CHALLENGED,
        entityId: updatedUser.id,
        description: `Two-factor authentication challenged for: ${updatedUser.email}`,
        userId: updatedUser.id,
      }).catch((err) => {
        logger.error("Failed to log audit event for 2FA challenge:", {
          err,
        });
      });

      return {
        email: updatedUser.email,
        twoFactorRequired: true,
        twoFactorToken: updatedUser.twoFactorToken,
      };
    }

    const userSessions = await prisma.session.findMany({
      where: { userId: userExists.id },
      select: {
        id: true,
        userId: true,
        accessedAt: true,
      },
      orderBy: {
        accessedAt: "asc",
      },
    });

    if (userSessions && userSessions.length >= 5 && userSessions[0]) {
      await prisma.session.delete({
        where: {
          id: userSessions[0].id,
        },
      });
    }

    const sessionToken = crypto.randomBytes(64).toString("hex");

    const [session, user] = await prisma.$transaction([
      prisma.session.create({
        data: {
          token: sessionToken,
          expiredAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          user: { connect: { id: userExists.id } },
        },
        select: {
          id: true,
          userId: true,
          token: true,
          createdAt: true,
          expiredAt: true,
        },
      }),
      prisma.user.update({
        where: { id: userExists.id },
        data: {
          lastLoginAt: new Date(),
          lockedUntil: null,
          lastFailedLoginAt: null,
          failedLoginAttempts: 0,
        },
        select: {
          id: true,
          email: true,
          lastLoginAt: true,
          lastFailedLoginAt: true,
          failedLoginAttempts: true,
        },
      }),
    ]);

    transporter
      .sendMail({
        from: env.EMAIL_FROM,
        to: user.email,
        subject: "New Login Detected - NRLIT",
        template: "new-login-detected",
        context: {
          email: user.email,
          lastLoginAt: user.lastLoginAt?.toLocaleString("en-US", {
            timeZone: "Asia/Dhaka",
          }),
        },
      } as never)
      .catch((error) => {
        logger.error("Failed to send new login detected email:", {
          error,
        });
      });

    logAuditEvent({
      entity: AuditEntity.USER,
      action: AuditAction.USER_LOGGED_IN,
      entityId: user.id,
      description: `User logged in: ${user.email}`,
      userId: user.id,
    }).catch((err) => {
      logger.error("Failed to log audit event for user login:", {
        err,
      });
    });

    return {
      email: user.email,
      token: session.token,
    };
  }
}

export const authService = new AuthService();
