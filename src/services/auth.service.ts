import * as argon2 from "argon2";
import crypto from "node:crypto";
import { prisma } from "../libs/db.js";
import {
  RegisterUserInput,
  ResendVerificationInput,
  VerifyEmailInput,
  registerSchema,
  resendVerificationSchema,
  verifyEmailSchema,
} from "../schemas/auth.schema.js";
import { HttpError } from "../utils/http-error.js";

class AuthService {
  public async register(data: RegisterUserInput) {
    const validate = await registerSchema.safeParseAsync({ body: data });

    if (!validate.success) {
      throw new HttpError("Invalid user data", 400, validate.error);
    }

    if (data.password !== data.confirmPassword) {
      throw new HttpError("Passwords do not match", 400);
    }

    const userExists = await prisma.user.findFirst({
      where: {
        OR: [
          { username: data.username },
          { email: data.email },
          { phone: data.phone },
        ],
      },
    });

    if (userExists && !userExists.deletedAt) {
      throw new HttpError("User already exists", 409);
    }

    if (userExists && userExists.deletedAt) {
      throw new HttpError("User previously deleted. Contact support.", 410);
    }

    const hashedPassword = await argon2.hash(data.password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });

    if (!hashedPassword) {
      throw new HttpError("Failed to hash password", 500);
    }

    const verificationToken = crypto.randomBytes(32).toString("hex");

    const newUser = await prisma.user.create({
      data: {
        firstName: data.firstName,
        lastName: data.lastName,
        username: data.username,
        email: data.email,
        phone: data.phone,
        password: hashedPassword,
        verificationToken: verificationToken,
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
        verificationTokenExpiredAt: true,
        createdAt: true,
      },
    });

    if (!newUser) {
      throw new HttpError("Failed to create user", 500);
    }

    // TODO: Send welcome email
    console.log(
      "Welcome email sent to:",
      newUser.email,
      "with token:",
      newUser.verificationToken
    );
    // TODO: Log registration event

    return newUser;
  }

  public async resendVerification(data: ResendVerificationInput) {
    const validate = await resendVerificationSchema.safeParseAsync({
      body: data,
    });

    if (!validate.success) {
      throw new HttpError("Invalid data", 400, validate.error);
    }

    const userExists = await prisma.user.findFirst({
      where: {
        email: data.email,
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
      throw new HttpError("User does not exist", 404);
    }

    if (userExists.verifiedAt) {
      throw new HttpError("Email is already verified", 400);
    }

    const verficationToken = crypto.randomBytes(32).toString("hex");

    const updatedUser = await prisma.user.update({
      where: { id: userExists.id },
      data: {
        verificationToken: verficationToken,
        verificationTokenExpiredAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
      select: {
        id: true,
        email: true,
        verificationToken: true,
        verificationTokenExpiredAt: true,
      },
    });

    // TODO: Resend verification email
    console.log(
      "Resent verification email to:",
      updatedUser.email,
      "with token:",
      updatedUser.verificationToken
    );
    // TODO: Log resend event

    return updatedUser;
  }

  public async verifyEmail(data: VerifyEmailInput) {
    const validate = await verifyEmailSchema.safeParseAsync({ body: data });

    if (!validate.success) {
      throw new HttpError("Invalid data", 400, validate.error);
    }

    const userExists = await prisma.user.findFirst({
      where: {
        verificationToken: data.token,
        verificationTokenExpiredAt: {
          gt: new Date(),
        },
        deletedAt: null,
      },
      select: {
        id: true,
        email: true,
        verificationToken: true,
        verifiedAt: true,
        verificationTokenExpiredAt: true,
      },
    });

    if (!userExists) {
      throw new HttpError("Invalid or expired verification token", 400);
    }

    if (userExists.verifiedAt) {
      throw new HttpError("Email is already verified", 400);
    }

    const verifiedUser = await prisma.user.update({
      where: { id: userExists.id },
      data: {
        verifiedAt: new Date(),
        verificationToken: null,
        verificationTokenExpiredAt: null,
      },
      select: {
        id: true,
        email: true,
        verificationToken: true,
        verifiedAt: true,
        verificationTokenExpiredAt: true,
      },
    });

    if (!verifiedUser) {
      throw new HttpError("Failed to verify email", 500);
    }

    // TODO: Send confirmation email
    console.log("Email verified for:", verifiedUser.email);
    // TODO: Log verification event

    return verifiedUser;
  }
}

export const authService = new AuthService();
