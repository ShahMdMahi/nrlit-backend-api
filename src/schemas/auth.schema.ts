import { z } from "zod";

export const registerSchema = z.object({
  body: z
    .object({
      firstName: z
        .string()
        .trim()
        .min(2, "First name must be at least 2 characters long")
        .max(50, "First name must be at most 50 characters long"),
      lastName: z
        .string()
        .trim()
        .min(2, "Last name must be at least 2 characters long")
        .max(50, "Last name must be at most 50 characters long"),
      username: z
        .string()
        .trim()
        .min(3, "Username must be at least 3 characters long")
        .max(30, "Username must be at most 30 characters long")
        .regex(
          /^(?![._])[a-zA-Z0-9._]{3,30}(?<![._])$/,
          "Username can only contain letters, numbers, dots and underscores, and cannot start or end with dot or underscore"
        ),
      email: z.email("Invalid email address").trim(),
      phone: z
        .string()
        .trim()
        .transform((val) => {
          if (/^01[3-9]\d{8}$/.test(val)) {
            return "+88" + val;
          }
          if (/^8801[3-9]\d{8}$/.test(val)) {
            return "+" + val;
          }
          return val;
        })
        .refine((val) => /^\+8801[3-9]\d{8}$/.test(val), {
          message: "Invalid Bangladeshi phone number format",
        }),
      password: z
        .string()
        .trim()
        .min(8, "Password must be at least 8 characters long")
        .refine(
          (val) => /[a-z]/.test(val),
          "Password must contain at least one lowercase letter"
        )
        .refine(
          (val) => /[A-Z]/.test(val),
          "Password must contain at least one uppercase letter"
        )
        .refine(
          (val) => /\d/.test(val),
          "Password must contain at least one digit"
        )
        .refine(
          (val) => /[!@#$%^&*()_+\-=\\[\]{};':"\\|,.<>\\/?~`]/.test(val),
          "Password must contain at least one special character"
        ),
      confirmPassword: z
        .string()
        .trim()
        .min(8, "Confirm Password must be at least 8 characters long"),
    })
    .refine(
      (data) => {
        return ![data.email, data.phone].includes(data.username);
      },
      {
        message: "Username cannot be an email or phone number",
        path: ["username"],
      }
    )
    .refine((data) => data.password === data.confirmPassword, {
      message: "Passwords do not match",
      path: ["confirmPassword"],
    }),
});

export type RegisterInput = z.infer<typeof registerSchema>["body"];

export const resendVerificationSchema = z.object({
  body: z.object({
    email: z.email("Invalid email address").trim(),
  }),
});

export type ResendVerificationInput = z.infer<
  typeof resendVerificationSchema
>["body"];

export const verifyEmailSchema = z.object({
  body: z.object({
    token: z.string().trim().min(1, "Token is required"),
    code: z
      .string()
      .trim()
      .length(6, "Code must be exactly 6 digits")
      .regex(/^\d{6}$/, "Code must be numeric"),
  }),
});

export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>["body"];

export const loginSchema = z.object({
  body: z.object({
    identifier: z
      .string()
      .trim()
      .min(1, "Username, email, or phone is required")
      .transform((val) => {
        if (/^01[3-9]\d{8}$/.test(val)) {
          return "+88" + val;
        }
        if (/^8801[3-9]\d{8}$/.test(val)) {
          return "+" + val;
        }
        return val;
      })
      .refine(
        (val) =>
          /^(?![._])[a-zA-Z0-9._]{3,30}(?<![._])$/.test(val) ||
          /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val) ||
          /^\+8801[3-9]\d{8}$/.test(val),
        "Enter a valid username, email, or Bangladeshi phone number"
      ),
    password: z.string().trim().min(1, "Password is required"),
  }),
});

export type LoginInput = z.infer<typeof loginSchema>["body"];

export const twoFactorSchema = z.object({
  body: z.object({
    token: z.string().trim().min(1, "Token is required"),
    code: z
      .string()
      .trim()
      .length(6, "Code must be exactly 6 digits")
      .regex(/^\d{6}$/, "Code must be numeric"),
  }),
});

export type TwoFactorInput = z.infer<typeof twoFactorSchema>["body"];

export const forgotPasswordSchema = z.object({
  body: z.object({
    email: z.email("Invalid email address").trim(),
  }),
});

export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>["body"];

export const resetPasswordSchema = z.object({
  body: z
    .object({
      token: z.string().trim().min(1, "Token is required"),
      newPassword: z
        .string()
        .trim()
        .min(8, "Password must be at least 8 characters long")
        .refine(
          (val) => /[a-z]/.test(val),
          "Password must contain at least one lowercase letter"
        )
        .refine(
          (val) => /[A-Z]/.test(val),
          "Password must contain at least one uppercase letter"
        )
        .refine(
          (val) => /\d/.test(val),
          "Password must contain at least one digit"
        )
        .refine(
          (val) => /[!@#$%^&*()_+\-=\\[\]{};':"\\|,.<>\\/?~`]/.test(val),
          "Password must contain at least one special character"
        ),
      newConfirmPassword: z
        .string()
        .trim()
        .min(8, "Confirm Password must be at least 8 characters long"),
    })
    .refine((data) => data.newPassword === data.newConfirmPassword, {
      message: "Passwords do not match",
      path: ["newConfirmPassword"],
    }),
});

export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>["body"];
