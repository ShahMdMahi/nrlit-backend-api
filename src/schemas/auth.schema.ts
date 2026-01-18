import { z } from "zod";

export const registerSchema = z.object({
  body: z
    .object({
      firstName: z
        .string()
        .min(2, "First name must be at least 2 characters long")
        .max(50, "First name must be at most 50 characters long"),
      lastName: z
        .string()
        .min(2, "Last name must be at least 2 characters long")
        .max(50, "Last name must be at most 50 characters long"),
      username: z
        .string()
        .min(3, "Username must be at least 3 characters long")
        .max(30, "Username must be at most 30 characters long")
        .regex(
          /^[a-zA-Z0-9._]+$/,
          "Username can only contain letters, numbers, dot and underscores"
        ),
      email: z.email("Invalid email address"),
      phone: z
        .string()
        .transform((val) => {
          if (/^01\d{9}$/.test(val)) {
            return "+880" + val;
          }
          return val;
        })
        .refine((val) => /^\+8801\d{9}$/.test(val), "Invalid phone number"),
      password: z
        .string()
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
        .min(8, "Confirm Password must be at least 8 characters long"),
    })
    .refine((data) => data.password === data.confirmPassword, {
      message: "Passwords do not match",
    }),
});

export type RegisterUserInput = z.infer<typeof registerSchema>["body"];

export const resendVerificationSchema = z.object({
  body: z.object({
    email: z.email("Invalid email address"),
  }),
});

export type ResendVerificationInput = z.infer<
  typeof resendVerificationSchema
>["body"];

export const verifyEmailSchema = z.object({
  body: z.object({
    token: z.string().min(1, "Token is required"),
  }),
});

export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>["body"];

export const loginSchema = z.object({
  body: z.object({
    identifier: z.string().min(1, "Identifier is required"),
    password: z.string().min(1, "Password is required"),
  }),
});

export type LoginInput = z.infer<typeof loginSchema>["body"];

export const forgotPasswordSchema = z.object({
  body: z.object({
    email: z.email("Invalid email address"),
  }),
});

export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>["body"];

export const resetPasswordSchema = z.object({
  body: z
    .object({
      token: z.string().min(1, "Token is required"),
      newPassword: z
        .string()
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
        .min(8, "Confirm Password must be at least 8 characters long"),
    })
    .refine((data) => data.newPassword === data.newConfirmPassword, {
      message: "Passwords do not match",
    }),
});

export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>["body"];
