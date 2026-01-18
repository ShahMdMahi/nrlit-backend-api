import { Request, Response, NextFunction } from "express";
import { ZodSchema, ZodError } from "zod";
import { HttpError } from "../utils/http-error.js";

/**
 * Validates request data against a Zod schema.
 * Supports body, query, and params.
 */
export const validate =
  (schema: ZodSchema) =>
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      await schema.parseAsync({
        body: req.body,
        query: req.query,
        params: req.params,
      });
      next();
    } catch (error: unknown) {
      // Fixes: "Object is of type 'unknown'"
      if (error instanceof ZodError) {
        const details = error.issues;
        const errorMessage = details[0]?.message || "Validation Failed";

        // Pass the error to our refined HttpError class
        return next(new HttpError(errorMessage, 400, details));
      }

      // Fallback for non-Zod errors
      next(error);
    }
  };
