import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger.js";
import { HttpError } from "../utils/http-error.js";
import { env } from "../libs/env.js";

const isProd = env.NODE_ENV === "production";

export function errorHandler(
  err: unknown,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  let statusCode = 500;
  let message = "Internal Server Error";

  if (err instanceof HttpError) {
    statusCode = err.statusCode;
    message = err.message;
  }

  logger.error(message, {
    requestId: req.id,
    statusCode,
    path: req.path,
    method: req.method,
    stack: err instanceof Error ? err.stack : undefined,
  });

  res.status(statusCode).json({
    success: false,
    message:
      err instanceof HttpError || !isProd ? message : "Internal Server Error",
    requestId: req.id,
  });
}
