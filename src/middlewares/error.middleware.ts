import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger.js";
import { HttpError } from "../utils/http-error.js";
import { env } from "../libs/env.js";
import {
  escapeMarkdownV2,
  formatJson,
} from "../utils/escape-telegram-markdown.js";
import { telegramBot } from "../libs/telegram.js";

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

  try {
    const timestamp = new Date().toLocaleString("en-US", {
      timeZone: "Asia/Dhaka",
      timeStyle: "long",
      dateStyle: "long",
    });
    const deviceInfo = req.device ? formatJson(req.device) : "None";
    const markdownText = `
**❗ Error Alert**
**Time:** ${escapeMarkdownV2(timestamp)}
**Request ID:** ${escapeMarkdownV2(req.id)}
**Path:** ${escapeMarkdownV2(req.path)}
**Method:** ${escapeMarkdownV2(req.method)}
**Error Message:** ${escapeMarkdownV2(
      err instanceof Error ? err.message : String(err)
    )}

**Stack Trace:**
\`\`\`
${escapeMarkdownV2(err instanceof Error ? err.stack || "N/A" : "N/A")}
\`\`\`
**Device Info:**
\`\`\`json
${deviceInfo}
\`\`\`
`.trim();
    telegramBot.telegram
      .sendMessage(env.TELEGRAM_CHAT_ID, markdownText, {
        parse_mode: "MarkdownV2",
      })
      .catch((err) => {
        logger.error("Failed to send error alert to Telegram", { err });
      });
  } catch (error) {
    logger.error("Failed to format timestamp", { error });
  }

  res.status(statusCode).json({
    success: false,
    message:
      err instanceof HttpError || !isProd ? message : "Internal Server Error",
    errors: err instanceof HttpError ? err.details : undefined,
    requestId: req.id,
  });
}
