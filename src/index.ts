import express, { Express, Request, Response } from "express";
import { env } from "./libs/env.js";
import { requestId } from "./middlewares/request-id.middleware.js";
import { httpLogger } from "./middlewares/logger.middleware.js";
import { compressionMiddleware } from "./middlewares/compression.middleware.js";
import { helmetMiddleware } from "./middlewares/helmet.middleware.js";
import { corsMiddleware } from "./middlewares/cors.middleware.js";
import {
  generalRateLimit,
  authRateLimit,
} from "./middlewares/rate-limit.middleware.js";
import { cookieParserMiddleware } from "./middlewares/cookie-parser.middleware.js";
import { hmacAuthorize } from "./middlewares/hmac.middleware.js";
import { useragentMiddleware } from "./middlewares/useragent.middleware.js";
import { hppMiddleware } from "./middlewares/hpp.middleware.js";
import { xssSanitizeMiddleware } from "./middlewares/xss-sanitize.middleware.js";
import { errorHandler } from "./middlewares/error.middleware.js";
import { authRouter } from "./routes/auth.route.js";
import { logger } from "./utils/logger.js";
import { telegramBot } from "./libs/telegram.js";
import { Server } from "http";
import { verifyEmailConnection } from "./libs/nodemailer.js";
import { prisma, verifyDbConnection } from "./libs/db.js";
import { promisify } from "util";

const app: Express = express();
const PORT = env.PORT;
const NODE_ENV = env.NODE_ENV;

// 1. Traceability & Infrastructure
app.use(requestId);
app.use(httpLogger);
app.use(compressionMiddleware);

// 2. Global Security Headers & CORS
app.use(helmetMiddleware);
app.use(corsMiddleware);

// 3. Rate Limiting
app.use(generalRateLimit);
app.use("/api/v1/auth", authRateLimit);

// 4. Body Parsing
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));
app.use(cookieParserMiddleware);

// 5. API Authorization (HMAC)
app.use(hmacAuthorize);

// 6. Sanitization & Metadata
app.use(useragentMiddleware);
app.use(hppMiddleware);
app.use(xssSanitizeMiddleware);

// 7. Routes
app.get("/", async (req: Request, res: Response) => {
  res.send("Hello, World!");
});

app.use("/api/v1/auth", authRouter);

// 8. 404 Handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
    requestId: req.id,
  });
});

// 9. Error Handling
app.use(errorHandler);

const startServer = async () => {
  let server: Server;

  try {
    // Ensure core infrastructure is ready
    await verifyDbConnection();
    await verifyEmailConnection();

    // 1. Start Express
    server = app.listen(PORT, () => {
      logger.info(
        `Server running at http://localhost:${PORT} in ${NODE_ENV} mode.`
      );
    });

    // 2. Start Telegram bot (Asynchronous/Non-blocking)
    // We do not await this so the HTTP server can remain healthy even if Telegram is slow
    telegramBot
      .launch()
      .catch((err) => logger.error("Telegram bot failed to start:", { err }));

    telegramBot.telegram.getMe().then((botInfo) => {
      logger.info(
        `🤖 Telegram bot started successfully as @${botInfo.username}`
      );
    });

    // 3. Graceful Shutdown Logic
    const shutdown = async (signal: string) => {
      logger.info(`${signal} received. Starting graceful shutdown...`);

      // Force exit if cleanup takes too long (e.g., hanging sockets)
      const forceExit = setTimeout(() => {
        logger.error("Graceful shutdown timed out. Forcing exit.");
        process.exit(1);
      }, 10000);

      try {
        // Stop Telegram Bot
        if (telegramBot) {
          await telegramBot.stop(signal);
          logger.info("Telegram bot stopped.");
        }

        // Stop Express Server (Stops accepting new connections)
        if (server) {
          await promisify(server.close.bind(server))();
          logger.info("Express server closed.");
        }

        // Close Database (Critical: prevents connection leaks)
        if (typeof prisma !== "undefined" && prisma.$disconnect) {
          await prisma.$disconnect();
          logger.info("Database connection closed.");
        }

        clearTimeout(forceExit);
        logger.info("Shutdown successful.");
        process.exit(0);
      } catch (err) {
        logger.error("Error during shutdown:", { err });
        process.exit(1);
      }
    };

    // Listen for termination signals
    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  } catch (error) {
    logger.error("Failed to start application:", { error });
    process.exit(1);
  }
};

/**
 * GLOBAL PROCESS ERROR HANDLERS
 */
process.on("unhandledRejection", (reason) => {
  logger.error("Unhandled Promise Rejection:", { reason });
  // In 2026, it is best practice to let the process crash/restart on unhandled rejections
  // to avoid unpredictable state.
  process.exit(1);
});

process.on("uncaughtException", (error) => {
  logger.error("Uncaught Exception! Check your logic:", { error });
  process.exit(1);
});

// Run the application
startServer();
