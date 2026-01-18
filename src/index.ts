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
// import { hmacAuthorize } from "./middlewares/hmac.middleware.js";
import { useragentMiddleware } from "./middlewares/useragent.middleware.js";
import { hppMiddleware } from "./middlewares/hpp.middleware.js";
import { xssSanitizeMiddleware } from "./middlewares/xss-sanitize.middleware.js";
import { errorHandler } from "./middlewares/error.middleware.js";
import { authRouter } from "./routes/auth.route.js";
import { logger } from "./utils/logger.js";

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
// app.use(hmacAuthorize);

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

const server = app.listen(PORT, () => {
  logger.info(
    `Server is running at http://localhost:${PORT} in ${NODE_ENV} mode.`
  );
});

const shutdown = (signal: string) => {
  logger.info(`${signal} received. Starting graceful shutdown...`);
  server.close(() => {
    logger.info("Process terminated. Closed all active connections.");
    process.exit(0);
  });

  setTimeout(() => {
    logger.error("Could not close connections in time, forcing shutdown.");
    process.exit(1);
  }, 10000);
};

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
