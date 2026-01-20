import rateLimit from "express-rate-limit";

/**
 * Perfected Rate Limiter
 * Balanced for general API usage with proxy support.
 */
export const generalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window

  // Custom Response Structure
  message: {
    status: 429,
    success: false,
    message: "Too many requests, please slow down.",
  },

  // Recommended Settings
  standardHeaders: "draft-7", // Use the latest standard for headers
  legacyHeaders: false,

  // Essential for Production:
  // Ensures that if a user is behind a proxy (Heroku, AWS, Nginx),
  // we rate limit the user's IP, not the Proxy's IP.
  validate: { trustProxy: true },

  // Optional: Skip rate limiting for specific users (e.g., internal health checks)
  skip: (req) => req.ip === "127.0.0.1",
});

/**
 * Pro-Tip: Create a stricter limiter for sensitive routes
 */
export const authRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Only 10 failed attempts per hour
  message: {
    success: false,
    message: "Too many login attempts. Please try again in an hour.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});
