import winston from "winston";

const { combine, timestamp, errors, json, printf, colorize } = winston.format;

const isProd = process.env.NODE_ENV === "production";

/* Dev console format */
const devFormat = printf(({ level, message, timestamp, stack, ...meta }) => {
  return `${timestamp} ${level}: ${stack || message} ${
    Object.keys(meta).length ? JSON.stringify(meta) : ""
  }`;
});

export const logger = winston.createLogger({
  level: isProd ? "info" : "debug",
  format: combine(
    timestamp(),
    errors({ stack: true }),
    isProd ? json() : devFormat
  ),
  transports: [
    new winston.transports.File({
      filename: "logs/error.log",
      level: "error",
    }),
    new winston.transports.File({
      filename: "logs/combined.log",
    }),
    ...(isProd
      ? []
      : [
          new winston.transports.Console({
            format: combine(colorize(), devFormat),
          }),
        ]),
  ],
  exceptionHandlers: [
    new winston.transports.File({ filename: "logs/exceptions.log" }),
  ],
  rejectionHandlers: [
    new winston.transports.File({ filename: "logs/rejections.log" }),
  ],
});
