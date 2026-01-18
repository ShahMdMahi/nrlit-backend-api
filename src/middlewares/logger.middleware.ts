import { Request } from "express";
import morgan from "morgan";
import { logger } from "../utils/logger.js";

/* Custom token */
morgan.token("id", (req: Request) => req.id);

export const httpLogger = morgan(
  ":id :method :url :status :res[content-length] - :response-time ms",
  {
    stream: {
      write: (message) => {
        logger.info(message.trim(), { type: "http" });
      },
    },
  }
);
