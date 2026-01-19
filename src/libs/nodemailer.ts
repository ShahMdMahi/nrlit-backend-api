import nodemailer from "nodemailer";
import hbs, {
  NodemailerExpressHandlebarsOptions,
} from "nodemailer-express-handlebars";
import path from "path";
import { fileURLToPath } from "url";
import { env } from "./env.js";
import { logger } from "../utils/logger.js";

// 1. ESM Path Handling
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// Pointing to src/emails
const viewPath = path.resolve(__dirname, "../emails");

// 2. Transporter Configuration
export const transporter = nodemailer.createTransport({
  host: "smtp.resend.com",
  secure: true,
  port: 465,
  auth: {
    user: "resend",
    pass: env.RESEND_API_KEY,
  },
  pool: true, // Reuses connections for better performance
  maxConnections: 5,
  maxMessages: 100,
});

// 3. Handlebars Configuration with explicit Type
const handlebarOptions: NodemailerExpressHandlebarsOptions = {
  viewEngine: {
    extname: ".handlebars", // Engine expects lowercase
    partialsDir: viewPath,
    layoutsDir: viewPath,
    defaultLayout: undefined,
  },
  viewPath: viewPath,
  extName: ".handlebars", // Plugin expects camelCase
};

transporter.use("compile", hbs(handlebarOptions));

/**
 * 4. Verify Connection
 */
export const verifyEmailConnection = async (): Promise<void> => {
  try {
    await transporter.verify();
    logger.info("📧 Email service initialized successfully");
  } catch (error) {
    logger.error("❌ Email service failed to connect:", { error });
    // In many production environments, you want to throw here so the container restarts
    throw error;
  }
};
