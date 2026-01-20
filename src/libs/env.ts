import "dotenv/config";
import { cleanEnv, str, port, url } from "envalid";

export const env = cleanEnv(process.env, {
  NODE_ENV: str({ choices: ["development", "test", "production"] }),
  PORT: port(),
  DATABASE_URL: url(),
  COOKIE_SECRET: str(),
  ALLOWED_ORIGINS: str(),
  API_SECRET: str(),
  COOKIE_DOMAIN: str(),
  TELEGRAM_BOT_TOKEN: str(),
  TELEGRAM_CHAT_ID: str(),
  RESEND_API_KEY: str(),
  EMAIL_FROM: str(),
  FRONTEND_BASE_URL: url(),
});
