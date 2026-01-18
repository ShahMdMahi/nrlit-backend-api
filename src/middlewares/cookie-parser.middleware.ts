import cookieParser from "cookie-parser";
import { env } from "../libs/env.js";

const COOKIE_SECRET = env.COOKIE_SECRET;

export const cookieParserMiddleware = cookieParser(COOKIE_SECRET);
