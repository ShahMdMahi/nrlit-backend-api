import { xss } from "express-xss-sanitizer";

export const xssSanitizeMiddleware = xss({
  allowedTags: [],
  allowedAttributes: {},
});
