import { logger } from "./logger.js";

/**
 * Escape ALL special characters for MarkdownV2.
 * Best for raw user input or data from an API that isn't formatted yet.
 */
export const escapeMarkdownV2 = (text: string): string => {
  return text.replace(/[_*[\]()~`>#+\-=|{}.!]/g, "\\$&");
};

/**
 * Robust JSON Formatter for Telegram.
 * Handles deeply nested objects and ensures code blocks don't break.
 */
export const formatJson = (data: object): string => {
  try {
    const jsonString = JSON.stringify(data, null, 2);
    // Inside a code block, only backticks and backslashes need escaping
    const escaped = jsonString.replace(/[`\\]/g, "\\$&");
    return escaped; // Do NOT wrap with ```json here
  } catch (error) {
    logger.error("Failed to stringify JSON data:", { error });
    return "Error: Could not stringify JSON data";
  }
};
