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
    // In MarkdownV2, inside a pre-formatted code block (```),
    // only \ and ` need to be escaped.
    // We wrap the escaped string in JSON code block syntax.
    const escapedCode = jsonString.replace(/[`\\]/g, "\\$&");
    return `\`\`\`json\n${escapedCode}\n\`\`\``;
  } catch (error) {
    logger.error("Failed to stringify JSON data:", { error });
    return "Error: Could not stringify JSON data";
  }
};
