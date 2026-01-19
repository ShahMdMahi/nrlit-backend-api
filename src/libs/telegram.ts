import { Telegraf } from "telegraf";
import { env } from "./env.js";

const bot = new Telegraf(env.TELEGRAM_BOT_TOKEN);

bot.start((ctx) => ctx.reply("Welcome! Use /help to see what I can do."));
bot.command("help", (ctx) =>
  ctx.reply("I am a Telegraf bot! Send me a message.")
);

export { bot as telegramBot };
