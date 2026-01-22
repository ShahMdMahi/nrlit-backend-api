import { prisma } from "../libs/db.js";
import { logger } from "./logger.js";
import { AuditEntity, AuditAction } from "../prisma/enums.js";
import { escapeMarkdownV2, formatJson } from "./escape-telegram-markdown.js";
import { telegramBot } from "../libs/telegram.js";
import { env } from "../libs/env.js";

export async function logAuditEvent({
  entity,
  action,
  entityId,
  description,
  userId,
  ipAddress,
  userAgent,
  fingerprint,
  metadata,
}: {
  entity: AuditEntity;
  action: AuditAction;
  entityId: string;
  description: string;
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  fingerprint?: string;
  metadata?: string;
}): Promise<void> {
  try {
    const log = await prisma.auditLog.create({
      data: {
        entity,
        action,
        entityId,
        description,
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        fingerprint: fingerprint ?? null,
        metadata: metadata ? JSON.parse(metadata) : null,
        user: { connect: { id: userId } },
      },
    });

    const timestamp = await log.createdAt.toLocaleString("en-US", {
      timeZone: "Asia/Dhaka",
      timeStyle: "long",
      dateStyle: "long",
    });
    const formattedMetadata = metadata
      ? formatJson(JSON.parse(metadata))
      : "None";

    const markdownText = `
**🔍 Audit Log Entry**

**Entity:** ${escapeMarkdownV2(entity)}
**Action:** ${escapeMarkdownV2(action)}
**Entity ID:** ${escapeMarkdownV2(entityId)}
**Description:** ${escapeMarkdownV2(description)}
**User ID:** ${escapeMarkdownV2(userId)}
**IP Address:** ${ipAddress ? escapeMarkdownV2(ipAddress) : "N/A"}
**User Agent:** ${userAgent ? escapeMarkdownV2(userAgent) : "N/A"}
**Fingerprint:** ${fingerprint ? escapeMarkdownV2(fingerprint) : "N/A"}
**Timestamp:** ${escapeMarkdownV2(timestamp)}

**Metadata:**
\`\`\`json
${formattedMetadata}
\`\`\`
`.trim();

    try {
      await telegramBot.telegram.sendMessage(
        env.TELEGRAM_CHAT_ID,
        markdownText,
        {
          parse_mode: "MarkdownV2",
        }
      );
    } catch (err) {
      logger.error("Failed to send audit log to Telegram", { err });
    }
  } catch (error) {
    logger.error("Failed to create audit log:", { error });
    throw error;
  }
}
