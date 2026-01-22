import { Request, Response, NextFunction } from "express";
import crypto from "node:crypto";
import { env } from "../libs/env.js";
import { HttpError } from "../utils/http-error.js";

function deriveKey(secret: string, purpose: string) {
  // SHA256(secret + purpose)
  return crypto.createHash("sha256").update(`${purpose}:${secret}`).digest();
}

function decryptDevicePayload(
  encryptedBase64: string,
  ivBase64: string,
  secret: string
) {
  const data = Buffer.from(encryptedBase64, "base64");
  const iv = Buffer.from(ivBase64, "base64");

  const key = deriveKey(secret, "device-encryption");

  const encrypted = data.subarray(0, data.length - 16); // last 16 bytes = GCM tag
  const tag = data.subarray(data.length - 16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return JSON.parse(decrypted.toString("utf8"));
}

export const hmacAuthorize = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const signature = req.get("x-signature");
  const timestamp = req.get("x-timestamp");
  const bodyString = req.body ? JSON.stringify(req.body) : "";

  if (!signature || !timestamp)
    throw new HttpError("Missing Authentication Headers", 401);

  const now = Date.now();
  const requestTime = parseInt(timestamp, 10);
  if (isNaN(requestTime) || Math.abs(now - requestTime) > 5 * 60 * 1000)
    throw new HttpError("Request expired or timestamp invalid", 401);

  // 1️⃣ HMAC validation
  const message = `${req.method}:${req.path}:${timestamp}:${bodyString}`;
  const expectedSignature = crypto
    .createHmac("sha256", deriveKey(env.API_SECRET, "hmac"))
    .update(message)
    .digest("hex");

  if (
    !crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    )
  )
    throw new HttpError("Invalid Signature", 403);

  // 2️⃣ Device decryption
  const encryptedDevice = req.get("x-device");
  const deviceIv = req.get("x-device-iv");
  if (!encryptedDevice || !deviceIv)
    throw new HttpError("Missing Device Headers", 401);

  try {
    const deviceInfo = decryptDevicePayload(
      encryptedDevice,
      deviceIv,
      env.API_SECRET
    );
    req.device = deviceInfo;
  } catch {
    throw new HttpError("Invalid Device Payload", 403);
  }

  next();
};
