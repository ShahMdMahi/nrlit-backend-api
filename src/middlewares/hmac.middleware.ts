import { Request, Response, NextFunction } from "express";
import crypto from "node:crypto";
import { env } from "../libs/env.js";
import { HttpError } from "../utils/http-error.js";

export const hmacAuthorize = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const signature = req.get("x-signature");
  const timestamp = req.get("x-timestamp"); // Prevents replay attacks
  const bodyString = req.body ? JSON.stringify(req.body) : "";

  if (!signature || !timestamp) {
    throw new HttpError("Missing Authentication Headers", 401);
  }

  // 1. Check if the request is "old" (e.g., more than 5 minutes)
  // This prevents an attacker from capturing a valid request and re-sending it later.
  const now = Date.now();
  const requestTime = parseInt(timestamp, 10);
  if (isNaN(requestTime) || Math.abs(now - requestTime) > 5 * 60 * 1000) {
    throw new HttpError("Request expired or timestamp invalid", 401);
  }

  // 2. Reconstruct the message that was signed
  // We include the method, path, and timestamp.
  const message = `${req.method}:${req.path}:${timestamp}:${bodyString}`;

  // 3. Generate our own signature using the secret stored in env
  const expectedSignature = crypto
    .createHmac("sha256", env.API_SECRET)
    .update(message)
    .digest("hex");

  // 4. Compare using timing-safe logic
  const isSignatureValid = crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );

  if (!isSignatureValid) {
    throw new HttpError("Invalid Signature", 403);
  }

  next();
};

// Usage Example:
// // libs/api-client.ts
// import { crypto } from "node:crypto";

// export async function generateHmacHeaders(method: string, path: string, body?: any) {
//   const timestamp = Date.now().toString();
//   const secret = process.env.API_SECRET!;

//   // The exact same "Message String" format your middleware expects
//   const bodyString = body ? JSON.stringify(body) : "";
//   const message = `${method.toUpperCase()}:${path}:${timestamp}:${bodyString}`;

//   const signature = crypto
//     .createHmac("sha256", secret)
//     .update(message)
//     .digest("hex");

//   return {
//     "Content-Type": "application/json",
//     "x-signature": signature,
//     "x-timestamp": timestamp,
//   };
// }

// // app/dashboard/page.tsx
// import { generateHmacHeaders } from "@/libs/api-client";

// export default async function DashboardPage() {
//   const path = "/api/v1/stats";
//   const headers = await generateHmacHeaders("GET", path);

//   const res = await fetch(`http://localhost:4000${path}`, {
//     method: "GET",
//     headers,
//     next: { revalidate: 60 } // Perfect for caching
//   });

//   const data = await res.json();

//   return (
//     <div>
//       <h1>Stats: {data.value}</h1>
//     </div>
//   );
// }

// // app/actions.ts
// "use server";
// import { generateHmacHeaders } from "@/libs/api-client";

// export async function createUser(formData: FormData) {
//   const path = "/api/v1/users";
//   const userData = { name: formData.get("name") };

//   const headers = await generateHmacHeaders("POST", path, userData);

//   const res = await fetch(`http://localhost:4000${path}`, {
//     method: "POST",
//     headers,
//     body: JSON.stringify(userData),
//   });

//   return res.json();
// }
