import { Request, Response, NextFunction } from "express";
import { v4 as uuid, validate as validateUuid } from "uuid";

export function requestId(req: Request, res: Response, next: NextFunction) {
  const existingId = req.get("X-Request-Id");

  const id = existingId && validateUuid(existingId) ? existingId : uuid();

  req.id = id;

  res.setHeader("X-Request-Id", id);

  next();
}
