/*
  Warnings:

  - You are about to drop the column `deletedAt` on the `Session` table. All the data in the column will be lost.
  - Made the column `expiredAt` on table `Session` required. This step will fail if there are existing NULL values in that column.

*/
-- DropIndex
DROP INDEX "Session_id_deletedAt_idx";

-- DropIndex
DROP INDEX "Session_userId_deletedAt_idx";

-- AlterTable
ALTER TABLE "Session" DROP COLUMN "deletedAt",
ALTER COLUMN "expiredAt" SET NOT NULL;

-- CreateIndex
CREATE INDEX "Session_id_idx" ON "Session"("id");

-- CreateIndex
CREATE INDEX "Session_userId_idx" ON "Session"("userId");

-- CreateIndex
CREATE INDEX "Session_token_idx" ON "Session"("token");

-- CreateIndex
CREATE INDEX "Session_accessedAt_idx" ON "Session"("accessedAt");
