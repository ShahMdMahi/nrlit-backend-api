/*
  Warnings:

  - The values [GUEST_USER] on the enum `Role` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "Role_new" AS ENUM ('SYSTEM_OWNER', 'SYSTEM_ADMIN', 'SYSTEM_MODERATOR', 'SYSTEM_USER', 'NORMAL_USER');
ALTER TABLE "User" ALTER COLUMN "role" TYPE "Role_new" USING ("role"::text::"Role_new");
ALTER TYPE "Role" RENAME TO "Role_old";
ALTER TYPE "Role_new" RENAME TO "Role";
DROP TYPE "public"."Role_old";
COMMIT;

-- AlterTable
ALTER TABLE "User" ALTER COLUMN "role" SET DEFAULT 'NORMAL_USER';

-- CreateIndex
CREATE INDEX "User_username_email_phone_idx" ON "User"("username", "email", "phone");
