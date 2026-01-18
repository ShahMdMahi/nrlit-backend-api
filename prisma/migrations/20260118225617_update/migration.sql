/*
  Warnings:

  - A unique constraint covering the columns `[username,email,phone]` on the table `User` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "User_email_username_phone_key";

-- CreateIndex
CREATE INDEX "User_id_idx" ON "User"("id");

-- CreateIndex
CREATE UNIQUE INDEX "User_username_email_phone_key" ON "User"("username", "email", "phone");
