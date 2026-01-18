-- CreateIndex
CREATE INDEX "User_verificationToken_verificationTokenExpiredAt_deletedAt_idx" ON "User"("verificationToken", "verificationTokenExpiredAt", "deletedAt");

-- CreateIndex
CREATE INDEX "User_resetPasswordToken_resetPasswordTokenExpiredAt_deleted_idx" ON "User"("resetPasswordToken", "resetPasswordTokenExpiredAt", "deletedAt");
