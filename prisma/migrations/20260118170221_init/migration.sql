-- CreateEnum
CREATE TYPE "Role" AS ENUM ('SYSTEM_OWNER', 'SYSTEM_ADMIN', 'SYSTEM_MODERATOR', 'SYSTEM_USER', 'NORMAL_USER', 'GUEST_USER');

-- CreateEnum
CREATE TYPE "DeviceType" AS ENUM ('DESKTOP', 'MOBILE', 'TABLET', 'TV', 'WEARABLE', 'CONSOLE', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "BlogProfileVisibility" AS ENUM ('PUBLIC', 'PRIVATE');

-- CreateEnum
CREATE TYPE "BlogPostVisibility" AS ENUM ('PUBLIC', 'PRIVATE', 'UNLISTED');

-- CreateEnum
CREATE TYPE "BlogPostStatus" AS ENUM ('DRAFT', 'PUBLISHED', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "AuditEntity" AS ENUM ('USER', 'SESSION', 'BLOG_PROFILE', 'BLOG_POST', 'BLOG_POST_COMMENT');

-- CreateEnum
CREATE TYPE "AuditAction" AS ENUM ('USER_REGISTERED', 'USER_LOGGED_IN', 'USER_LOGGED_OUT', 'USER_FORGOT_PASSWORD', 'USER_RESET_PASSWORD', 'USER_RESEND_VERIFICATION', 'USER_2FA_ENABLED', 'USER_2FA_DISABLED', 'USER_2FA_CODES_GENERATED', 'USER_2FA_CHALLENGED', 'USER_2FA_VERIFIED', 'USER_2FA_FAILED', 'USER_2FA_RECOVERED', 'USER_FAILED_LOGIN', 'USER_CHANGED_PASSWORD', 'USER_UPDATED_PROFILE', 'USER_VERIFIED', 'USER_APPROVED', 'USER_SUSPENDED', 'USER_BANNED', 'USER_LOCKED', 'USER_CREATED', 'USER_UPDATED', 'USER_DELETED', 'SESSION_CREATED', 'SESSION_EXPIRED', 'SESSION_REVOKED', 'BLOG_PROFILE_CREATED', 'BLOG_PROFILE_UPDATED', 'BLOG_PROFILE_DELETED', 'BLOG_POST_CREATED', 'BLOG_POST_UPDATED', 'BLOG_POST_DELETED', 'BLOG_POST_STATUS_CHANGED', 'BLOG_POST_VISIBILITY_CHANGED', 'BLOG_POST_COMMENT_CREATED', 'BLOG_POST_COMMENT_UPDATED', 'BLOG_POST_COMMENT_DELETED');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "firstName" TEXT NOT NULL,
    "lastName" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "phone" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "avatar" TEXT,
    "dateOfBirth" TIMESTAMP(3),
    "failedLoginAttempts" INTEGER NOT NULL DEFAULT 0,
    "twoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
    "twoFactorSecret" TEXT,
    "twoFactorBackupCodes" TEXT[],
    "role" "Role" NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "verifiedAt" TIMESTAMP(3),
    "approvedAt" TIMESTAMP(3),
    "suspendedAt" TIMESTAMP(3),
    "bannedAt" TIMESTAMP(3),
    "lockedUntil" TIMESTAMP(3),

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "ipAddress" TEXT,
    "isp" TEXT,
    "region" TEXT,
    "country" TEXT,
    "city" TEXT,
    "latitude" DOUBLE PRECISION,
    "longitude" DOUBLE PRECISION,
    "userAgent" TEXT,
    "fingerprint" TEXT,
    "deviceName" TEXT,
    "deviceBrand" TEXT,
    "deviceModel" TEXT,
    "osName" TEXT,
    "osVersion" TEXT,
    "browserName" TEXT,
    "browserVersion" TEXT,
    "browserEngine" TEXT,
    "cpuArch" TEXT,
    "deviceType" "DeviceType" NOT NULL DEFAULT 'UNKNOWN',
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "accessedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiredAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlogProfile" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "bio" TEXT,
    "website" TEXT,
    "location" TEXT,
    "visibility" "BlogProfileVisibility" NOT NULL DEFAULT 'PUBLIC',
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "BlogProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlogPost" (
    "id" TEXT NOT NULL,
    "blogProfileId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "summary" TEXT,
    "coverImage" TEXT,
    "visibility" "BlogPostVisibility" NOT NULL DEFAULT 'PRIVATE',
    "status" "BlogPostStatus" NOT NULL DEFAULT 'DRAFT',
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "publishedAt" TIMESTAMP(3),
    "archivedAt" TIMESTAMP(3),

    CONSTRAINT "BlogPost_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlogPostComment" (
    "id" TEXT NOT NULL,
    "blogPostId" TEXT NOT NULL,
    "blogProfileId" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "BlogPostComment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "entityId" TEXT NOT NULL,
    "entity" "AuditEntity" NOT NULL,
    "action" "AuditAction" NOT NULL,
    "description" TEXT,
    "ipAddress" TEXT,
    "isp" TEXT,
    "region" TEXT,
    "country" TEXT,
    "city" TEXT,
    "latitude" DOUBLE PRECISION,
    "longitude" DOUBLE PRECISION,
    "userAgent" TEXT,
    "fingerprint" TEXT,
    "deviceName" TEXT,
    "deviceBrand" TEXT,
    "deviceModel" TEXT,
    "osName" TEXT,
    "osVersion" TEXT,
    "browserName" TEXT,
    "browserVersion" TEXT,
    "browserEngine" TEXT,
    "cpuArch" TEXT,
    "deviceType" "DeviceType" NOT NULL DEFAULT 'UNKNOWN',
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- CreateIndex
CREATE UNIQUE INDEX "User_phone_key" ON "User"("phone");

-- CreateIndex
CREATE INDEX "User_id_deletedAt_idx" ON "User"("id", "deletedAt");

-- CreateIndex
CREATE INDEX "User_email_deletedAt_idx" ON "User"("email", "deletedAt");

-- CreateIndex
CREATE INDEX "User_username_deletedAt_idx" ON "User"("username", "deletedAt");

-- CreateIndex
CREATE INDEX "User_phone_deletedAt_idx" ON "User"("phone", "deletedAt");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_username_phone_key" ON "User"("email", "username", "phone");

-- CreateIndex
CREATE UNIQUE INDEX "Session_token_key" ON "Session"("token");

-- CreateIndex
CREATE INDEX "Session_id_deletedAt_idx" ON "Session"("id", "deletedAt");

-- CreateIndex
CREATE INDEX "Session_userId_deletedAt_idx" ON "Session"("userId", "deletedAt");

-- CreateIndex
CREATE UNIQUE INDEX "BlogProfile_userId_key" ON "BlogProfile"("userId");

-- CreateIndex
CREATE INDEX "BlogProfile_id_visibility_deletedAt_idx" ON "BlogProfile"("id", "visibility", "deletedAt");

-- CreateIndex
CREATE INDEX "BlogProfile_userId_visibility_deletedAt_idx" ON "BlogProfile"("userId", "visibility", "deletedAt");

-- CreateIndex
CREATE UNIQUE INDEX "BlogPost_slug_key" ON "BlogPost"("slug");

-- CreateIndex
CREATE INDEX "BlogPost_id_status_visibility_deletedAt_idx" ON "BlogPost"("id", "status", "visibility", "deletedAt");

-- CreateIndex
CREATE INDEX "BlogPost_slug_status_visibility_deletedAt_idx" ON "BlogPost"("slug", "status", "visibility", "deletedAt");

-- CreateIndex
CREATE INDEX "BlogPost_publishedAt_status_visibility_deletedAt_idx" ON "BlogPost"("publishedAt", "status", "visibility", "deletedAt");

-- CreateIndex
CREATE INDEX "BlogPost_archivedAt_status_visibility_deletedAt_idx" ON "BlogPost"("archivedAt", "status", "visibility", "deletedAt");

-- CreateIndex
CREATE INDEX "BlogPostComment_id_deletedAt_idx" ON "BlogPostComment"("id", "deletedAt");

-- CreateIndex
CREATE INDEX "BlogPostComment_blogPostId_deletedAt_idx" ON "BlogPostComment"("blogPostId", "deletedAt");

-- CreateIndex
CREATE INDEX "BlogPostComment_blogProfileId_deletedAt_idx" ON "BlogPostComment"("blogProfileId", "deletedAt");

-- CreateIndex
CREATE INDEX "AuditLog_id_idx" ON "AuditLog"("id");

-- CreateIndex
CREATE INDEX "AuditLog_userId_idx" ON "AuditLog"("userId");

-- CreateIndex
CREATE INDEX "AuditLog_entity_entityId_idx" ON "AuditLog"("entity", "entityId");

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BlogProfile" ADD CONSTRAINT "BlogProfile_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BlogPost" ADD CONSTRAINT "BlogPost_blogProfileId_fkey" FOREIGN KEY ("blogProfileId") REFERENCES "BlogProfile"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BlogPostComment" ADD CONSTRAINT "BlogPostComment_blogPostId_fkey" FOREIGN KEY ("blogPostId") REFERENCES "BlogPost"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BlogPostComment" ADD CONSTRAINT "BlogPostComment_blogProfileId_fkey" FOREIGN KEY ("blogProfileId") REFERENCES "BlogProfile"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
