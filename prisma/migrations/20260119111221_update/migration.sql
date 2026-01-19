/*
  Warnings:

  - You are about to drop the column `browserEngine` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `browserName` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `browserVersion` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `city` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `country` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `cpuArch` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `deviceBrand` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `deviceModel` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `deviceName` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `deviceType` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `isp` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `latitude` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `longitude` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `osName` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `osVersion` on the `AuditLog` table. All the data in the column will be lost.
  - You are about to drop the column `region` on the `AuditLog` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "AuditLog" DROP COLUMN "browserEngine",
DROP COLUMN "browserName",
DROP COLUMN "browserVersion",
DROP COLUMN "city",
DROP COLUMN "country",
DROP COLUMN "cpuArch",
DROP COLUMN "deviceBrand",
DROP COLUMN "deviceModel",
DROP COLUMN "deviceName",
DROP COLUMN "deviceType",
DROP COLUMN "isp",
DROP COLUMN "latitude",
DROP COLUMN "longitude",
DROP COLUMN "osName",
DROP COLUMN "osVersion",
DROP COLUMN "region";

-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "browserEngine" TEXT,
ADD COLUMN     "browserName" TEXT,
ADD COLUMN     "browserVersion" TEXT,
ADD COLUMN     "city" TEXT,
ADD COLUMN     "country" TEXT,
ADD COLUMN     "cpuArch" TEXT,
ADD COLUMN     "deviceBrand" TEXT,
ADD COLUMN     "deviceModel" TEXT,
ADD COLUMN     "deviceName" TEXT,
ADD COLUMN     "deviceType" "DeviceType" NOT NULL DEFAULT 'UNKNOWN',
ADD COLUMN     "isp" TEXT,
ADD COLUMN     "latitude" TEXT,
ADD COLUMN     "longitude" TEXT,
ADD COLUMN     "osName" TEXT,
ADD COLUMN     "osVersion" TEXT,
ADD COLUMN     "region" TEXT;
