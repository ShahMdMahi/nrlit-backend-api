/*
  Warnings:

  - You are about to drop the column `browserEngine` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `browserName` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `browserVersion` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `city` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `country` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `cpuArch` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `deviceBrand` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `deviceModel` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `deviceName` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `deviceType` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `isp` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `latitude` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `longitude` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `osName` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `osVersion` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `region` on the `Session` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "Session" DROP COLUMN "browserEngine",
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
