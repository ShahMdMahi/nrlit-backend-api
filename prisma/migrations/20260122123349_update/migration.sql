/*
  Warnings:

  - You are about to drop the column `latitude` on the `Session` table. All the data in the column will be lost.
  - You are about to drop the column `longitude` on the `Session` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "Session" DROP COLUMN "latitude",
DROP COLUMN "longitude",
ADD COLUMN     "as" TEXT,
ADD COLUMN     "countryCode" TEXT,
ADD COLUMN     "lat" TEXT,
ADD COLUMN     "lon" TEXT,
ADD COLUMN     "org" TEXT,
ADD COLUMN     "regionName" TEXT,
ADD COLUMN     "timezone" TEXT,
ADD COLUMN     "zip" TEXT;
