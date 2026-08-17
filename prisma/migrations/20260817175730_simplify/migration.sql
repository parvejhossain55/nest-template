/*
  Warnings:

  - You are about to drop the column `is_two_factor_enabled` on the `users` table. All the data in the column will be lost.
  - You are about to drop the `oauth_accounts` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `two_factor_auth` table. If the table is not empty, all the data it contains will be lost.
  - Made the column `password_hash` on table `users` required. This step will fail if there are existing NULL values in that column.

*/
-- DropForeignKey
ALTER TABLE "oauth_accounts" DROP CONSTRAINT "oauth_accounts_user_id_fkey";

-- DropForeignKey
ALTER TABLE "two_factor_auth" DROP CONSTRAINT "two_factor_auth_user_id_fkey";

-- AlterTable
ALTER TABLE "users" DROP COLUMN "is_two_factor_enabled",
ALTER COLUMN "password_hash" SET NOT NULL;

-- DropTable
DROP TABLE "oauth_accounts";

-- DropTable
DROP TABLE "two_factor_auth";

-- DropEnum
DROP TYPE "OAuthProvider";

-- DropEnum
DROP TYPE "TwoFactorMethod";
