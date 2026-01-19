import "dotenv/config";
import { Pool } from "pg";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../prisma/client.js";
import { logger } from "../utils/logger.js";

const connectionString = process.env.DATABASE_URL;

// 1. Initialize the PostgreSQL pool
export const pool = new Pool({
  connectionString,
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// 2. Setup the adapter
const adapter = new PrismaPg(pool);

// 3. Instantiate the Prisma Client with the adapter
export const prisma = new PrismaClient({ adapter });

/**
 * 4. Verify Database Connection
 * Checks the pool connectivity and Prisma's ability to execute a query
 */
export const verifyDbConnection = async (): Promise<void> => {
  try {
    // Check if the pool can connect
    const client = await pool.connect();
    client.release(); // Release back to pool immediately

    // Check if Prisma can execute a raw query
    await prisma.$queryRaw`SELECT 1`;

    logger.info(
      "🗄️  Database connection established successfully (Adapter-PG)"
    );
  } catch (error) {
    logger.error("❌ Database connection failed:", { error });
    // Exit process because the DB is a hard dependency
    process.exit(1);
  }
};
