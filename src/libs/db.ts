import "dotenv/config";
import { Pool } from "pg";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../prisma/client.js";

const connectionString = process.env.DATABASE_URL;

// 1. Initialize the PostgreSQL pool
const pool = new Pool({ connectionString });

// 2. Setup the adapter
const adapter = new PrismaPg(pool);

// 3. Instantiate the Prisma Client with the adapter
export const prisma = new PrismaClient({ adapter });
