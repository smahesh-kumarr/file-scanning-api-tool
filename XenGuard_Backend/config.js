import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config();

const config = {
    mongoUri: process.env.MONGODB_URI || 'mongodb://localhost:27017/xenguard',
    jwtSecret: process.env.JWT_SECRET || 'xg_9d8f7g6h5j4k3l2m1n0p9q8r7s6t5u4v3w2x1y',
    port: parseInt(process.env.PORT, 10) || 4000,
    frontendUrl: process.env.FRONTEND_URL || 'http://localhost:5173'
};

export default config;
