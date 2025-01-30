import express from "express";
import mongoose from "mongoose";
import authRoutes from "./routes/authRoutes.js";
import cors from "cors";
import bodyParser from "body-parser";
import config from "./config.js";
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import path from 'path';
import dotenv from 'dotenv';
import { createServer } from 'http';
import { Server } from 'socket.io';
import threatRoutes from './routes/threatRoutes.js';
import lookupRoutes from './routes/lookupRoutes.js';
import ThreatMonitoringService from './services/threatMonitoringService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config();

// Verify environment variables
const requiredEnvVars = [
  'JWT_SECRET',
  'PORT',
  'FRONTEND_URL',
  'MONGODB_URI',
  'VIRUSTOTAL_API_KEY',
  'SHODAN_API_KEY'
];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('Error: Missing required environment variables:', missingVars.join(', '));
    process.exit(1);
}

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: process.env.FRONTEND_URL || 'http://localhost:5173',
        methods: ['GET', 'POST']
    }
});

// Initialize threat monitoring service
const threatMonitoring = new ThreatMonitoringService(io);

// Middleware
app.use(express.json());
app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? 'https://xenguard.com' : ['http://localhost:5173', 'http://127.0.0.1:5173'],
    credentials: true
}));
app.use(bodyParser.json());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/threats", threatRoutes);
app.use("/api", lookupRoutes);

// WebSocket connection handling
io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error details:', err);
    res.status(500).json({
        success: false,
        error: "Server Error",
        message: process.env.NODE_ENV === 'development' ? err.message : 'Internal Server Error'
    });
});

// Connect to MongoDB
async function connectDB(retries = 5) {
    try {
        console.log('MongoDB URI:', process.env.MONGODB_URI);
        console.log('Attempting to connect to MongoDB...');
        
        await mongoose.connect(process.env.MONGODB_URI);
        
        console.log('Connected to MongoDB successfully');
        
        // Test the connection
        await mongoose.connection.db.admin().ping();
        console.log('MongoDB ping successful');
        
        // List all collections
        const collections = await mongoose.connection.db.listCollections().toArray();
        console.log('Available collections:', collections.map(c => c.name));
        
        // Start threat monitoring after database connection
        threatMonitoring.startMonitoring();
        
    } catch (err) {
        console.error('MongoDB connection error:', err);
        console.error('Error details:', {
            name: err.name,
            message: err.message,
            code: err.code,
            stack: err.stack
        });
        
        if (retries > 0) {
            console.log(`Retrying connection... (${retries} attempts remaining)`);
            await new Promise(resolve => setTimeout(resolve, 5000));
            return connectDB(retries - 1);
        }
        throw err;
    }
}

// Connect to MongoDB
connectDB().catch(err => {
    console.error("Failed to connect to MongoDB after all retries:", err);
    process.exit(1);
});

// Monitor MongoDB connection
mongoose.connection.on('error', err => {
    console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.warn('MongoDB disconnected. Attempting to reconnect...');
    connectDB();
});

// Function to start server
async function startServer(port) {
    try {
        await new Promise((resolve, reject) => {
            httpServer.listen(port, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
        console.log(`Server is running on port ${port}`);
    } catch (err) {
        console.error('Failed to start server:', err);
        if (err.code === 'EADDRINUSE') {
            console.log(`Port ${port} is busy, trying ${port + 1}...`);
            await startServer(port + 1);
        } else {
            process.exit(1);
        }
    }
}

// Start server with initial port
startServer(config.port);
