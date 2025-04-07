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
import fs from 'fs';
import threatScanRoutes from './routes/threatScanRoutes.js';
import alertRoutes from './routes/alertRoutes.js';
import securityRoutes from './routes/securityRoutes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config();

// Verify environment variables
const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET', 'PORT'];
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

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Middleware
app.use(express.json());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// Log all incoming requests
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
    next();
});

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/security", securityRoutes);
app.use("/api/threats", threatRoutes);
app.use("/api/alerts", alertRoutes);
app.use("/api/scan", threatScanRoutes);
app.use("/api", lookupRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// 404 handler
app.use((req, res) => {
    console.error(`404 - Not Found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        error: 'Server Error',
        message: err.message
    });
});

// WebSocket connection handling
io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

// Connect to MongoDB
async function connectDB() {
    try {
        console.log('MongoDB URI:', process.env.MONGO_URI);
        console.log('Attempting to connect to MongoDB...');
        
        await mongoose.connect(process.env.MONGO_URI);
        
        console.log('Connected to MongoDB successfully');
        
        // Test the connection
        const db = mongoose.connection;
        await db.collection('users').findOne({});
        console.log('MongoDB ping successful');
        
        // Log available collections
        const collections = await db.db.listCollections().toArray();
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
        process.exit(1);
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
