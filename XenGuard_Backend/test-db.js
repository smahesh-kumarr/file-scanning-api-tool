import mongoose from 'mongoose';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

async function testConnection() {
    try {
        console.log('MongoDB URI:', process.env.MONGODB_URI);
        console.log('Attempting to connect to MongoDB...');
        
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        console.log('Connected to MongoDB successfully');
        
        // Test the connection
        await mongoose.connection.db.admin().ping();
        console.log('MongoDB ping successful');
        
        // List all collections
        const collections = await mongoose.connection.db.listCollections().toArray();
        console.log('Available collections:', collections.map(c => c.name));
        
        // Close the connection
        await mongoose.connection.close();
        console.log('Connection closed');
        
    } catch (err) {
        console.error('MongoDB connection error:', err);
        console.error('Error details:', {
            name: err.name,
            message: err.message,
            code: err.code,
            stack: err.stack
        });
    }
}

testConnection();
