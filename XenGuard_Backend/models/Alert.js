import mongoose from 'mongoose';

const alertSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true
    },
    priority: {
        type: String,
        enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        required: true
    },
    category: {
        type: String,
        enum: ['INTRUSION', 'MALWARE', 'POLICY_VIOLATION', 'SYSTEM', 'NETWORK', 'OTHER'],
        required: true
    },
    source: {
        type: {
            type: String,
            enum: ['SYSTEM', 'USER', 'INTEGRATION', 'AUTOMATED'],
            required: true
        },
        name: String,
        details: mongoose.Schema.Types.Mixed
    },
    status: {
        type: String,
        enum: ['NEW', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE'],
        default: 'NEW'
    },
    assignedTo: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    relatedThreats: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Threat'
    }],
    affectedAssets: [{
        type: String,
        trim: true
    }],
    actions: [{
        type: {
            type: String,
            enum: ['CREATED', 'STATUS_CHANGED', 'ASSIGNED', 'COMMENT_ADDED', 'RESOLVED']
        },
        timestamp: {
            type: Date,
            default: Date.now
        },
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        details: mongoose.Schema.Types.Mixed
    }],
    metadata: {
        ipAddress: String,
        location: {
            country: String,
            city: String,
            coordinates: {
                type: [Number], // [longitude, latitude]
                index: '2dsphere'
            }
        },
        deviceInfo: mongoose.Schema.Types.Mixed
    }
}, {
    timestamps: true
});

// Indexes for efficient querying
alertSchema.index({ status: 1, priority: 1 });
alertSchema.index({ category: 1 });
alertSchema.index({ 'source.type': 1 });
alertSchema.index({ assignedTo: 1 });
alertSchema.index({ createdAt: 1 });
alertSchema.index({ 'metadata.ipAddress': 1 });
alertSchema.index({ 'metadata.location.coordinates': '2dsphere' });

const Alert = mongoose.model('Alert', alertSchema);

export default Alert;
