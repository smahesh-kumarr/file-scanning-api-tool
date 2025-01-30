import mongoose from 'mongoose';

const threatSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true
    },
    severity: {
        type: String,
        enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        required: true
    },
    type: {
        type: String,
        enum: ['MALWARE', 'VULNERABILITY', 'PHISHING', 'DATA_BREACH', 'RANSOMWARE', 'OTHER'],
        required: true
    },
    source: {
        name: String,
        url: String,
        type: {
            type: String,
            enum: ['VIRUSTOTAL', 'ALIENVAULT', 'CVE', 'SOCIAL_MEDIA', 'MANUAL', 'OTHER']
        }
    },
    status: {
        type: String,
        enum: ['ACTIVE', 'RESOLVED', 'INVESTIGATING', 'FALSE_POSITIVE'],
        default: 'ACTIVE'
    },
    indicators: [{
        type: {
            type: String,
            enum: ['IP', 'DOMAIN', 'URL', 'FILE_HASH', 'EMAIL']
        },
        value: String,
        confidence: {
            type: Number,
            min: 0,
            max: 100
        }
    }],
    affectedSystems: [{
        type: String
    }],
    mitigation: {
        steps: [String],
        recommendations: String
    },
    tags: [{
        type: String,
        trim: true
    }],
    reportedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, {
    timestamps: true
});

// Add indexes for common queries
threatSchema.index({ severity: 1, status: 1 });
threatSchema.index({ type: 1 });
threatSchema.index({ 'source.type': 1 });
threatSchema.index({ tags: 1 });

const Threat = mongoose.model('Threat', threatSchema);

export default Threat;
