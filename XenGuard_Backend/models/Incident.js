import mongoose from 'mongoose';

const incidentSchema = new mongoose.Schema({
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
        enum: ['SECURITY_BREACH', 'MALWARE_OUTBREAK', 'DDOS', 'DATA_LEAK', 'UNAUTHORIZED_ACCESS', 'OTHER'],
        required: true
    },
    status: {
        type: String,
        enum: ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'],
        default: 'OPEN'
    },
    discoveredBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    assignedTeam: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    relatedAlerts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Alert'
    }],
    relatedThreats: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Threat'
    }],
    timeline: [{
        timestamp: {
            type: Date,
            default: Date.now
        },
        action: {
            type: String,
            required: true
        },
        description: String,
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        evidence: [{
            type: {
                type: String,
                enum: ['LOG', 'SCREENSHOT', 'FILE', 'NOTE']
            },
            description: String,
            url: String,
            metadata: mongoose.Schema.Types.Mixed
        }]
    }],
    impact: {
        systems: [{
            name: String,
            status: {
                type: String,
                enum: ['AFFECTED', 'AT_RISK', 'STABLE']
            }
        }],
        users: {
            type: Number,
            default: 0
        },
        financial: {
            estimated: Number,
            currency: {
                type: String,
                default: 'USD'
            }
        },
        description: String
    },
    containmentSteps: [{
        step: String,
        status: {
            type: String,
            enum: ['PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED']
        },
        assignedTo: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        completedAt: Date
    }],
    lessonLearned: {
        rootCause: String,
        preventiveMeasures: [String],
        recommendations: [String]
    },
    attachments: [{
        name: String,
        type: String,
        url: String,
        uploadedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        uploadedAt: {
            type: Date,
            default: Date.now
        }
    }]
}, {
    timestamps: true
});

// Indexes for efficient querying
incidentSchema.index({ status: 1, severity: 1 });
incidentSchema.index({ type: 1 });
incidentSchema.index({ discoveredBy: 1 });
incidentSchema.index({ 'assignedTeam': 1 });
incidentSchema.index({ createdAt: 1 });
incidentSchema.index({ 'impact.systems.status': 1 });

const Incident = mongoose.model('Incident', incidentSchema);

export default Incident;
