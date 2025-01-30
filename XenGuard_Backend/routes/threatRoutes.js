import express from 'express';
import { body, param } from 'express-validator';
import Threat from '../models/Threat.js';
import { protect } from '../middleware/auth.js';
import { validateRequest } from '../middleware/validate.js';

const router = express.Router();

// Get all threats with filtering
router.get('/', protect, async (req, res) => {
    try {
        const { severity, type, status, search } = req.query;
        const query = {};

        if (severity) query.severity = severity;
        if (type) query.type = type;
        if (status) query.status = status;
        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }

        const threats = await Threat.find(query)
            .sort({ createdAt: -1 });

        res.json({ success: true, data: threats });
    } catch (error) {
        console.error('Error fetching threats:', error);
        res.status(500).json({ success: false, error: 'Error fetching threats' });
    }
});

// Get threat by ID
router.get('/:id', protect, async (req, res) => {
    try {
        const threat = await Threat.findById(req.params.id);
        if (!threat) {
            return res.status(404).json({ success: false, error: 'Threat not found' });
        }
        res.json({ success: true, data: threat });
    } catch (error) {
        console.error('Error fetching threat:', error);
        res.status(500).json({ success: false, error: 'Error fetching threat' });
    }
});

// Create new threat
router.post('/', 
    protect,
    [
        body('title').notEmpty().trim(),
        body('description').notEmpty(),
        body('severity').isIn(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
        body('type').isIn(['MALWARE', 'VULNERABILITY', 'PHISHING', 'DATA_BREACH', 'RANSOMWARE', 'OTHER']),
        validateRequest
    ],
    async (req, res) => {
        try {
            const threat = new Threat(req.body);
            await threat.save();
            res.status(201).json({ success: true, data: threat });
        } catch (error) {
            console.error('Error creating threat:', error);
            res.status(500).json({ success: false, error: 'Error creating threat' });
        }
    }
);

// Update threat
router.put('/:id',
    protect,
    [
        param('id').isMongoId(),
        body('status').optional().isIn(['ACTIVE', 'RESOLVED', 'INVESTIGATING', 'FALSE_POSITIVE']),
        body('severity').optional().isIn(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
        validateRequest
    ],
    async (req, res) => {
        try {
            const threat = await Threat.findByIdAndUpdate(
                req.params.id,
                req.body,
                { new: true }
            );
            
            if (!threat) {
                return res.status(404).json({ success: false, error: 'Threat not found' });
            }
            
            res.json({ success: true, data: threat });
        } catch (error) {
            console.error('Error updating threat:', error);
            res.status(500).json({ success: false, error: 'Error updating threat' });
        }
    }
);

// Delete threat
router.delete('/:id',
    protect,
    [param('id').isMongoId(), validateRequest],
    async (req, res) => {
        try {
            const threat = await Threat.findByIdAndDelete(req.params.id);
            
            if (!threat) {
                return res.status(404).json({ success: false, error: 'Threat not found' });
            }
            
            res.json({ success: true, message: 'Threat deleted successfully' });
        } catch (error) {
            console.error('Error deleting threat:', error);
            res.status(500).json({ success: false, error: 'Error deleting threat' });
        }
    }
);

export default router;
