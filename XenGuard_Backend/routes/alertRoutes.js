import express from 'express';
import { protect } from '../middleware/auth.js';

const router = express.Router();

// All routes require authentication
router.use(protect);

// Basic alert routes placeholder - can be expanded later
router.get('/', async (req, res) => {
    try {
        res.json({ alerts: [] });
    } catch (error) {
        console.error('Error fetching alerts:', error);
        res.status(500).json({ error: 'Failed to fetch alerts' });
    }
});

export default router;
