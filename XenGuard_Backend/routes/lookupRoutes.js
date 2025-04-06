import express from 'express';
import lookupService from '../services/lookupService.js';
import { protect } from '../middleware/auth.js';

const router = express.Router();

router.post('/lookup', protect, async (req, res) => {
  try {
    const { query, type } = req.body;
    
    if (!query || !type) {
      return res.status(400).json({ error: 'Query and type are required' });
    }

    const results = await lookupService.lookup(query, type);

    res.json({
      success: true,
      data: {
        query,
        type,
        results: {
          virusTotal: results.virusTotal,
          history: results.history
        }
      }
    });
  } catch (error) {
    console.error('Lookup failed:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
