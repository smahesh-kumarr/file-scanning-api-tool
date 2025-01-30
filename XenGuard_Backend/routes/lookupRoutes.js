import express from 'express';
import lookupService from '../services/lookupService.js';
import { protect } from '../middleware/auth.js';

const router = express.Router();

router.post('/lookup', protect, async (req, res) => {
  try {
    console.log('Received lookup request:', req.body);
    const { query, type } = req.body;

    if (!query || !type) {
      return res.status(400).json({
        success: false,
        message: 'Query and type are required'
      });
    }

    // Validate query type
    if (!['ip', 'domain', 'hash'].includes(type)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid lookup type. Must be ip, domain, or hash'
      });
    }

    console.log('Starting lookup operations for:', { query, type });

    // Perform lookups in parallel
    try {
      const [virusTotalResults, shodanResults, historyResults] = await Promise.all([
        lookupService.lookupVirusTotal(query, type).catch(error => {
          console.error('VirusTotal lookup failed:', error.message);
          return null;
        }),
        type === 'ip' ? lookupService.lookupShodan(query, type).catch(error => {
          console.error('Shodan lookup failed:', error.message);
          return null;
        }) : null,
        lookupService.getLookupHistory(query).catch(error => {
          console.error('History lookup failed:', error.message);
          return [];
        })
      ]);

      console.log('Lookup results:', {
        hasVirusTotal: !!virusTotalResults,
        hasShodan: !!shodanResults,
        historyCount: historyResults?.length
      });

      // Check if we have any results
      if (!virusTotalResults && !shodanResults) {
        return res.status(404).json({
          success: false,
          message: 'No results found from any source'
        });
      }

      // Prepare response data
      const results = {
        virustotal: virusTotalResults,
        shodan: shodanResults,
        history: historyResults
      };

      // Save lookup history
      try {
        await lookupService.saveLookupHistory(query, type, results, req.user.id);
      } catch (error) {
        console.error('Failed to save history:', error);
        // Continue even if history save fails
      }

      res.json({
        success: true,
        data: results
      });
    } catch (error) {
      console.error('Lookup operations failed:', error);
      throw error;
    }
  } catch (error) {
    console.error('Route handler error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to perform lookup'
    });
  }
});

export default router;
