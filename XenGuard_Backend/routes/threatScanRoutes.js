import express from 'express';
import { protect } from '../middleware/auth.js';
import threatScanController from '../controllers/threatScanController.js';

const router = express.Router();

// All routes require authentication
router.use(protect);

// Scan URL
router.post('/url', threatScanController.scanUrl);

// Scan File
router.post('/file', 
    threatScanController.getUploadMiddleware(),
    threatScanController.scanFile
);

// Scan IP
router.post('/ip', threatScanController.scanIp);

export default router;
