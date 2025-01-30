import multer from 'multer';
import path from 'path';
import threatScanService from '../services/threatScanService.js';
import { promises as fs } from 'fs';

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 32 * 1024 * 1024 // 32MB limit
    }
});

class ThreatScanController {
    getUploadMiddleware() {
        return upload.single('file');
    }

    async scanUrl(req, res) {
        try {
            const { url } = req.body;
            
            if (!url) {
                return res.status(400).json({
                    success: false,
                    error: 'URL is required'
                });
            }

            // Basic URL validation
            try {
                new URL(url);
            } catch (e) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid URL format'
                });
            }

            const result = await threatScanService.scanUrl(url);
            
            return res.json({
                success: true,
                data: result
            });
        } catch (error) {
            console.error('Error in scanUrl:', error);
            return res.status(error.status || 500).json({
                success: false,
                error: error.message || 'Failed to scan URL'
            });
        }
    }

    async scanFile(req, res) {
        try {
            if (!req.file) {
                return res.status(400).json({
                    success: false,
                    error: 'No file uploaded'
                });
            }

            const result = await threatScanService.scanFile(req.file.path);
            
            // Clean up the uploaded file
            fs.unlink(req.file.path, (err) => {
                if (err) console.error('Error deleting file:', err);
            });

            return res.json({
                success: true,
                data: result
            });
        } catch (error) {
            console.error('Error in scanFile:', error);
            
            // Clean up the uploaded file even if scan fails
            if (req.file) {
                fs.unlink(req.file.path, (err) => {
                    if (err) console.error('Error deleting file:', err);
                });
            }

            return res.status(error.status || 500).json({
                success: false,
                error: error.message || 'Failed to scan file'
            });
        }
    }

    async scanIp(req, res) {
        try {
            const { ip } = req.body;
            
            if (!ip) {
                return res.status(400).json({
                    success: false,
                    error: 'IP address is required'
                });
            }

            // Basic IP validation
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (!ipRegex.test(ip)) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid IP address format'
                });
            }

            const result = await threatScanService.scanIp(ip);
            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            console.error('IP scan error:', error);
            res.status(500).json({
                success: false,
                error: error.message || 'Failed to scan IP'
            });
        }
    }
}

export default new ThreatScanController();
