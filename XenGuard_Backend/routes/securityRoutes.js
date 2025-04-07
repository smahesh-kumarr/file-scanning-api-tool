import express from 'express';
import axios from 'axios';
import dotenv from 'dotenv';
import multer from 'multer';
import fs from 'fs';
import path from 'path';

dotenv.config();

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

// File Scan endpoint
router.post('/scan-file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = req.file.path;
    const fileBuffer = fs.readFileSync(filePath);

    // Get file size in bytes
    const fileSize = fileBuffer.length;

    // Check if file is too large (VirusTotal has a 32MB limit)
    if (fileSize > 32 * 1024 * 1024) {
      fs.unlinkSync(filePath); // Clean up the uploaded file
      return res.status(400).json({ error: 'File size exceeds 32MB limit' });
    }

    // Upload file to VirusTotal
    const formData = new FormData();
    formData.append('file', fileBuffer, req.file.originalname);

    const uploadResponse = await axios.post('https://www.virustotal.com/api/v3/files', 
      formData,
      {
        headers: {
          'x-apikey': process.env.VIRUS_SCAN_API_KEY,
          'Accept': 'application/json'
        }
      }
    );

    // Get the analysis ID
    const analysisId = uploadResponse.data.data.id;

    // Wait for analysis to complete
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Get the analysis results
    const response = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: {
        'x-apikey': process.env.VIRUS_SCAN_API_KEY,
        'Accept': 'application/json'
      }
    });

    // Clean up the uploaded file
    fs.unlinkSync(filePath);

    // Extract relevant data from VirusTotal response
    const analysis = response.data.data.attributes;
    
    const result = {
      status: analysis.stats.malicious > 0 ? 'unsafe' : 'safe',
      details: {
        isSafe: analysis.stats.malicious === 0,
        threatScore: analysis.stats.malicious,
        lastAnalysisDate: new Date().toISOString(),
        reputation: analysis.stats.malicious > 0 ? 'Low' : 'High',
        securityChecks: {
          malware: analysis.stats.malicious > 0 ? 'Detected' : 'Clean',
          suspicious: analysis.stats.suspicious > 0 ? 'Detected' : 'Clean',
          undetected: analysis.stats.undetected
        },
        fileInfo: {
          name: req.file.originalname,
          size: fileSize,
          type: req.file.mimetype
        },
        engines: analysis.results
      }
    };

    res.json(result);
  } catch (error) {
    console.error('File Scan Error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to scan file',
      details: error.response?.data || error.message
    });
  }
});

// URL Scan endpoint
router.post('/scan-url', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch (e) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // First, submit the URL for analysis
    const submitResponse = await axios.post('https://www.virustotal.com/api/v3/urls', 
      { url },
      {
        headers: {
          'x-apikey': process.env.VIRUS_SCAN_API_KEY,
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    // Get the analysis ID
    const analysisId = submitResponse.data.data.id;

    // Wait for analysis to complete
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Get the analysis results
    const response = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: {
        'x-apikey': process.env.VIRUS_SCAN_API_KEY,
        'Accept': 'application/json'
      }
    });

    // Extract relevant data from VirusTotal response
    const analysis = response.data.data.attributes;
    
    const result = {
      status: analysis.stats.malicious > 0 ? 'unsafe' : 'safe',
      details: {
        isSafe: analysis.stats.malicious === 0,
        threatScore: analysis.stats.malicious,
        lastAnalysisDate: new Date().toISOString(),
        reputation: analysis.stats.malicious > 0 ? 'Low' : 'High',
        securityChecks: {
          malware: analysis.stats.malicious > 0 ? 'Detected' : 'Clean',
          phishing: analysis.stats.phishing > 0 ? 'Detected' : 'Clean',
          suspicious: analysis.stats.suspicious > 0 ? 'Detected' : 'Clean',
          certificates: 'Not Available'
        },
        categories: analysis.categories || [],
        engines: analysis.results
      }
    };

    res.json(result);
  } catch (error) {
    console.error('URL Scan Error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to scan URL',
      details: error.response?.data || error.message
    });
  }
});

export default router; 