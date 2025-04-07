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

    // Validate URL format and structure
    try {
      const urlObj = new URL(url);
      
      // Check if URL has a valid protocol
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        return res.status(400).json({ 
          error: 'Invalid URL protocol',
          details: 'URL must start with http:// or https://'
        });
      }

      // Check if URL has a valid domain
      if (!urlObj.hostname || urlObj.hostname.length < 3) {
        return res.status(400).json({ 
          error: 'Invalid domain',
          details: 'Please enter a valid domain name'
        });
      }

      // Check if URL is accessible
      try {
        await axios.head(url, { timeout: 5000 });
      } catch (error) {
        if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
          return res.status(400).json({ 
            error: 'URL not accessible',
            details: 'The URL you entered is not accessible or does not exist. Please check the URL and try again.'
          });
        }
      }

    } catch (e) {
      return res.status(400).json({ 
        error: 'Invalid URL format',
        details: 'Please enter a valid URL (e.g., https://example.com)'
      });
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
    
    // Handle specific VirusTotal API errors
    if (error.response?.status === 404) {
      return res.status(400).json({ 
        error: 'URL not found',
        details: 'The URL you entered could not be found. Please check the URL and try again.'
      });
    }
    
    if (error.response?.status === 429) {
      return res.status(429).json({ 
        error: 'Rate limit exceeded',
        details: 'Too many requests. Please try again later.'
      });
    }

    res.status(500).json({ 
      error: 'Failed to scan URL',
      details: error.response?.data?.error || error.message
    });
  }
});

export default router; 