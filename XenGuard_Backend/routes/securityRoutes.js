import express from 'express';
import axios from 'axios';
import dotenv from 'dotenv';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import FormData from 'form-data';

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

const upload = multer({ 
  storage,
  limits: {
    fileSize: 32 * 1024 * 1024 // 32MB limit
  },
  fileFilter: (req, file, cb) => {
    // Accept only specific file types
    const allowedTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'text/plain',
      'application/octet-stream' // For executables
    ];

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Please upload a valid file.'));
    }
  }
});

// File Scan endpoint
router.post('/scan-file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        error: 'No file uploaded',
        details: 'Please select a file to scan'
      });
    }

    const filePath = req.file.path;
    const fileBuffer = fs.readFileSync(filePath);

    // Create form data for VirusTotal
    const formData = new FormData();
    formData.append('file', fileBuffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype
    });

    // Upload file to VirusTotal
    const uploadResponse = await axios.post('https://www.virustotal.com/api/v3/files', 
      formData,
      {
        headers: {
          'x-apikey': process.env.VIRUS_SCAN_API_KEY,
          'Accept': 'application/json',
          ...formData.getHeaders()
        }
      }
    );

    // Get the analysis ID
    const analysisId = uploadResponse.data.data.id;

    // Wait for analysis to complete (VirusTotal recommends waiting 15-30 seconds)
    await new Promise(resolve => setTimeout(resolve, 15000));

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
    
    // Calculate threat level based on multiple factors
    const maliciousCount = analysis.stats.malicious || 0;
    const suspiciousCount = analysis.stats.suspicious || 0;
    const totalEngines = Object.keys(analysis.results || {}).length;
    
    // Determine threat level
    let threatLevel = 'safe';
    if (maliciousCount > 0) {
      const maliciousPercentage = (maliciousCount / totalEngines) * 100;
      if (maliciousPercentage > 50) {
        threatLevel = 'high';
      } else if (maliciousPercentage > 20) {
        threatLevel = 'medium';
      } else {
        threatLevel = 'low';
      }
    } else if (suspiciousCount > 0) {
      threatLevel = 'suspicious';
    }

    // Extract detailed threat information
    const threats = Object.entries(analysis.results || {})
      .filter(([_, result]) => result.category === 'malicious' || result.category === 'suspicious')
      .map(([engine, result]) => ({
        engine,
        category: result.category,
        result: result.result,
        method: result.method,
        severity: result.category === 'malicious' ? 'high' : 'medium'
      }));

    const result = {
      status: threatLevel === 'safe' ? 'safe' : 'unsafe',
      threatLevel,
      details: {
        isSafe: threatLevel === 'safe',
        threatScore: maliciousCount,
        suspiciousScore: suspiciousCount,
        totalEngines,
        lastAnalysisDate: new Date().toISOString(),
        reputation: threatLevel === 'safe' ? 'High' : 'Low',
        securityChecks: {
          malware: maliciousCount > 0 ? `${maliciousCount} detected` : 'Clean',
          suspicious: suspiciousCount > 0 ? `${suspiciousCount} detected` : 'Clean',
          undetected: analysis.stats.undetected || 0,
          harmless: analysis.stats.harmless || 0
        },
        fileInfo: {
          name: req.file.originalname,
          size: req.file.size,
          type: req.file.mimetype
        },
        threats: threats,
        engineResults: Object.entries(analysis.results || {}).map(([engine, result]) => ({
          engine,
          category: result.category,
          result: result.result,
          method: result.method
        }))
      }
    };

    res.json(result);
  } catch (error) {
    console.error('File Scan Error:', error.response?.data || error.message);
    
    // Clean up file if it exists
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (e) {
        console.error('Error cleaning up file:', e);
      }
    }

    // Handle specific errors
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ 
        error: 'File too large',
        details: 'File size exceeds 32MB limit'
      });
    }

    if (error.message === 'Invalid file type. Please upload a valid file.') {
      return res.status(400).json({ 
        error: 'Invalid file type',
        details: 'Please upload a valid file type (PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT)'
      });
    }

    // Handle VirusTotal API errors
    if (error.response?.status === 401) {
      return res.status(500).json({ 
        error: 'VirusTotal API Error',
        details: 'Invalid API key. Please check your VirusTotal API configuration.'
      });
    }

    if (error.response?.status === 429) {
      return res.status(429).json({ 
        error: 'Rate Limit Exceeded',
        details: 'Too many requests to VirusTotal API. Please try again later.'
      });
    }

    res.status(500).json({ 
      error: 'Failed to scan file',
      details: error.response?.data?.error || error.message
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

// Hash Scan endpoint
router.post('/scan-hash', async (req, res) => {
  try {
    const { hash } = req.body;

    if (!hash) {
      return res.status(400).json({ 
        error: 'Hash is required',
        details: 'Please provide a hash to scan'
      });
    }

    // Validate hash format (MD5, SHA-1, or SHA-256)
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    if (!hashRegex.test(hash)) {
      return res.status(400).json({ 
        error: 'Invalid hash format',
        details: 'Please provide a valid MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars) hash'
      });
    }

    // Get hash report from VirusTotal
    const response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: {
        'x-apikey': process.env.VIRUS_SCAN_API_KEY,
        'Accept': 'application/json'
      }
    });

    // Extract relevant data from VirusTotal response
    const data = response.data.data;
    const attributes = data.attributes;
    
    // Calculate threat level based on multiple factors
    const maliciousCount = attributes.last_analysis_stats.malicious || 0;
    const suspiciousCount = attributes.last_analysis_stats.suspicious || 0;
    const totalEngines = Object.keys(attributes.last_analysis_results || {}).length;
    
    // Determine threat level
    let threatLevel = 'safe';
    if (maliciousCount > 0) {
      const maliciousPercentage = (maliciousCount / totalEngines) * 100;
      if (maliciousPercentage > 50) {
        threatLevel = 'high';
      } else if (maliciousPercentage > 20) {
        threatLevel = 'medium';
      } else {
        threatLevel = 'low';
      }
    } else if (suspiciousCount > 0) {
      threatLevel = 'suspicious';
    }

    // Extract detailed threat information
    const threats = Object.entries(attributes.last_analysis_results || {})
      .filter(([_, result]) => result.category === 'malicious' || result.category === 'suspicious')
      .map(([engine, result]) => ({
        engine,
        category: result.category,
        result: result.result,
        method: result.method,
        severity: result.category === 'malicious' ? 'high' : 'medium'
      }));

    const result = {
      status: threatLevel === 'safe' ? 'safe' : 'unsafe',
      threatLevel,
      details: {
        isSafe: threatLevel === 'safe',
        threatScore: maliciousCount,
        suspiciousScore: suspiciousCount,
        totalEngines,
        lastAnalysisDate: attributes.last_analysis_date,
        reputation: threatLevel === 'safe' ? 'High' : 'Low',
        securityChecks: {
          malware: maliciousCount > 0 ? `${maliciousCount} detected` : 'Clean',
          suspicious: suspiciousCount > 0 ? `${suspiciousCount} detected` : 'Clean',
          undetected: attributes.last_analysis_stats.undetected || 0,
          harmless: attributes.last_analysis_stats.harmless || 0
        },
        fileInfo: {
          name: attributes.meaningful_name || 'Unknown',
          size: attributes.size || 0,
          type: attributes.type_description || 'Unknown',
          md5: attributes.md5,
          sha1: attributes.sha1,
          sha256: attributes.sha256
        },
        threats: threats,
        engineResults: Object.entries(attributes.last_analysis_results || {}).map(([engine, result]) => ({
          engine,
          category: result.category,
          result: result.result,
          method: result.method
        })),
        additionalInfo: {
          firstSeen: attributes.first_seen_itw_date,
          lastSeen: attributes.last_seen_itw_date,
          tags: attributes.tags || [],
          names: attributes.names || []
        }
      }
    };

    res.json(result);
  } catch (error) {
    console.error('Hash Scan Error:', error.response?.data || error.message);

    // Handle specific VirusTotal API errors
    if (error.response?.status === 404) {
      return res.status(404).json({ 
        error: 'Hash not found',
        details: 'The provided hash was not found in VirusTotal database'
      });
    }

    if (error.response?.status === 401) {
      return res.status(500).json({ 
        error: 'VirusTotal API Error',
        details: 'Invalid API key. Please check your VirusTotal API configuration.'
      });
    }

    if (error.response?.status === 429) {
      return res.status(429).json({ 
        error: 'Rate Limit Exceeded',
        details: 'Too many requests to VirusTotal API. Please try again later.'
      });
    }

    res.status(500).json({ 
      error: 'Failed to scan hash',
      details: error.response?.data?.error || error.message
    });
  }
});

// Phishing Scan endpoint
router.post('/scan-phishing', async (req, res) => {
  try {
    const { content, url } = req.body;

    if (!content && !url) {
      return res.status(400).json({ 
        error: 'Content or URL required',
        details: 'Please provide either email content or URL to analyze'
      });
    }

    let results = {
      status: 'safe',
      threatLevel: 'low',
      details: {
        isSafe: true,
        threatScore: 0,
        totalChecks: 0,
        securityChecks: {
          phishing: 'Clean',
          suspicious: 'Clean',
          malware: 'Clean'
        },
        analysis: []
      }
    };

    // If URL is provided, check against PhishTank
    if (url) {
      try {
        const phishTankResponse = await axios.get(`https://checkurl.phishtank.com/checkurl/`, {
          params: {
            url: url,
            format: 'json',
            app_key: process.env.PHISHTANK_API_KEY
          }
        });

        if (phishTankResponse.data.results.in_database) {
          results.status = 'unsafe';
          results.threatLevel = 'high';
          results.details.isSafe = false;
          results.details.threatScore += 100;
          results.details.securityChecks.phishing = 'Detected';
          results.details.analysis.push({
            source: 'PhishTank',
            result: 'Known phishing URL',
            confidence: 'High',
            details: phishTankResponse.data.results
          });
        }
      } catch (error) {
        console.error('PhishTank API Error:', error);
      }
    }

    // Analyze content for suspicious patterns
    if (content) {
      const suspiciousPatterns = [
        { pattern: /password/i, weight: 0.3 },
        { pattern: /login/i, weight: 0.2 },
        { pattern: /account/i, weight: 0.2 },
        { pattern: /verify/i, weight: 0.2 },
        { pattern: /urgent/i, weight: 0.3 },
        { pattern: /immediate/i, weight: 0.3 },
        { pattern: /click here/i, weight: 0.4 },
        { pattern: /http[s]?:\/\/[^\s]+/i, weight: 0.5 },
        { pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i, weight: 0.3 }
      ];

      let contentScore = 0;
      const foundPatterns = [];

      suspiciousPatterns.forEach(pattern => {
        if (pattern.pattern.test(content)) {
          contentScore += pattern.weight;
          foundPatterns.push({
            pattern: pattern.pattern.toString(),
            weight: pattern.weight
          });
        }
      });

      if (contentScore > 0.5) {
        results.status = 'suspicious';
        results.threatLevel = 'medium';
        results.details.threatScore += Math.round(contentScore * 100);
        results.details.securityChecks.suspicious = 'Detected';
        results.details.analysis.push({
          source: 'Content Analysis',
          result: 'Suspicious patterns detected',
          confidence: 'Medium',
          details: {
            score: contentScore,
            patterns: foundPatterns
          }
        });
      }
    }

    // If URL is provided, also check with VirusTotal
    if (url) {
      try {
        const virusTotalResponse = await axios.get(`https://www.virustotal.com/api/v3/urls/${Buffer.from(url).toString('base64').replace(/=/g, '')}`, {
          headers: {
            'x-apikey': process.env.VIRUS_SCAN_API_KEY
          }
        });

        const stats = virusTotalResponse.data.data.attributes.last_analysis_stats;
        if (stats.malicious > 0) {
          results.status = 'unsafe';
          results.threatLevel = 'high';
          results.details.isSafe = false;
          results.details.threatScore += stats.malicious * 20;
          results.details.securityChecks.malware = `${stats.malicious} detections`;
          results.details.analysis.push({
            source: 'VirusTotal',
            result: 'Malicious URL detected',
            confidence: 'High',
            details: {
              malicious: stats.malicious,
              suspicious: stats.suspicious,
              total: stats.malicious + stats.suspicious + stats.harmless + stats.undetected
            }
          });
        }
      } catch (error) {
        console.error('VirusTotal API Error:', error);
      }
    }

    // Calculate final threat level
    if (results.details.threatScore > 100) {
      results.threatLevel = 'high';
    } else if (results.details.threatScore > 50) {
      results.threatLevel = 'medium';
    }

    results.details.totalChecks = results.details.analysis.length;

    res.json(results);
  } catch (error) {
    console.error('Phishing Scan Error:', error);
    res.status(500).json({ 
      error: 'Failed to analyze content',
      details: error.message
    });
  }
});

export default router; 