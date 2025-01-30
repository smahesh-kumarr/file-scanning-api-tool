import React, { useState, useRef } from 'react';
import { useSelector } from 'react-redux';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  CircularProgress,
  Alert,
  Grid,
  IconButton,
  Tooltip,
  Input,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Search as SearchIcon,
  Link as LinkIcon,
  Upload as UploadIcon,
  Info as InfoIcon,
} from '@mui/icons-material';

const XenSafe = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);
  const { token } = useSelector((state) => state.auth);

  const handleScan = async () => {
    if (!url) {
      setError('Please enter a URL, IP address, or upload a file');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
      let response;
      // Check if input is an IP address
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      
      if (ipRegex.test(url)) {
        response = await fetch(`${baseUrl}/api/scan/ip`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ ip: url }),
        });
      } else {
        response = await fetch(`${baseUrl}/api/scan/url`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ url }),
        });
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: `Server error: ${response.status}` }));
        throw new Error(errorData.error || `Server error: ${response.status}`);
      }

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'Scan failed');
      }

      setResult(data.data);
    } catch (err) {
      console.error('Scan error:', err);
      setError(err.message || 'Failed to scan. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(`${baseUrl}/api/scan/file`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: `Server error: ${response.status}` }));
        throw new Error(errorData.error || `Server error: ${response.status}`);
      }

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'Scan failed');
      }

      setResult(data.data);
    } catch (err) {
      console.error('File scan error:', err);
      setError(err.message || 'Failed to scan file. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileButtonClick = () => {
    fileInputRef.current.click();
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'safe':
        return 'success.main';
      case 'suspicious':
        return 'warning.main';
      case 'dangerous':
        return 'error.main';
      default:
        return 'text.primary';
    }
  };

  return (
    <Box p={3}>
      <Paper elevation={3} sx={{ p: 3 }}>
        <Box display="flex" alignItems="center" mb={3}>
          <SecurityIcon sx={{ mr: 2, fontSize: 40 }} />
          <Typography variant="h4" component="h1">
            Personal Threat Scanner
          </Typography>
        </Box>

        <Typography variant="body1" mb={3} color="text.secondary">
          Scan websites, files, or IP addresses for potential security threats. We use multiple security databases to ensure your safety online.
        </Typography>

        <Box mb={3}>
          <Box display="flex" gap={1}>
            <TextField
              fullWidth
              variant="outlined"
              placeholder="Enter URL, IP address, or upload a file"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              InputProps={{
                endAdornment: (
                  <Box display="flex" gap={1}>
                    <IconButton onClick={handleFileButtonClick}>
                      <UploadIcon />
                    </IconButton>
                    <IconButton onClick={() => navigator.clipboard.readText().then(text => setUrl(text))}>
                      <LinkIcon />
                    </IconButton>
                  </Box>
                ),
              }}
            />
            <Button
              variant="contained"
              color="primary"
              onClick={handleScan}
              disabled={loading}
              startIcon={loading ? <CircularProgress size={20} /> : <SearchIcon />}
              sx={{ minWidth: 120 }}
            >
              Scan Now
            </Button>
          </Box>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            style={{ display: 'none' }}
          />
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {result && (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <Box display="flex" alignItems="center" gap={1}>
                  <Typography variant="h6" component="h2">
                    Scan Results
                  </Typography>
                  <Typography
                    variant="subtitle1"
                    sx={{ color: getStatusColor(result.status) }}
                  >
                    ({result.status.toUpperCase()})
                  </Typography>
                </Box>
              </Grid>

              <Grid item xs={12}>
                <Typography variant="body1" color="text.secondary">
                  Trust Score: {result.score}%
                </Typography>
              </Grid>

              {result.threats.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                    Detected Threats:
                  </Typography>
                  {result.threats.map((threat, index) => (
                    <Typography variant="body2" component="div" sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                      • {threat}
                    </Typography>
                  ))}
                </Grid>
              )}

              {result.details && (
                <Grid item xs={12}>
                  <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                    Scan Details:
                  </Typography>
                  {result.details.virusTotal && (
                    <Typography variant="body2">
                      • VirusTotal: {result.details.virusTotal.maliciousCount} out of{' '}
                      {result.details.virusTotal.totalEngines} security vendors flagged this
                    </Typography>
                  )}
                  {result.details.phishTank && result.details.phishTank.inDatabase && (
                    <Typography variant="body2">
                      • PhishTank: {result.details.phishTank.verified ? 'Verified' : 'Suspected'} phishing site
                      {result.details.phishTank.detailsUrl && (
                        <Tooltip title="View details on PhishTank">
                          <IconButton
                            size="small"
                            onClick={() => window.open(result.details.phishTank.detailsUrl, '_blank')}
                          >
                            <InfoIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </Typography>
                  )}
                </Grid>
              )}
            </Grid>
          </Paper>
        )}
      </Paper>
    </Box>
  );
};

export default XenSafe;
