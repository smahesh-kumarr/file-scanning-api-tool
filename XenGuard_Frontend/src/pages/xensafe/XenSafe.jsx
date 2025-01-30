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
  LinearProgress,
  Card,
  CardContent,
  Divider,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Search as SearchIcon,
  Link as LinkIcon,
  Upload as UploadIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
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

  const getStatusIcon = (status) => {
    switch (status?.toLowerCase()) {
      case 'safe':
        return <CheckCircleIcon sx={{ color: 'success.main', fontSize: 40 }} />;
      case 'suspicious':
        return <WarningIcon sx={{ color: 'warning.main', fontSize: 40 }} />;
      case 'dangerous':
        return <ErrorIcon sx={{ color: 'error.main', fontSize: 40 }} />;
      default:
        return null;
    }
  };

  const renderTrustScore = (score) => {
    const normalizedScore = score || 0;
    const color = normalizedScore > 70 ? 'success.main' 
                : normalizedScore > 40 ? 'warning.main' 
                : 'error.main';

    return (
      <Box sx={{ position: 'relative', display: 'inline-flex', flexDirection: 'column', alignItems: 'center' }}>
        <Box sx={{ position: 'relative', display: 'inline-flex' }}>
          <CircularProgress
            variant="determinate"
            value={100}
            size={120}
            thickness={4}
            sx={{ color: 'grey.200' }}
          />
          <CircularProgress
            variant="determinate"
            value={normalizedScore}
            size={120}
            thickness={4}
            sx={{
              color: color,
              position: 'absolute',
              left: 0,
            }}
          />
          <Box
            sx={{
              top: 0,
              left: 0,
              bottom: 0,
              right: 0,
              position: 'absolute',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Typography variant="h4" component="div" color={color}>
              {normalizedScore}%
            </Typography>
          </Box>
        </Box>
        <Typography variant="h6" color="text.secondary" sx={{ mt: 1 }}>
          Trust Score
        </Typography>
      </Box>
    );
  };

  const renderScanDetails = (details) => {
    if (!details) return null;

    return (
      <Grid container spacing={3}>
        {details.virusTotal && (
          <Grid item xs={12} md={6}>
            <Card variant="outlined">
              <CardContent>
                <Box display="flex" alignItems="center" mb={2}>
                  <SecurityIcon sx={{ mr: 1, color: 'primary.main' }} />
                  <Typography variant="h6">VirusTotal Analysis</Typography>
                </Box>
                <Box sx={{ width: '100%', mb: 2 }}>
                  <Box display="flex" justifyContent="space-between" mb={1}>
                    <Typography variant="body2" color="text.secondary">
                      Security Vendors
                    </Typography>
                    <Typography variant="body2">
                      {details.virusTotal.maliciousCount} / {details.virusTotal.totalEngines}
                    </Typography>
                  </Box>
                  <LinearProgress 
                    variant="determinate" 
                    value={(details.virusTotal.maliciousCount / details.virusTotal.totalEngines) * 100}
                    sx={{
                      height: 8,
                      borderRadius: 4,
                      backgroundColor: 'success.light',
                      '& .MuiLinearProgress-bar': {
                        backgroundColor: 'error.main',
                      }
                    }}
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        )}

        {details.urlscan && (
          <Grid item xs={12} md={6}>
            <Card variant="outlined">
              <CardContent>
                <Box display="flex" alignItems="center" mb={2}>
                  <SearchIcon sx={{ mr: 1, color: 'primary.main' }} />
                  <Typography variant="h6">URL Analysis</Typography>
                </Box>
                {details.urlscan.verdict && (
                  <Box>
                    <Typography variant="body1" gutterBottom>
                      Verdict: {details.urlscan.verdict}
                    </Typography>
                    {details.urlscan.scanUrl && (
                      <Button
                        variant="outlined"
                        size="small"
                        startIcon={<InfoIcon />}
                        onClick={() => window.open(details.urlscan.scanUrl, '_blank')}
                      >
                        View Full Report
                      </Button>
                    )}
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>
    );
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
          <Paper variant="outlined" sx={{ p: 3 }}>
            <Box display="flex" alignItems="center" justifyContent="space-between" mb={4}>
              <Box display="flex" alignItems="center" gap={2}>
                {getStatusIcon(result.status)}
                <Typography variant="h5" sx={{ color: getStatusColor(result.status) }}>
                  Scan Results ({result.status.toUpperCase()})
                </Typography>
              </Box>
            </Box>

            <Grid container spacing={4}>
              <Grid item xs={12} md={4} display="flex" justifyContent="center">
                {renderTrustScore(result.score)}
              </Grid>
              <Grid item xs={12} md={8}>
                {renderScanDetails(result.details)}
              </Grid>
            </Grid>

            {result.threats.length > 0 && (
              <Box mt={4}>
                <Divider sx={{ mb: 2 }} />
                <Typography variant="h6" gutterBottom>
                  Detected Threats:
                </Typography>
                {result.threats.map((threat, index) => (
                  <Alert key={index} severity="warning" sx={{ mb: 1 }}>
                    {threat}
                  </Alert>
                ))}
              </Box>
            )}
          </Paper>
        )}
      </Paper>
    </Box>
  );
};

export default XenSafe;
