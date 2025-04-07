import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  CircularProgress,
  Alert,
  IconButton,
  styled,
  Grid,
  Chip,
} from '@mui/material';
import { Link as LinkIcon, ContentCopy, CheckCircle, Warning, Cancel } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const StyledCard = styled(Card)(({ theme }) => ({
  background: 'linear-gradient(135deg, #6B46C1 0%, #9F7AEA 100%)',
  borderRadius: '16px',
  maxWidth: '600px',
  margin: '20px auto',
  padding: '20px',
  color: '#fff',
}));

const ResultCard = styled(Card)(({ theme, status }) => ({
  background: status === 'safe' 
    ? 'linear-gradient(135deg, #1B5E20 0%, #2E7D32 100%)'
    : status === 'warning'
    ? 'linear-gradient(135deg, #E65100 0%, #F57C00 100%)'
    : 'linear-gradient(135deg, #B71C1C 0%, #D32F2F 100%)',
  borderRadius: '12px',
  padding: '20px',
  marginTop: '20px',
  color: '#fff',
}));

const URLScan = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const navigate = useNavigate();

  const handleScan = async () => {
    if (!url) {
      setError('Please enter a URL to scan');
      return;
    }

    // Validate URL format
    try {
      new URL(url);
    } catch (e) {
      setError('Please enter a valid URL (e.g., https://example.com)');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      setResult(null);
      
      const response = await axios.post('http://localhost:5000/api/security/scan-url', 
        { url },
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );
      
      if (response.data && response.data.details) {
        setResult(response.data);
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (err) {
      console.error('Scan error:', err);
      setError(
        err.response?.data?.error || 
        err.response?.data?.details || 
        'Failed to scan URL. Please try again.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Button
        startIcon={<LinkIcon />}
        onClick={() => navigate('/dashboard')}
        sx={{ m: 2, color: 'text.secondary' }}
      >
        Back to Dashboard
      </Button>

      <StyledCard>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
            <LinkIcon sx={{ fontSize: 40, mr: 2 }} />
            <Typography variant="h4">
              URL Scanner
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 4, opacity: 0.9 }}>
            Check URLs for security threats, malware, and phishing attempts
          </Typography>

          <Box sx={{ mb: 3 }}>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              URL to Scan
            </Typography>
            <TextField
              fullWidth
              variant="outlined"
              placeholder="Enter URL (e.g., https://example.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              InputProps={{
                endAdornment: (
                  <IconButton
                    size="small"
                    onClick={() => navigator.clipboard.writeText(url)}
                    sx={{ color: 'rgba(255, 255, 255, 0.7)' }}
                  >
                    <ContentCopy />
                  </IconButton>
                ),
              }}
              sx={{
                '& .MuiOutlinedInput-root': {
                  backgroundColor: 'rgba(255, 255, 255, 0.1)',
                  borderRadius: '8px',
                  color: '#fff',
                  '& fieldset': {
                    borderColor: 'rgba(255, 255, 255, 0.3)',
                  },
                  '&:hover fieldset': {
                    borderColor: 'rgba(255, 255, 255, 0.5)',
                  },
                  '&.Mui-focused fieldset': {
                    borderColor: '#fff',
                  },
                },
                '& .MuiOutlinedInput-input::placeholder': {
                  color: 'rgba(255, 255, 255, 0.7)',
                },
              }}
            />
          </Box>

          {error && (
            <Alert 
              severity="error" 
              sx={{ 
                mb: 2,
                backgroundColor: 'rgba(211, 47, 47, 0.1)',
                color: '#fff',
                '& .MuiAlert-icon': {
                  color: '#fff',
                },
              }}
            >
              {error}
            </Alert>
          )}

          <Button
            fullWidth
            variant="contained"
            onClick={handleScan}
            disabled={loading}
            startIcon={loading ? <CircularProgress size={20} /> : <LinkIcon />}
            sx={{
              height: '48px',
              backgroundColor: 'rgba(255, 255, 255, 0.2)',
              color: '#fff',
              '&:hover': {
                backgroundColor: 'rgba(255, 255, 255, 0.3)',
              },
              '&.Mui-disabled': {
                backgroundColor: 'rgba(255, 255, 255, 0.1)',
                color: 'rgba(255, 255, 255, 0.5)',
              },
            }}
          >
            {loading ? 'Scanning...' : 'Scan URL'}
          </Button>

          {result && (
            <ResultCard status={result.status}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                {result.status === 'safe' ? (
                  <CheckCircle sx={{ fontSize: 40, mr: 2 }} />
                ) : result.status === 'warning' ? (
                  <Warning sx={{ fontSize: 40, mr: 2 }} />
                ) : (
                  <Cancel sx={{ fontSize: 40, mr: 2 }} />
                )}
                <Typography variant="h5">
                  {result.status === 'safe' ? 'URL is Safe' : 'URL May Be Unsafe'}
                </Typography>
              </Box>

              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom>
                    Security Checks
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {Object.entries(result.details.securityChecks).map(([key, value]) => (
                      <Chip
                        key={key}
                        label={`${key}: ${value}`}
                        color={value === 'Clean' ? 'success' : 'error'}
                        sx={{ m: 0.5 }}
                      />
                    ))}
                  </Box>
                </Grid>

                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom>
                    Additional Information
                  </Typography>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    <Typography variant="body2">
                      Threat Score: {result.details.threatScore}/100
                    </Typography>
                    <Typography variant="body2">
                      Reputation: {result.details.reputation}
                    </Typography>
                    <Typography variant="body2">
                      Last Analysis: {new Date(result.details.lastAnalysisDate * 1000).toLocaleDateString()}
                    </Typography>
                  </Box>
                </Grid>
              </Grid>

              {result.details.categories.length > 0 && (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="subtitle1" gutterBottom>
                    Categories
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {result.details.categories.map((category) => (
                      <Chip
                        key={category}
                        label={category}
                        sx={{ m: 0.5 }}
                      />
                    ))}
                  </Box>
                </Box>
              )}
            </ResultCard>
          )}
        </CardContent>
      </StyledCard>
    </Box>
  );
};

export default URLScan; 