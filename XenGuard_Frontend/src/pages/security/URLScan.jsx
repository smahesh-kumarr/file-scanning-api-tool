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
} from '@mui/material';
import { Link as LinkIcon, ContentCopy } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

const StyledCard = styled(Card)(({ theme }) => ({
  background: 'linear-gradient(135deg, #6B46C1 0%, #9F7AEA 100%)',
  borderRadius: '16px',
  maxWidth: '600px',
  margin: '20px auto',
  padding: '20px',
  color: '#fff',
}));

const URLScan = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const handleScan = async () => {
    if (!url) {
      setError('Please enter a URL to scan');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      // TODO: Replace with actual API call
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Handle successful scan
      setLoading(false);
    } catch (err) {
      setError('Failed to scan URL. Please try again.');
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
        </CardContent>
      </StyledCard>
    </Box>
  );
};

export default URLScan; 