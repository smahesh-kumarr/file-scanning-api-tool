import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  IconButton,
  CircularProgress,
  Alert,
  Grid,
  Paper,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import {
  CloudUpload as CloudUploadIcon,
  Email as EmailIcon,
  Language as LanguageIcon,
  Security as SecurityIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  LocationOn as LocationOnIcon,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';

// Styled components
const VisuallyHiddenInput = styled('input')`
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  height: 1px;
  overflow: hidden;
  position: absolute;
  bottom: 0;
  left: 0;
  white-space: nowrap;
  width: 1px;
`;

const StyledCard = styled(Card)(({ theme }) => ({
  height: '100%',
  display: 'flex',
  flexDirection: 'column',
  transition: 'transform 0.3s ease-in-out, box-shadow 0.3s ease-in-out',
  '&:hover': {
    transform: 'translateY(-5px)',
    boxShadow: theme.shadows[8],
  },
}));

const SecurityTools = () => {
  const [fileToScan, setFileToScan] = useState(null);
  const [emailToCheck, setEmailToCheck] = useState('');
  const [ipToCheck, setIpToCheck] = useState('');
  const [loading, setLoading] = useState({
    file: false,
    email: false,
    ip: false,
  });
  const [results, setResults] = useState({
    file: null,
    email: null,
    ip: null,
  });

  const handleFileChange = (event) => {
    if (event.target.files.length > 0) {
      setFileToScan(event.target.files[0]);
      setResults(prev => ({ ...prev, file: null }));
    }
  };

  const handleFileScan = async () => {
    setLoading(prev => ({ ...prev, file: true }));
    // Simulated API call - replace with actual implementation
    try {
      await new Promise(resolve => setTimeout(resolve, 2000));
      setResults(prev => ({
        ...prev,
        file: {
          safe: true,
          threats: [],
          scanTime: new Date().toISOString(),
        },
      }));
    } catch (error) {
      console.error('File scan error:', error);
    } finally {
      setLoading(prev => ({ ...prev, file: false }));
    }
  };

  const handleEmailCheck = async () => {
    setLoading(prev => ({ ...prev, email: true }));
    try {
      await new Promise(resolve => setTimeout(resolve, 1500));
      setResults(prev => ({
        ...prev,
        email: {
          valid: true,
          reputation: 'Good',
          lastSeen: new Date().toISOString(),
        },
      }));
    } catch (error) {
      console.error('Email check error:', error);
    } finally {
      setLoading(prev => ({ ...prev, email: false }));
    }
  };

  const handleIpCheck = async () => {
    setLoading(prev => ({ ...prev, ip: true }));
    try {
      await new Promise(resolve => setTimeout(resolve, 1500));
      setResults(prev => ({
        ...prev,
        ip: {
          reputation: 'Clean',
          location: 'United States',
          lastReport: new Date().toISOString(),
        },
      }));
    } catch (error) {
      console.error('IP check error:', error);
    } finally {
      setLoading(prev => ({ ...prev, ip: false }));
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" sx={{ mb: 4 }}>
        Security Tools
      </Typography>

      <Grid container spacing={3}>
        {/* File Scanning */}
        <Grid item xs={12} md={4}>
          <StyledCard>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <SecurityIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">File Scanning</Typography>
              </Box>
              <Divider sx={{ mb: 2 }} />
              
              <Box sx={{ mb: 2 }}>
                <Button
                  component="label"
                  variant="outlined"
                  startIcon={<CloudUploadIcon />}
                  fullWidth
                  sx={{ mb: 2 }}
                >
                  Upload File
                  <VisuallyHiddenInput
                    type="file"
                    onChange={handleFileChange}
                  />
                </Button>
                {fileToScan && (
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    Selected: {fileToScan.name}
                  </Typography>
                )}
                <Button
                  variant="contained"
                  onClick={handleFileScan}
                  disabled={!fileToScan || loading.file}
                  fullWidth
                >
                  {loading.file ? <CircularProgress size={24} /> : 'Scan File'}
                </Button>
              </Box>

              {results.file && (
                <Alert
                  severity={results.file.safe ? 'success' : 'error'}
                  sx={{ mt: 2 }}
                >
                  File scan completed: {results.file.safe ? 'No threats detected' : 'Threats found'}
                </Alert>
              )}
            </CardContent>
          </StyledCard>
        </Grid>

        {/* Email Validation */}
        <Grid item xs={12} md={4}>
          <StyledCard>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <EmailIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">Email Validation</Typography>
              </Box>
              <Divider sx={{ mb: 2 }} />

              <TextField
                fullWidth
                label="Email Address"
                variant="outlined"
                value={emailToCheck}
                onChange={(e) => setEmailToCheck(e.target.value)}
                sx={{ mb: 2 }}
              />
              <Button
                variant="contained"
                onClick={handleEmailCheck}
                disabled={!emailToCheck || loading.email}
                fullWidth
              >
                {loading.email ? <CircularProgress size={24} /> : 'Check Email'}
              </Button>

              {results.email && (
                <Box sx={{ mt: 2 }}>
                  <Alert
                    severity={results.email.valid ? 'success' : 'error'}
                    sx={{ mb: 2 }}
                  >
                    Email is {results.email.valid ? 'valid' : 'invalid'}
                  </Alert>
                  <List dense>
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" />
                      </ListItemIcon>
                      <ListItemText
                        primary="Reputation"
                        secondary={results.email.reputation}
                      />
                    </ListItem>
                  </List>
                </Box>
              )}
            </CardContent>
          </StyledCard>
        </Grid>

        {/* IP Reputation */}
        <Grid item xs={12} md={4}>
          <StyledCard>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <LanguageIcon sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">IP Reputation</Typography>
              </Box>
              <Divider sx={{ mb: 2 }} />

              <TextField
                fullWidth
                label="IP Address"
                variant="outlined"
                value={ipToCheck}
                onChange={(e) => setIpToCheck(e.target.value)}
                sx={{ mb: 2 }}
              />
              <Button
                variant="contained"
                onClick={handleIpCheck}
                disabled={!ipToCheck || loading.ip}
                fullWidth
              >
                {loading.ip ? <CircularProgress size={24} /> : 'Check IP'}
              </Button>

              {results.ip && (
                <Box sx={{ mt: 2 }}>
                  <Alert
                    severity={results.ip.reputation === 'Clean' ? 'success' : 'warning'}
                    sx={{ mb: 2 }}
                  >
                    IP Reputation: {results.ip.reputation}
                  </Alert>
                  <List dense>
                    <ListItem>
                      <ListItemIcon>
                        <LocationOnIcon />
                      </ListItemIcon>
                      <ListItemText
                        primary="Location"
                        secondary={results.ip.location}
                      />
                    </ListItem>
                  </List>
                </Box>
              )}
            </CardContent>
          </StyledCard>
        </Grid>
      </Grid>
    </Box>
  );
};

export default SecurityTools; 