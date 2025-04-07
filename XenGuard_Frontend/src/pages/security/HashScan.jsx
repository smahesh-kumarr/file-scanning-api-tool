import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  TextField,
  Button,
  Card,
  CardContent,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  CircularProgress,
  Paper,
  Chip,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  IconButton,
} from '@mui/material';
import {
  Fingerprint as HashIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Security as SecurityIcon,
  ArrowBack as ArrowBackIcon,
  ContentCopy as CopyIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { styled } from '@mui/material/styles';

const StyledCard = styled(Card)(({ theme }) => ({
  background: 'linear-gradient(135deg, #805AD5 0%, #6B46C1 100%)',
  color: 'white',
  marginBottom: theme.spacing(3),
}));

const ResultCard = styled(Paper)(({ theme, severity }) => ({
  padding: theme.spacing(3),
  marginTop: theme.spacing(3),
  border: '1px solid',
  borderColor: severity === 'error' ? theme.palette.error.main : theme.palette.success.main,
  borderRadius: theme.shape.borderRadius,
  backgroundColor: severity === 'error' 
    ? 'rgba(244, 67, 54, 0.05)' 
    : 'rgba(76, 175, 80, 0.05)',
}));

const HashScan = () => {
  const navigate = useNavigate();
  const [hashType, setHashType] = useState('md5');
  const [hashValue, setHashValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleHashTypeChange = (event) => {
    setHashType(event.target.value);
    setResult(null);
    setError(null);
  };

  const handleHashInput = (event) => {
    const value = event.target.value;
    setHashValue(value);
    setResult(null);
    setError(null);
  };

  const validateHash = (hash, type) => {
    const patterns = {
      md5: /^[a-f0-9]{32}$/i,
      sha1: /^[a-f0-9]{40}$/i,
      sha256: /^[a-f0-9]{64}$/i,
    };

    if (!patterns[type].test(hash)) {
      setError(`Please enter a valid ${type.toUpperCase()} hash`);
      return false;
    }
    return true;
  };

  const handleScan = async () => {
    if (!hashValue.trim()) {
      setError('Please enter a hash value');
      return;
    }

    if (!validateHash(hashValue, hashType)) {
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Simulated API call - replace with actual VirusTotal API implementation
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Simulated response - replace with actual VirusTotal API response
      const mockResponse = {
        isMalicious: true,
        confidence: 0.95,
        detectionCount: 45,
        totalScanners: 70,
        firstSeen: '2023-01-15T08:30:00Z',
        lastSeen: '2023-04-05T14:22:00Z',
        detections: [
          {
            engine: 'Kaspersky',
            result: 'Trojan.Win32.Generic',
            severity: 'high',
          },
          {
            engine: 'Microsoft',
            result: 'Trojan:Win32/Wacatac.B!ml',
            severity: 'high',
          },
          {
            engine: 'ESET-NOD32',
            result: 'Win32/Agent.ABX',
            severity: 'medium',
          },
        ],
        fileInfo: {
          type: 'PE32 executable (GUI) Intel 80386, for MS Windows',
          size: '2.5 MB',
          tags: ['executable', 'windows', 'malicious'],
        },
        recommendations: [
          'Do not download or execute this file',
          'Delete the file if already downloaded',
          'Run a full system scan',
          'Update your antivirus definitions',
        ],
      };

      setResult(mockResponse);
    } catch (err) {
      setError('Failed to analyze hash. Please try again.');
      console.error('Hash scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high':
        return 'error.main';
      case 'medium':
        return 'warning.main';
      case 'low':
        return 'info.main';
      default:
        return 'text.primary';
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(hashValue);
  };

  return (
    <Container maxWidth="md">
      <Box sx={{ pt: 4, pb: 6 }}>
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/dashboard')}
          sx={{ mb: 4 }}
        >
          Back to Dashboard
        </Button>

        <StyledCard>
          <CardContent sx={{ py: 4 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <SecurityIcon sx={{ fontSize: 40, mr: 2 }} />
              <Typography variant="h4" component="h1">
                Hash Scanner
              </Typography>
            </Box>
            <Typography variant="subtitle1" sx={{ opacity: 0.9 }}>
              Check file hashes against VirusTotal's database
            </Typography>
          </CardContent>
        </StyledCard>

        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Box sx={{ mb: 3 }}>
              <FormControl fullWidth>
                <InputLabel>Hash Type</InputLabel>
                <Select
                  value={hashType}
                  onChange={handleHashTypeChange}
                  label="Hash Type"
                >
                  <MenuItem value="md5">MD5</MenuItem>
                  <MenuItem value="sha1">SHA-1</MenuItem>
                  <MenuItem value="sha256">SHA-256</MenuItem>
                </Select>
              </FormControl>
            </Box>

            <Box sx={{ position: 'relative' }}>
              <TextField
                fullWidth
                label={`Enter ${hashType.toUpperCase()} Hash`}
                variant="outlined"
                value={hashValue}
                onChange={handleHashInput}
                error={!!error}
                helperText={error}
                disabled={loading}
                placeholder={`Paste your ${hashType.toUpperCase()} hash here...`}
                sx={{ mb: 2 }}
              />
              <IconButton
                onClick={copyToClipboard}
                sx={{
                  position: 'absolute',
                  right: 8,
                  top: 8,
                  color: 'primary.main',
                }}
              >
                <CopyIcon />
              </IconButton>
            </Box>

            {error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {error}
              </Alert>
            )}

            <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
              <Button
                variant="contained"
                size="large"
                onClick={handleScan}
                disabled={loading || !hashValue.trim()}
                startIcon={loading ? <CircularProgress size={20} /> : <HashIcon />}
              >
                {loading ? 'Scanning...' : 'Scan Hash'}
              </Button>
            </Box>
          </CardContent>
        </Card>

        {result && (
          <ResultCard severity={result.isMalicious ? 'error' : 'success'}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              {result.isMalicious ? (
                <WarningIcon color="error" sx={{ mr: 2, fontSize: 30 }} />
              ) : (
                <CheckCircleIcon color="success" sx={{ mr: 2, fontSize: 30 }} />
              )}
              <Typography variant="h6">
                {result.isMalicious
                  ? `Malicious Content Detected (${Math.round(result.confidence * 100)}% confidence)`
                  : 'No Malicious Content Detected'}
              </Typography>
            </Box>

            {result.isMalicious && (
              <>
                <Box sx={{ mt: 2, mb: 3 }}>
                  <Typography variant="subtitle1" gutterBottom>
                    Detection Summary
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {result.detectionCount} out of {result.totalScanners} security vendors flagged this hash as malicious
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    First seen: {new Date(result.firstSeen).toLocaleDateString()}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Last seen: {new Date(result.lastSeen).toLocaleDateString()}
                  </Typography>
                </Box>

                <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>
                  Detections:
                </Typography>
                <List>
                  {result.detections.map((detection, index) => (
                    <React.Fragment key={index}>
                      <ListItem alignItems="flex-start">
                        <ListItemIcon>
                          <WarningIcon sx={{ color: getSeverityColor(detection.severity) }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              {detection.engine}
                              <Chip
                                label={detection.severity}
                                size="small"
                                sx={{
                                  ml: 1,
                                  backgroundColor: getSeverityColor(detection.severity),
                                  color: 'white',
                                }}
                              />
                            </Box>
                          }
                          secondary={detection.result}
                        />
                      </ListItem>
                      {index < result.detections.length - 1 && <Divider />}
                    </React.Fragment>
                  ))}
                </List>

                <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>
                  File Information:
                </Typography>
                <List>
                  <ListItem>
                    <ListItemText
                      primary="File Type"
                      secondary={result.fileInfo.type}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="File Size"
                      secondary={result.fileInfo.size}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Tags"
                      secondary={result.fileInfo.tags.join(', ')}
                    />
                  </ListItem>
                </List>

                <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>
                  Recommendations:
                </Typography>
                <List>
                  {result.recommendations.map((recommendation, index) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        <SecurityIcon color="primary" />
                      </ListItemIcon>
                      <ListItemText primary={recommendation} />
                    </ListItem>
                  ))}
                </List>
              </>
            )}
          </ResultCard>
        )}
      </Box>
    </Container>
  );
};

export default HashScan; 