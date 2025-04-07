import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Button,
  Card,
  CardContent,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  CircularProgress,
  Paper,
  Chip,
  TextField,
  Grid,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Security as SecurityIcon,
  ArrowBack as ArrowBackIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  ContentCopy as CopyIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { styled } from '@mui/material/styles';
import axios from 'axios';

const StyledCard = styled(Card)(({ theme }) => ({
  background: 'linear-gradient(135deg, #2D3748 0%, #1A202C 100%)',
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
  const [hash, setHash] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [errorDetails, setErrorDetails] = useState(null);

  const handleHashChange = (event) => {
    setHash(event.target.value.trim());
    setError(null);
    setErrorDetails(null);
    setResult(null);
  };

  const handleCopyHash = () => {
    navigator.clipboard.writeText(hash);
  };

  const handleScan = async () => {
    if (!hash) {
      setError('Hash is required');
      setErrorDetails('Please enter a hash to scan');
      return;
    }

    // Validate hash format
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    if (!hashRegex.test(hash)) {
      setError('Invalid hash format');
      setErrorDetails('Please enter a valid MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars) hash');
      return;
    }

    setLoading(true);
    setError(null);
    setErrorDetails(null);

    try {
      const response = await axios.post('http://localhost:5000/api/security/scan-hash', { hash });
      setResult(response.data);
    } catch (err) {
      console.error('Hash scan error:', err);
      setError(err.response?.data?.error || 'Failed to scan hash');
      setErrorDetails(err.response?.data?.details || 'An error occurred while scanning the hash. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
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
                Hash Security Scanner
              </Typography>
            </Box>
            <Typography variant="subtitle1" sx={{ opacity: 0.9 }}>
              Enter a file hash (MD5, SHA-1, or SHA-256) to check its security status
            </Typography>
          </CardContent>
        </StyledCard>

        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Box sx={{ mb: 3 }}>
              <TextField
                fullWidth
                label="Enter Hash"
                variant="outlined"
                value={hash}
                onChange={handleHashChange}
                placeholder="e.g., 44d88612fea8a8f36de82e1278abb02f"
                InputProps={{
                  endAdornment: (
                    <IconButton onClick={handleCopyHash} disabled={!hash}>
                      <CopyIcon />
                    </IconButton>
                  ),
                }}
                helperText="Enter MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars) hash"
              />
            </Box>

            {(error || errorDetails) && (
              <Alert 
                severity="error" 
                sx={{ mb: 2 }}
              >
                <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                  {error}
                </Typography>
                {errorDetails && (
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    {errorDetails}
                  </Typography>
                )}
              </Alert>
            )}

            <Button
              fullWidth
              variant="contained"
              onClick={handleScan}
              disabled={!hash || loading}
              startIcon={loading ? <CircularProgress size={20} /> : <SecurityIcon />}
            >
              {loading ? 'Scanning...' : 'Scan Hash'}
            </Button>
          </CardContent>
        </Card>

        {result && (
          <ResultCard severity={result.status === 'safe' ? 'success' : 'error'}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
              {result.status === 'safe' ? (
                <CheckCircleIcon color="success" sx={{ fontSize: 40, mr: 2 }} />
              ) : (
                <WarningIcon color="error" sx={{ fontSize: 40, mr: 2 }} />
              )}
              <Box>
                <Typography variant="h5">
                  {result.status === 'safe' ? 'Hash is Safe' : 'Hash May Be Unsafe'}
                </Typography>
                {result.status !== 'safe' && (
                  <Typography variant="subtitle1" color="error">
                    Threat Level: {result.threatLevel.toUpperCase()}
                  </Typography>
                )}
              </Box>
            </Box>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  File Information
                </Typography>
                <List>
                  <ListItem>
                    <ListItemText
                      primary="Name"
                      secondary={result.details.fileInfo.name}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Size"
                      secondary={formatFileSize(result.details.fileInfo.size)}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Type"
                      secondary={result.details.fileInfo.type}
                    />
                  </ListItem>
                </List>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Hash Information
                </Typography>
                <List>
                  <ListItem>
                    <ListItemText
                      primary="MD5"
                      secondary={result.details.fileInfo.md5}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="SHA-1"
                      secondary={result.details.fileInfo.sha1}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="SHA-256"
                      secondary={result.details.fileInfo.sha256}
                    />
                  </ListItem>
                </List>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Security Analysis
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  <Chip
                    label={`Malware: ${result.details.securityChecks.malware}`}
                    color={result.details.securityChecks.malware === 'Clean' ? 'success' : 'error'}
                    sx={{ m: 0.5 }}
                  />
                  <Chip
                    label={`Suspicious: ${result.details.securityChecks.suspicious}`}
                    color={result.details.securityChecks.suspicious === 'Clean' ? 'success' : 'warning'}
                    sx={{ m: 0.5 }}
                  />
                  <Chip
                    label={`Total Engines: ${result.details.totalEngines}`}
                    color="info"
                    sx={{ m: 0.5 }}
                  />
                  <Chip
                    label={`Threat Score: ${result.details.threatScore}`}
                    color={result.details.threatScore > 0 ? 'error' : 'success'}
                    sx={{ m: 0.5 }}
                  />
                </Box>
              </Grid>

              {result.details.threats && result.details.threats.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle1" gutterBottom>
                    Detected Threats
                  </Typography>
                  <List>
                    {result.details.threats.map((threat, index) => (
                      <ListItem key={index}>
                        <ListItemIcon>
                          <ErrorIcon color={threat.severity === 'high' ? 'error' : 'warning'} />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <Typography variant="subtitle2">{threat.engine}</Typography>
                              <Chip
                                label={threat.category}
                                size="small"
                                color={threat.severity === 'high' ? 'error' : 'warning'}
                              />
                            </Box>
                          }
                          secondary={
                            <Box>
                              <Typography variant="body2" color="text.secondary">
                                {threat.result}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Method: {threat.method}
                              </Typography>
                            </Box>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              )}

              <Grid item xs={12}>
                <Typography variant="subtitle1" gutterBottom>
                  Additional Information
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  <Chip
                    label={`First Seen: ${result.details.additionalInfo.firstSeen ? new Date(result.details.additionalInfo.firstSeen).toLocaleString() : 'Unknown'}`}
                    color="info"
                    sx={{ m: 0.5 }}
                  />
                  <Chip
                    label={`Last Seen: ${result.details.additionalInfo.lastSeen ? new Date(result.details.additionalInfo.lastSeen).toLocaleString() : 'Unknown'}`}
                    color="info"
                    sx={{ m: 0.5 }}
                  />
                  {result.details.additionalInfo.tags && result.details.additionalInfo.tags.length > 0 && (
                    result.details.additionalInfo.tags.map((tag, index) => (
                      <Chip
                        key={index}
                        label={tag}
                        color="default"
                        sx={{ m: 0.5 }}
                      />
                    ))
                  )}
                </Box>
              </Grid>
            </Grid>
          </ResultCard>
        )}
      </Box>
    </Container>
  );
};

export default HashScan; 