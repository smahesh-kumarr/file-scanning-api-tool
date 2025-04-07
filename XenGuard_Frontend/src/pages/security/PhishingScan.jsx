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
  Tabs,
  Tab,
  Divider,
} from '@mui/material';
import {
  Security as SecurityIcon,
  ArrowBack as ArrowBackIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  ContentCopy as CopyIcon,
  Info as InfoIcon,
  Link as LinkIcon,
  Email as EmailIcon,
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

const PhishingScan = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);
  const [url, setUrl] = useState('');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [errorDetails, setErrorDetails] = useState(null);

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
    setResult(null);
    setError(null);
    setErrorDetails(null);
  };

  const handleUrlChange = (event) => {
    setUrl(event.target.value.trim());
    setResult(null);
    setError(null);
    setErrorDetails(null);
  };

  const handleContentChange = (event) => {
    setContent(event.target.value);
    setResult(null);
    setError(null);
    setErrorDetails(null);
  };

  const handleCopyContent = () => {
    navigator.clipboard.writeText(content);
  };

  const handleScan = async () => {
    if (activeTab === 0 && !url) {
      setError('URL is required');
      setErrorDetails('Please enter a URL to analyze');
      return;
    }

    if (activeTab === 1 && !content) {
      setError('Content is required');
      setErrorDetails('Please enter email content to analyze');
      return;
    }

    setLoading(true);
    setError(null);
    setErrorDetails(null);

    try {
      const response = await axios.post('http://localhost:5000/api/security/scan-phishing', {
        url: activeTab === 0 ? url : null,
        content: activeTab === 1 ? content : null
      });
      setResult(response.data);
    } catch (err) {
      console.error('Phishing scan error:', err);
      setError(err.response?.data?.error || 'Failed to analyze content');
      setErrorDetails(err.response?.data?.details || 'An error occurred while analyzing the content. Please try again.');
    } finally {
      setLoading(false);
    }
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
                Phishing Scanner
              </Typography>
            </Box>
            <Typography variant="subtitle1" sx={{ opacity: 0.9 }}>
              Analyze URLs and email content for phishing attempts
            </Typography>
          </CardContent>
        </StyledCard>

        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Tabs
              value={activeTab}
              onChange={handleTabChange}
              sx={{ mb: 3 }}
            >
              <Tab 
                icon={<LinkIcon />} 
                label="URL Analysis" 
              />
              <Tab 
                icon={<EmailIcon />} 
                label="Email Content" 
              />
            </Tabs>

            {activeTab === 0 ? (
              <Box sx={{ mb: 3 }}>
                <TextField
                  fullWidth
                  label="Enter URL"
                  variant="outlined"
                  value={url}
                  onChange={handleUrlChange}
                  placeholder="https://example.com"
                  InputProps={{
                    endAdornment: (
                      <IconButton onClick={() => navigator.clipboard.writeText(url)} disabled={!url}>
                        <CopyIcon />
                      </IconButton>
                    ),
                  }}
                  helperText="Enter the URL to analyze for phishing attempts"
                />
              </Box>
            ) : (
              <Box sx={{ mb: 3 }}>
                <TextField
                  fullWidth
                  multiline
                  rows={6}
                  label="Enter Email Content"
                  variant="outlined"
                  value={content}
                  onChange={handleContentChange}
                  placeholder="Paste email content here..."
                  InputProps={{
                    endAdornment: (
                      <IconButton onClick={handleCopyContent} disabled={!content}>
                        <CopyIcon />
                      </IconButton>
                    ),
                  }}
                  helperText="Paste the email content to analyze for phishing patterns"
                />
              </Box>
            )}

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
              disabled={loading || (activeTab === 0 ? !url : !content)}
              startIcon={loading ? <CircularProgress size={20} /> : <SecurityIcon />}
            >
              {loading ? 'Analyzing...' : 'Analyze Content'}
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
                  {result.status === 'safe' ? 'Content is Safe' : 'Potential Phishing Detected'}
                </Typography>
                {result.status !== 'safe' && (
                  <Typography variant="subtitle1" color="error">
                    Threat Level: {result.threatLevel.toUpperCase()}
                  </Typography>
                )}
              </Box>
            </Box>

            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Typography variant="subtitle1" gutterBottom>
                  Security Analysis
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  <Chip
                    label={`Phishing: ${result.details.securityChecks.phishing}`}
                    color={result.details.securityChecks.phishing === 'Clean' ? 'success' : 'error'}
                    sx={{ m: 0.5 }}
                  />
                  <Chip
                    label={`Suspicious: ${result.details.securityChecks.suspicious}`}
                    color={result.details.securityChecks.suspicious === 'Clean' ? 'success' : 'warning'}
                    sx={{ m: 0.5 }}
                  />
                  <Chip
                    label={`Malware: ${result.details.securityChecks.malware}`}
                    color={result.details.securityChecks.malware === 'Clean' ? 'success' : 'error'}
                    sx={{ m: 0.5 }}
                  />
                  <Chip
                    label={`Threat Score: ${result.details.threatScore}%`}
                    color={result.details.threatScore > 50 ? 'error' : 'success'}
                    sx={{ m: 0.5 }}
                  />
                </Box>
              </Grid>

              {result.details.analysis && result.details.analysis.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle1" gutterBottom>
                    Detailed Analysis
                  </Typography>
                  <List>
                    {result.details.analysis.map((analysis, index) => (
                      <React.Fragment key={index}>
                        <ListItem>
                          <ListItemIcon>
                            <InfoIcon color={analysis.confidence === 'High' ? 'error' : 'warning'} />
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <Typography variant="subtitle2">{analysis.source}</Typography>
                                <Chip
                                  label={analysis.confidence}
                                  size="small"
                                  color={analysis.confidence === 'High' ? 'error' : 'warning'}
                                />
                              </Box>
                            }
                            secondary={
                              <Box>
                                <Typography variant="body2" color="text.secondary">
                                  {analysis.result}
                                </Typography>
                                {analysis.details && (
                                  <Typography variant="caption" color="text.secondary">
                                    {JSON.stringify(analysis.details, null, 2)}
                                  </Typography>
                                )}
                              </Box>
                            }
                          />
                        </ListItem>
                        {index < result.details.analysis.length - 1 && <Divider />}
                      </React.Fragment>
                    ))}
                  </List>
                </Grid>
              )}
            </Grid>
          </ResultCard>
        )}
      </Box>
    </Container>
  );
};

export default PhishingScan; 