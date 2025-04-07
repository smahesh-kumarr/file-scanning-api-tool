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
  Tab,
  Tabs,
} from '@mui/material';
import {
  PhishingOutlined as PhishingIcon,
  AttachFile as FileIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Security as SecurityIcon,
  ArrowBack as ArrowBackIcon,
  Mail as MailIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { styled } from '@mui/material/styles';

const StyledCard = styled(Card)(({ theme }) => ({
  background: 'linear-gradient(135deg, #1e88e5 0%, #1565c0 100%)',
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

const UploadBox = styled(Box)(({ theme, isDragActive }) => ({
  border: `2px dashed ${isDragActive ? theme.palette.primary.main : theme.palette.grey[300]}`,
  borderRadius: theme.shape.borderRadius,
  padding: theme.spacing(3),
  textAlign: 'center',
  backgroundColor: isDragActive ? 'rgba(25, 118, 210, 0.08)' : 'transparent',
  transition: 'all 0.3s ease',
  cursor: 'pointer',
  '&:hover': {
    backgroundColor: 'rgba(25, 118, 210, 0.08)',
    borderColor: theme.palette.primary.main,
  },
}));

const PhishingScan = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);
  const [emailContent, setEmailContent] = useState('');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
    setResult(null);
    setError(null);
  };

  const handleFileUpload = (event) => {
    const uploadedFile = event.target.files[0];
    if (uploadedFile && uploadedFile.name.endsWith('.eml')) {
      setFile(uploadedFile);
      setError(null);
    } else {
      setError('Please upload a valid .eml file');
      setFile(null);
    }
  };

  const handleDrop = (event) => {
    event.preventDefault();
    const droppedFile = event.dataTransfer.files[0];
    if (droppedFile && droppedFile.name.endsWith('.eml')) {
      setFile(droppedFile);
      setError(null);
    } else {
      setError('Please upload a valid .eml file');
      setFile(null);
    }
  };

  const handleDragOver = (event) => {
    event.preventDefault();
  };

  const handleScan = async () => {
    if (activeTab === 0 && !file) {
      setError('Please upload an email file');
      return;
    }

    if (activeTab === 1 && !emailContent.trim()) {
      setError('Please enter email content');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Simulated API call - replace with actual implementation
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Simulated response - replace with actual API response
      const mockResponse = {
        isPhishing: true,
        confidence: 0.89,
        indicators: [
          {
            type: 'Suspicious Link',
            description: 'Contains URLs that mimic legitimate domains',
            severity: 'high',
          },
          {
            type: 'Urgency Language',
            description: 'Uses urgent or threatening language to prompt action',
            severity: 'medium',
          },
          {
            type: 'Sender Spoofing',
            description: 'Sender email address may be impersonating a legitimate domain',
            severity: 'high',
          },
        ],
        recommendations: [
          'Do not click on any links in the email',
          'Do not download any attachments',
          'Report this email to your IT department',
          'Delete the email from your inbox',
        ],
      };

      setResult(mockResponse);
    } catch (err) {
      setError('Failed to analyze email. Please try again.');
      console.error('Phishing scan error:', err);
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
              Analyze emails for potential phishing threats
            </Typography>
          </CardContent>
        </StyledCard>

        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Tabs value={activeTab} onChange={handleTabChange} sx={{ mb: 3 }}>
              <Tab 
                icon={<FileIcon />} 
                label="Upload EML" 
                iconPosition="start"
              />
              <Tab 
                icon={<MailIcon />} 
                label="Paste Content" 
                iconPosition="start"
              />
            </Tabs>

            {activeTab === 0 ? (
              <UploadBox
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                isDragActive={false}
              >
                <input
                  type="file"
                  accept=".eml"
                  onChange={handleFileUpload}
                  style={{ display: 'none' }}
                  id="eml-upload"
                />
                <label htmlFor="eml-upload">
                  <Box sx={{ cursor: 'pointer' }}>
                    <FileIcon sx={{ fontSize: 40, color: 'primary.main', mb: 1 }} />
                    <Typography variant="h6" gutterBottom>
                      Drop your .eml file here or click to upload
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {file ? file.name : 'Supports .eml format only'}
                    </Typography>
                  </Box>
                </label>
              </UploadBox>
            ) : (
              <TextField
                fullWidth
                multiline
                rows={6}
                label="Enter Email Content"
                variant="outlined"
                value={emailContent}
                onChange={(e) => setEmailContent(e.target.value)}
                error={!!error}
                helperText={error}
                disabled={loading}
                placeholder="Paste the email content here including headers, body, and links..."
              />
            )}

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
                disabled={loading}
                startIcon={loading ? <CircularProgress size={20} /> : <PhishingIcon />}
              >
                {loading ? 'Analyzing...' : 'Scan for Phishing'}
              </Button>
            </Box>
          </CardContent>
        </Card>

        {result && (
          <ResultCard severity={result.isPhishing ? 'error' : 'success'}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              {result.isPhishing ? (
                <WarningIcon color="error" sx={{ mr: 2, fontSize: 30 }} />
              ) : (
                <CheckCircleIcon color="success" sx={{ mr: 2, fontSize: 30 }} />
              )}
              <Typography variant="h6">
                {result.isPhishing
                  ? `Phishing Detected (${Math.round(result.confidence * 100)}% confidence)`
                  : 'No Phishing Detected'}
              </Typography>
            </Box>

            {result.isPhishing && (
              <>
                <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>
                  Detected Indicators:
                </Typography>
                <List>
                  {result.indicators.map((indicator, index) => (
                    <React.Fragment key={index}>
                      <ListItem alignItems="flex-start">
                        <ListItemIcon>
                          <WarningIcon sx={{ color: getSeverityColor(indicator.severity) }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={indicator.type}
                          secondary={indicator.description}
                          primaryTypographyProps={{
                            color: getSeverityColor(indicator.severity),
                          }}
                        />
                      </ListItem>
                      {index < result.indicators.length - 1 && <Divider />}
                    </React.Fragment>
                  ))}
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

export default PhishingScan; 