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
  LinearProgress,
  Grid,
  IconButton,
} from '@mui/material';
import {
  CloudUpload as UploadIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Security as SecurityIcon,
  ArrowBack as ArrowBackIcon,
  Description as FileIcon,
  Delete as DeleteIcon,
  Error as ErrorIcon,
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

const FilePreview = styled(Box)(({ theme }) => ({
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: theme.spacing(2),
  marginTop: theme.spacing(2),
  backgroundColor: theme.palette.grey[100],
  borderRadius: theme.shape.borderRadius,
}));

const FileUploadScan = () => {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [errorDetails, setErrorDetails] = useState(null);
  const [progress, setProgress] = useState(0);
  const [isDragActive, setIsDragActive] = useState(false);

  const handleFileUpload = (event) => {
    const uploadedFile = event.target.files[0];
    if (uploadedFile) {
      // Validate file type
      const allowedTypes = [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'text/plain',
        'application/octet-stream'
      ];

      if (!allowedTypes.includes(uploadedFile.type)) {
        setError('Invalid file type');
        setErrorDetails('Please upload a valid file type (PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT)');
        return;
      }

      // Validate file size (32MB limit)
      if (uploadedFile.size > 32 * 1024 * 1024) {
        setError('File too large');
        setErrorDetails('File size exceeds 32MB limit');
        return;
      }

      setFile(uploadedFile);
      setError(null);
      setErrorDetails(null);
      setResult(null);
    }
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragActive(false);
    const droppedFile = event.dataTransfer.files[0];
    if (droppedFile) {
      handleFileUpload({ target: { files: [droppedFile] } });
    }
  };

  const handleDragOver = (event) => {
    event.preventDefault();
    setIsDragActive(true);
  };

  const handleDragLeave = () => {
    setIsDragActive(false);
  };

  const handleRemoveFile = () => {
    setFile(null);
    setResult(null);
  };

  const handleScan = async () => {
    if (!file) {
      setError('No file selected');
      setErrorDetails('Please select a file to scan');
      return;
    }

    setLoading(true);
    setError(null);
    setErrorDetails(null);
    setProgress(0);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await axios.post('http://localhost:5000/api/security/scan-file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          setProgress(percentCompleted);
        }
      });

      if (response.data && response.data.status) {
        setResult(response.data);
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (err) {
      console.error('File scan error:', err);
      setError(err.response?.data?.error || 'Failed to scan file');
      setErrorDetails(err.response?.data?.details || 'An error occurred while scanning the file. Please try again.');
    } finally {
      setLoading(false);
      setProgress(0);
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
                File Security Scanner
              </Typography>
            </Box>
            <Typography variant="subtitle1" sx={{ opacity: 0.9 }}>
              Upload and scan files for potential security threats
            </Typography>
          </CardContent>
        </StyledCard>

        <Card sx={{ mb: 4 }}>
          <CardContent>
            <UploadBox
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              isDragActive={isDragActive}
            >
              <input
                type="file"
                id="file-upload"
                style={{ display: 'none' }}
                onChange={handleFileUpload}
              />
              <label htmlFor="file-upload">
                <Button
                  variant="contained"
                  component="span"
                  startIcon={<UploadIcon />}
                  sx={{ mb: 2 }}
                >
                  Select File
                </Button>
              </label>
              <Typography variant="body2" color="textSecondary">
                or drag and drop files here
              </Typography>
              <Typography variant="caption" color="textSecondary" sx={{ mt: 1, display: 'block' }}>
                Supported formats: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT
              </Typography>
            </UploadBox>

            {file && (
              <FilePreview>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <FileIcon sx={{ mr: 2 }} />
                  <Box>
                    <Typography variant="body2">{file.name}</Typography>
                    <Typography variant="caption" color="textSecondary">
                      {formatFileSize(file.size)}
                    </Typography>
                  </Box>
                </Box>
                <IconButton onClick={handleRemoveFile} size="small">
                  <DeleteIcon />
                </IconButton>
              </FilePreview>
            )}

            {(error || errorDetails) && (
              <Alert 
                severity="error" 
                sx={{ mt: 2 }}
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

            {loading && (
              <Box sx={{ mt: 2 }}>
                <LinearProgress variant="determinate" value={progress} />
                <Typography variant="body2" sx={{ mt: 1, textAlign: 'center' }}>
                  Scanning file... {progress}%
                </Typography>
              </Box>
            )}

            <Button
              fullWidth
              variant="contained"
              onClick={handleScan}
              disabled={!file || loading}
              startIcon={loading ? <CircularProgress size={20} /> : <SecurityIcon />}
              sx={{ mt: 2 }}
            >
              {loading ? 'Scanning...' : 'Scan File'}
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
                  {result.status === 'safe' ? 'File is Safe' : 'File May Be Unsafe'}
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
                  Analysis Details
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  <Chip
                    label={`Last Analysis: ${new Date(result.details.lastAnalysisDate).toLocaleString()}`}
                    color="info"
                    sx={{ m: 0.5 }}
                  />
                  <Chip
                    label={`Reputation: ${result.details.reputation}`}
                    color={result.details.reputation === 'High' ? 'success' : 'error'}
                    sx={{ m: 0.5 }}
                  />
                  <Chip
                    label={`Undetected: ${result.details.securityChecks.undetected}`}
                    color="default"
                    sx={{ m: 0.5 }}
                  />
                  <Chip
                    label={`Harmless: ${result.details.securityChecks.harmless}`}
                    color="success"
                    sx={{ m: 0.5 }}
                  />
                </Box>
              </Grid>
            </Grid>
          </ResultCard>
        )}
      </Box>
    </Container>
  );
};

export default FileUploadScan; 