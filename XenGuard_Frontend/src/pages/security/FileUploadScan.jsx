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
  Divider,
  CircularProgress,
  Paper,
  Chip,
} from '@mui/material';
import {
  CloudUpload as UploadIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Security as SecurityIcon,
  ArrowBack as ArrowBackIcon,
  Description as FileIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { styled } from '@mui/material/styles';

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

  const handleFileUpload = (event) => {
    const uploadedFile = event.target.files[0];
    if (uploadedFile) {
      const fileType = uploadedFile.type;
      const validTypes = [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'text/plain',
      ];

      if (validTypes.includes(fileType)) {
        setFile(uploadedFile);
        setError(null);
      } else {
        setError('Please upload a valid file type (PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT)');
        setFile(null);
      }
    }
  };

  const handleDrop = (event) => {
    event.preventDefault();
    const droppedFile = event.dataTransfer.files[0];
    if (droppedFile) {
      const fileType = droppedFile.type;
      const validTypes = [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'text/plain',
      ];

      if (validTypes.includes(fileType)) {
        setFile(droppedFile);
        setError(null);
      } else {
        setError('Please upload a valid file type (PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT)');
        setFile(null);
      }
    }
  };

  const handleDragOver = (event) => {
    event.preventDefault();
  };

  const handleRemoveFile = () => {
    setFile(null);
    setResult(null);
  };

  const handleScan = async () => {
    if (!file) {
      setError('Please upload a file to scan');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Simulated API call - replace with actual implementation
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Simulated response - replace with actual API response
      const mockResponse = {
        isSafe: false,
        confidence: 0.92,
        threats: [
          {
            type: 'Malicious Code',
            description: 'Contains potentially harmful executable code',
            severity: 'high',
          },
          {
            type: 'Suspicious Links',
            description: 'Contains URLs that may lead to malicious websites',
            severity: 'medium',
          },
          {
            type: 'Macro Content',
            description: 'Contains potentially dangerous macros',
            severity: 'high',
          },
        ],
        fileInfo: {
          name: file.name,
          type: file.type,
          size: file.size,
          lastModified: file.lastModified,
        },
        recommendations: [
          'Do not open this file',
          'Delete the file from your system',
          'Report this file to your IT department',
          'Run a full system scan',
        ],
      };

      setResult(mockResponse);
    } catch (err) {
      setError('Failed to analyze file. Please try again.');
      console.error('File scan error:', err);
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
              isDragActive={false}
            >
              <input
                type="file"
                accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt"
                onChange={handleFileUpload}
                style={{ display: 'none' }}
                id="file-upload"
              />
              <label htmlFor="file-upload">
                <Box sx={{ cursor: 'pointer' }}>
                  <UploadIcon sx={{ fontSize: 40, color: 'primary.main', mb: 1 }} />
                  <Typography variant="h6" gutterBottom>
                    Drop your file here or click to upload
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Supports PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT
                  </Typography>
                </Box>
              </label>
            </UploadBox>

            {file && (
              <FilePreview>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <FileIcon sx={{ mr: 2, color: 'primary.main' }} />
                  <Box>
                    <Typography variant="subtitle1">{file.name}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {formatFileSize(file.size)}
                    </Typography>
                  </Box>
                </Box>
                <Button
                  startIcon={<DeleteIcon />}
                  onClick={handleRemoveFile}
                  color="error"
                >
                  Remove
                </Button>
              </FilePreview>
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
                disabled={loading || !file}
                startIcon={loading ? <CircularProgress size={20} /> : <SecurityIcon />}
              >
                {loading ? 'Scanning...' : 'Scan File'}
              </Button>
            </Box>
          </CardContent>
        </Card>

        {result && (
          <ResultCard severity={result.isSafe ? 'success' : 'error'}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              {result.isSafe ? (
                <CheckCircleIcon color="success" sx={{ mr: 2, fontSize: 30 }} />
              ) : (
                <WarningIcon color="error" sx={{ mr: 2, fontSize: 30 }} />
              )}
              <Typography variant="h6">
                {result.isSafe
                  ? 'File is Safe'
                  : `Threats Detected (${Math.round(result.confidence * 100)}% confidence)`}
              </Typography>
            </Box>

            {!result.isSafe && (
              <>
                <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>
                  Detected Threats:
                </Typography>
                <List>
                  {result.threats.map((threat, index) => (
                    <React.Fragment key={index}>
                      <ListItem alignItems="flex-start">
                        <ListItemIcon>
                          <WarningIcon sx={{ color: getSeverityColor(threat.severity) }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              {threat.type}
                              <Chip
                                label={threat.severity}
                                size="small"
                                sx={{
                                  ml: 1,
                                  backgroundColor: getSeverityColor(threat.severity),
                                  color: 'white',
                                }}
                              />
                            </Box>
                          }
                          secondary={threat.description}
                        />
                      </ListItem>
                      {index < result.threats.length - 1 && <Divider />}
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

export default FileUploadScan; 