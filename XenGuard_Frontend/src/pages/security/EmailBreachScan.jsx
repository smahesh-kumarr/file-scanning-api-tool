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
} from '@mui/material';
import {
  MailOutline as EmailIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Security as SecurityIcon,
  ArrowBack as ArrowBackIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { styled } from '@mui/material/styles';

const StyledCard = styled(Card)(({ theme }) => ({
  background: 'linear-gradient(135deg, #1a237e 0%, #0d47a1 100%)',
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

const EmailBreachScan = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleEmailCheck = async () => {
    if (!email) {
      setError('Please enter an email address');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Simulated API call - replace with actual implementation
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Simulated response - replace with actual API response
      const mockResponse = {
        breached: true,
        breaches: [
          {
            name: 'Example Breach 1',
            domain: 'example1.com',
            date: '2023-01-15',
            description: 'Data breach affecting user credentials',
          },
          {
            name: 'Example Breach 2',
            domain: 'example2.com',
            date: '2022-11-20',
            description: 'Security incident exposing user information',
          },
        ],
      };

      setResult(mockResponse);
    } catch (err) {
      setError('Failed to check email. Please try again.');
      console.error('Email check error:', err);
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
                Email Breach Scanner
              </Typography>
            </Box>
            <Typography variant="subtitle1" sx={{ opacity: 0.9 }}>
              Check if your email has been compromised in data breaches
            </Typography>
          </CardContent>
        </StyledCard>

        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Box sx={{ display: 'flex', gap: 2 }}>
              <TextField
                fullWidth
                label="Enter Email Address"
                variant="outlined"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                error={!!error}
                helperText={error}
                disabled={loading}
                InputProps={{
                  startAdornment: <EmailIcon sx={{ mr: 1, color: 'action.active' }} />,
                }}
              />
              <Button
                variant="contained"
                size="large"
                onClick={handleEmailCheck}
                disabled={loading}
                sx={{ minWidth: '120px' }}
              >
                {loading ? <CircularProgress size={24} /> : 'Scan'}
              </Button>
            </Box>
          </CardContent>
        </Card>

        {result && (
          <ResultCard severity={result.breached ? 'error' : 'success'}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              {result.breached ? (
                <WarningIcon color="error" sx={{ mr: 2, fontSize: 30 }} />
              ) : (
                <CheckCircleIcon color="success" sx={{ mr: 2, fontSize: 30 }} />
              )}
              <Typography variant="h6">
                {result.breached
                  ? 'Email Found in Data Breaches'
                  : 'No Breaches Found'}
              </Typography>
            </Box>

            {result.breached && (
              <>
                <Typography variant="body1" sx={{ mb: 2 }}>
                  Your email was found in the following data breaches:
                </Typography>
                <List>
                  {result.breaches.map((breach, index) => (
                    <React.Fragment key={index}>
                      <ListItem alignItems="flex-start">
                        <ListItemIcon>
                          <WarningIcon color="error" />
                        </ListItemIcon>
                        <ListItemText
                          primary={breach.name}
                          secondary={
                            <>
                              <Typography component="span" variant="body2" color="text.primary">
                                {breach.domain} - {breach.date}
                              </Typography>
                              <br />
                              {breach.description}
                            </>
                          }
                        />
                      </ListItem>
                      {index < result.breaches.length - 1 && <Divider />}
                    </React.Fragment>
                  ))}
                </List>
                <Box sx={{ mt: 3 }}>
                  <Alert severity="warning">
                    We recommend changing your password immediately if you use it on any of these sites.
                  </Alert>
                </Box>
              </>
            )}
          </ResultCard>
        )}
      </Box>
    </Container>
  );
};

export default EmailBreachScan; 