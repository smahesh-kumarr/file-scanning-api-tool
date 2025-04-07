import React from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  IconButton,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  NotificationsActive as AlertIcon,
  BugReport as BugIcon,
  Settings as SettingsIcon,
  Link as LinkIcon,
  Fingerprint as HashIcon,
  CloudUpload,
  PhishingOutlined as PhishingIcon,
  MailOutline as EmailIcon,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { useNavigate } from 'react-router-dom';

const StyledCard = styled(Card)(({ theme }) => ({
  height: '100%',
  display: 'flex',
  flexDirection: 'column',
  transition: 'transform 0.3s ease-in-out, box-shadow 0.3s ease-in-out',
  cursor: 'pointer',
  '&:hover': {
    transform: 'translateY(-5px)',
    boxShadow: theme.shadows[8],
  },
}));

const IconWrapper = styled(Box)(({ theme, color }) => ({
  backgroundColor: color || theme.palette.primary.main,
  borderRadius: '50%',
  padding: theme.spacing(1),
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  marginRight: theme.spacing(1),
  '& svg': {
    color: '#fff',
  },
}));

const Dashboard = () => {
  const navigate = useNavigate();

  const dashboardItems = [
    {
      title: 'XenSafe Mode',
      description: 'Personal security tools for everyday users',
      icon: SecurityIcon,
      color: '#4C51BF',
      count: null,
      path: '/xensafe',
    },
    {
      title: 'Active Threats',
      description: 'Monitor and manage current security threats',
      icon: WarningIcon,
      color: '#E53E3E',
      count: 12,
      path: '/threats',
    },
    {
      title: 'Recent Alerts',
      description: 'View and respond to security alerts',
      icon: AlertIcon,
      color: '#38A169',
      count: 8,
      path: '/alerts',
    },
    {
      title: 'Open Incidents',
      description: 'Track and resolve security incidents',
      icon: BugIcon,
      color: '#3182CE',
      count: 3,
      path: '/incidents',
    },
    {
      title: 'URL Scan',
      description: 'Check URLs for security threats',
      icon: LinkIcon,
      color: '#2196F3',
      count: null,
      path: '/url-scan',
    },
    {
      title: 'Hash Scan',
      description: 'Check file hashes against threat databases',
      icon: HashIcon,
      color: '#D69E2E',
      count: null,
      path: '/hash-scan',
    },
    {
      title: 'File Upload Scan',
      description: 'Scan files for security threats',
      icon: CloudUpload,
      color: '#4299E1',
      count: null,
      path: '/file-upload-scan',
    },
    {
      title: 'Phishing Scan',
      description: 'Detect phishing attempts and scams',
      icon: PhishingIcon,
      color: '#63B3ED',
      count: null,
      path: '/phishing-scan',
    },
    {
      title: 'Email Breach Scan',
      description: 'Check if your email was compromised',
      icon: EmailIcon,
      color: '#9F7AEA',
      count: null,
      path: '/email-breach-scan',
    },
    {
      title: 'System Settings',
      description: 'Configure system preferences and security policies',
      icon: SettingsIcon,
      color: '#6B46C1',
      count: null,
      path: '/settings',
    },
  ];

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" sx={{ mb: 1 }}>
          Welcome back, {localStorage.getItem('userName') || 'User'}! 👋
        </Typography>
        <Typography color="text.secondary">
          Here's what's happening in your security environment
        </Typography>
      </Box>

      <Grid container spacing={3}>
        {dashboardItems.map((item, index) => (
          <Grid item xs={12} sm={6} md={4} key={index}>
            <StyledCard onClick={() => navigate(item.path)}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <IconWrapper color={item.color}>
                    <item.icon />
                  </IconWrapper>
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="h6" component="div">
                      {item.title}
                    </Typography>
                    {item.count !== null && (
                      <Typography
                        variant="h4"
                        component="div"
                        sx={{ fontWeight: 'bold', color: item.color }}
                      >
                        {item.count}
                      </Typography>
                    )}
                  </Box>
                </Box>
                <Typography color="text.secondary" variant="body2">
                  {item.description}
                </Typography>
                <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
                  <Button
                    size="small"
                    endIcon={<item.icon />}
                    sx={{ color: item.color }}
                  >
                    View Details
                  </Button>
                </Box>
              </CardContent>
            </StyledCard>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

export default Dashboard;