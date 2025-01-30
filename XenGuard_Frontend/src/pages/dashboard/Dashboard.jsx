import React from 'react';
import { Box, Typography, Grid, Paper, Button, IconButton, Avatar } from '@mui/material';
import {
  Security as SecurityIcon,
  NotificationsActive as AlertsIcon,
  BugReport as IncidentsIcon,
  Settings as SettingsIcon,
  ArrowForward as ArrowForwardIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';

const QuickAccessCard = ({ title, description, icon: Icon, path, count, gradient }) => {
  const navigate = useNavigate();
  
  return (
    <Paper
      elevation={3}
      sx={{
        p: 3,
        height: '100%',
        background: gradient,
        color: 'white',
        position: 'relative',
        overflow: 'hidden',
        cursor: 'pointer',
        transition: 'transform 0.2s',
        '&:hover': {
          transform: 'translateY(-4px)',
        },
      }}
      onClick={() => navigate(path)}
    >
      <Box sx={{ position: 'relative', zIndex: 1 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Avatar sx={{ bgcolor: 'rgba(255, 255, 255, 0.2)', width: 48, height: 48 }}>
            <Icon />
          </Avatar>
          {count !== undefined && (
            <Typography variant="h4" fontWeight="bold">
              {count}
            </Typography>
          )}
        </Box>
        <Typography variant="h6" fontWeight="bold" sx={{ mb: 1 }}>
          {title}
        </Typography>
        <Typography variant="body2" sx={{ mb: 2, opacity: 0.9 }}>
          {description}
        </Typography>
        <Button
          variant="text"
          color="inherit"
          endIcon={<ArrowForwardIcon />}
          sx={{ 
            pl: 0,
            '&:hover': { bgcolor: 'transparent', opacity: 0.8 }
          }}
        >
          View Details
        </Button>
      </Box>
      <Box
        sx={{
          position: 'absolute',
          right: -20,
          bottom: -20,
          opacity: 0.1,
        }}
      >
        <Icon sx={{ fontSize: 140 }} />
      </Box>
    </Paper>
  );
};

const Dashboard = () => {
  const user = useSelector((state) => state.auth.user);
  
  const quickAccessItems = [
    {
      title: 'Active Threats',
      description: 'Monitor and manage current security threats',
      icon: SecurityIcon,
      path: '/threats',
      count: 12,
      gradient: 'linear-gradient(135deg, #FF6B6B 0%, #FF8E53 100%)',
    },
    {
      title: 'Recent Alerts',
      description: 'View and respond to security alerts',
      icon: AlertsIcon,
      path: '/alerts',
      count: 8,
      gradient: 'linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%)',
    },
    {
      title: 'Open Incidents',
      description: 'Track and resolve security incidents',
      icon: IncidentsIcon,
      path: '/incidents',
      count: 3,
      gradient: 'linear-gradient(135deg, #2196F3 0%, #1565C0 100%)',
    },
    {
      title: 'System Settings',
      description: 'Configure system preferences and security policies',
      icon: SettingsIcon,
      path: '/settings',
      gradient: 'linear-gradient(135deg, #9C27B0 0%, #6A1B9A 100%)',
    },
  ];

  return (
    <Box sx={{ p: 4 }}>
      <Box sx={{ mb: 6 }}>
        <Typography variant="h4" sx={{ mb: 1 }}>
          Welcome back, {user?.name || 'User'}! 👋
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Here's what's happening in your security environment
        </Typography>
      </Box>

      <Grid container spacing={3}>
        {quickAccessItems.map((item, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <QuickAccessCard {...item} />
          </Grid>
        ))}
      </Grid>

      <Box sx={{ mt: 6 }}>
        <Typography variant="h5" sx={{ mb: 3 }}>
          Security Overview
        </Typography>
        <Paper
          elevation={3}
          sx={{
            p: 3,
            background: 'linear-gradient(135deg, #1a237e 0%, #0d47a1 100%)',
            color: 'white',
          }}
        >
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <WarningIcon sx={{ fontSize: 40 }} />
                <Box>
                  <Typography variant="h6">System Status</Typography>
                  <Typography variant="body2" sx={{ opacity: 0.9 }}>
                    All security systems are operating normally
                  </Typography>
                </Box>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
                <Button
                  variant="contained"
                  sx={{
                    bgcolor: 'rgba(255, 255, 255, 0.1)',
                    '&:hover': {
                      bgcolor: 'rgba(255, 255, 255, 0.2)',
                    },
                  }}
                >
                  View Security Report
                </Button>
              </Box>
            </Grid>
          </Grid>
        </Paper>
      </Box>
    </Box>
  );
};

export default Dashboard;