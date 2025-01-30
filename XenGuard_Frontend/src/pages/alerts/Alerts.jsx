import React, { useState } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  IconButton,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Button,
  TextField,
  InputAdornment,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Search as SearchIcon,
  FilterList as FilterListIcon,
  MoreVert as MoreVertIcon,
} from '@mui/icons-material';

// Mock data - Replace with actual API data
const alerts = [
  {
    id: 1,
    title: 'Multiple Failed Login Attempts',
    priority: 'HIGH',
    category: 'SECURITY',
    status: 'NEW',
    timestamp: '2024-01-28 14:30',
    source: 'Auth Service',
  },
  {
    id: 2,
    title: 'Unusual Network Traffic Detected',
    priority: 'CRITICAL',
    category: 'NETWORK',
    status: 'INVESTIGATING',
    timestamp: '2024-01-28 14:15',
    source: 'Network Monitor',
  },
  {
    id: 3,
    title: 'System Resource Usage Spike',
    priority: 'MEDIUM',
    category: 'SYSTEM',
    status: 'RESOLVED',
    timestamp: '2024-01-28 13:45',
    source: 'System Monitor',
  },
];

const getPriorityColor = (priority) => {
  const colors = {
    LOW: 'success',
    MEDIUM: 'warning',
    HIGH: 'error',
    CRITICAL: 'error',
  };
  return colors[priority] || 'default';
};

const getStatusColor = (status) => {
  const colors = {
    NEW: 'error',
    INVESTIGATING: 'warning',
    IN_PROGRESS: 'info',
    RESOLVED: 'success',
  };
  return colors[status] || 'default';
};

const AlertSummaryCard = ({ title, count, icon: Icon, color }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Icon sx={{ color: `${color}.main`, mr: 1 }} />
          <Typography variant="h6" color="textPrimary">
            {title}
          </Typography>
        </Box>
        <IconButton size="small">
          <MoreVertIcon />
        </IconButton>
      </Box>
      <Typography variant="h3" sx={{ mt: 2, mb: 1, fontWeight: 'bold' }}>
        {count}
      </Typography>
    </CardContent>
  </Card>
);

const Alerts = () => {
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Typography variant="h4" sx={{ fontWeight: 'bold' }}>
          Security Alerts
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <TextField
            size="small"
            placeholder="Search alerts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
            sx={{ width: 300 }}
          />
          <Button
            variant="outlined"
            startIcon={<FilterListIcon />}
            sx={{ borderRadius: 2 }}
          >
            Filter
          </Button>
        </Box>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <AlertSummaryCard
            title="New Alerts"
            count="18"
            icon={NotificationsIcon}
            color="error"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <AlertSummaryCard
            title="Investigating"
            count="7"
            icon={NotificationsIcon}
            color="warning"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <AlertSummaryCard
            title="In Progress"
            count="12"
            icon={NotificationsIcon}
            color="info"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <AlertSummaryCard
            title="Resolved Today"
            count="23"
            icon={NotificationsIcon}
            color="success"
          />
        </Grid>
      </Grid>

      {/* Alerts Table */}
      <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Title</TableCell>
              <TableCell>Priority</TableCell>
              <TableCell>Category</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Source</TableCell>
              <TableCell>Timestamp</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {alerts.map((alert) => (
              <TableRow key={alert.id} hover>
                <TableCell>{alert.title}</TableCell>
                <TableCell>
                  <Chip
                    label={alert.priority}
                    color={getPriorityColor(alert.priority)}
                    size="small"
                  />
                </TableCell>
                <TableCell>{alert.category}</TableCell>
                <TableCell>
                  <Chip
                    label={alert.status}
                    color={getStatusColor(alert.status)}
                    size="small"
                  />
                </TableCell>
                <TableCell>{alert.source}</TableCell>
                <TableCell>{alert.timestamp}</TableCell>
                <TableCell align="right">
                  <IconButton size="small">
                    <MoreVertIcon />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default Alerts;
