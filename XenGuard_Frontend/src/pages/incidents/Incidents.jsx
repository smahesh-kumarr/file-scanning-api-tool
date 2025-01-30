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
  LinearProgress,
} from '@mui/material';
import {
  Report as ReportIcon,
  Add as AddIcon,
  MoreVert as MoreVertIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';

// Mock data - Replace with actual API data
const incidents = [
  {
    id: 1,
    title: 'Data Breach Investigation',
    type: 'SECURITY_BREACH',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    progress: 35,
    assignedTo: 'John Doe',
    createdAt: '2024-01-28 10:30',
  },
  {
    id: 2,
    title: 'Ransomware Attack',
    type: 'MALWARE_OUTBREAK',
    severity: 'HIGH',
    status: 'CONTAINED',
    progress: 75,
    assignedTo: 'Jane Smith',
    createdAt: '2024-01-28 09:15',
  },
  {
    id: 3,
    title: 'DDoS Attack',
    type: 'DDOS',
    severity: 'MEDIUM',
    status: 'RESOLVED',
    progress: 100,
    assignedTo: 'Mike Johnson',
    createdAt: '2024-01-27 15:45',
  },
];

const getSeverityColor = (severity) => {
  const colors = {
    LOW: 'success',
    MEDIUM: 'warning',
    HIGH: 'error',
    CRITICAL: 'error',
  };
  return colors[severity] || 'default';
};

const getStatusColor = (status) => {
  const colors = {
    OPEN: 'error',
    INVESTIGATING: 'warning',
    CONTAINED: 'info',
    RESOLVED: 'success',
  };
  return colors[status] || 'default';
};

const IncidentSummaryCard = ({ title, count, icon: Icon, color }) => (
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

const Incidents = () => {
  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Typography variant="h4" sx={{ fontWeight: 'bold' }}>
          Security Incidents
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          sx={{ borderRadius: 2 }}
        >
          Create Incident
        </Button>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <IncidentSummaryCard
            title="Open Incidents"
            count="5"
            icon={ReportIcon}
            color="error"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <IncidentSummaryCard
            title="Under Investigation"
            count="8"
            icon={TimelineIcon}
            color="warning"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <IncidentSummaryCard
            title="Contained"
            count="3"
            icon={ReportIcon}
            color="info"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <IncidentSummaryCard
            title="Resolved"
            count="15"
            icon={ReportIcon}
            color="success"
          />
        </Grid>
      </Grid>

      {/* Incidents Table */}
      <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Title</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Progress</TableCell>
              <TableCell>Assigned To</TableCell>
              <TableCell>Created At</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {incidents.map((incident) => (
              <TableRow key={incident.id} hover>
                <TableCell>{incident.title}</TableCell>
                <TableCell>{incident.type}</TableCell>
                <TableCell>
                  <Chip
                    label={incident.severity}
                    color={getSeverityColor(incident.severity)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={incident.status}
                    color={getStatusColor(incident.status)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <LinearProgress
                      variant="determinate"
                      value={incident.progress}
                      sx={{ flexGrow: 1, height: 8, borderRadius: 4 }}
                    />
                    <Typography variant="body2" color="textSecondary">
                      {incident.progress}%
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell>{incident.assignedTo}</TableCell>
                <TableCell>{incident.createdAt}</TableCell>
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

export default Incidents;
