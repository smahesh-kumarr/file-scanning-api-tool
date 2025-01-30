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
} from '@mui/material';
import {
  Security as SecurityIcon,
  MoreVert as MoreVertIcon,
  Add as AddIcon,
} from '@mui/icons-material';

// Mock data - Replace with actual API data
const threats = [
  {
    id: 1,
    title: 'Suspicious Network Activity',
    type: 'Network',
    severity: 'HIGH',
    status: 'ACTIVE',
    lastUpdated: '2024-01-28',
    source: 'IDS',
  },
  {
    id: 2,
    title: 'Malware Detection',
    type: 'Malware',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    lastUpdated: '2024-01-28',
    source: 'Endpoint Security',
  },
  {
    id: 3,
    title: 'Unauthorized Access Attempt',
    type: 'Access',
    severity: 'MEDIUM',
    status: 'CONTAINED',
    lastUpdated: '2024-01-27',
    source: 'SIEM',
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
    ACTIVE: 'error',
    INVESTIGATING: 'warning',
    CONTAINED: 'success',
    RESOLVED: 'default',
  };
  return colors[status] || 'default';
};

const ThreatSummaryCard = ({ title, count, color }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <SecurityIcon sx={{ color: `${color}.main`, mr: 1 }} />
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

const Threats = () => {
  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Typography variant="h4" sx={{ fontWeight: 'bold' }}>
          Threat Intelligence
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          sx={{ borderRadius: 2 }}
        >
          Add Threat
        </Button>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <ThreatSummaryCard title="Critical Threats" count="12" color="error" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <ThreatSummaryCard title="High Threats" count="28" color="warning" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <ThreatSummaryCard title="Medium Threats" count="45" color="info" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <ThreatSummaryCard title="Low Threats" count="67" color="success" />
        </Grid>
      </Grid>

      {/* Threats Table */}
      <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Title</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Source</TableCell>
              <TableCell>Last Updated</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {threats.map((threat) => (
              <TableRow key={threat.id} hover>
                <TableCell>{threat.title}</TableCell>
                <TableCell>{threat.type}</TableCell>
                <TableCell>
                  <Chip
                    label={threat.severity}
                    color={getSeverityColor(threat.severity)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={threat.status}
                    color={getStatusColor(threat.status)}
                    size="small"
                  />
                </TableCell>
                <TableCell>{threat.source}</TableCell>
                <TableCell>{threat.lastUpdated}</TableCell>
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

export default Threats;
