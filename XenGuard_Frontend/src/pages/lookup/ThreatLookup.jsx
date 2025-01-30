import React, { useState } from 'react';
import {
  Box,
  TextField,
  Button,
  Paper,
  Typography,
  CircularProgress,
  Grid,
  Tabs,
  Tab,
  Chip,
  Divider,
  Alert,
} from '@mui/material';
import {
  Search as SearchIcon,
  Language as DomainIcon,
  Memory as HashIcon,
  Router as IpIcon,
} from '@mui/icons-material';
import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:4000';

// Custom TabPanel component
function TabPanel({ children, value, index, ...other }) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`lookup-tabpanel-${index}`}
      aria-labelledby={`lookup-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const ThreatLookup = () => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [results, setResults] = useState(null);
  const [activeTab, setActiveTab] = useState(0);
  const [queryType, setQueryType] = useState('ip'); // 'ip', 'domain', or 'hash'

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
  };

  const detectQueryType = (input) => {
    // IP address regex
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    // Domain regex
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    // Hash regex (MD5, SHA1, SHA256)
    const hashRegex = /^[a-fA-F0-9]{32,64}$/;

    if (ipRegex.test(input)) return 'ip';
    if (domainRegex.test(input)) return 'domain';
    if (hashRegex.test(input)) return 'hash';
    return null;
  };

  const handleSearch = async () => {
    if (!query.trim()) return;

    const detectedType = detectQueryType(query);
    if (!detectedType) {
      setError('Invalid input format. Please enter a valid IP, domain, or hash.');
      return;
    }

    setQueryType(detectedType);
    setLoading(true);
    setError(null);

    try {
      const response = await axios.post(`${API_BASE_URL}/api/lookup`, {
        query: query.trim(),
        type: detectedType,
      });

      if (response.data.success) {
        setResults(response.data.data);
        setActiveTab(0); // Reset to first tab when new results arrive
      } else {
        setError(response.data.message || 'Lookup failed');
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to perform lookup');
    } finally {
      setLoading(false);
    }
  };

  const renderResults = () => {
    if (!results) return null;

    return (
      <Box sx={{ width: '100%', mt: 3 }}>
        <Paper elevation={3}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={activeTab} onChange={handleTabChange} aria-label="lookup results tabs">
              {results.virustotal && <Tab label="VirusTotal" />}
              {results.shodan && <Tab label="Shodan" />}
              {results.history && <Tab label="Lookup History" />}
            </Tabs>
          </Box>

          {results.virustotal && (
            <TabPanel value={activeTab} index={0}>
              <Typography variant="h6" gutterBottom>
                VirusTotal Results
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Paper elevation={1} sx={{ p: 2, bgcolor: 'background.default' }}>
                    <Typography variant="subtitle1" gutterBottom>
                      Detections: {results.virustotal.positives}/{results.virustotal.total}
                    </Typography>
                    <Box sx={{ mt: 2 }}>
                      {results.virustotal.scans?.map((scan, index) => (
                        <Chip
                          key={index}
                          label={`${scan.vendor}: ${scan.result}`}
                          color={scan.detected ? 'error' : 'success'}
                          sx={{ m: 0.5 }}
                        />
                      ))}
                    </Box>
                  </Paper>
                </Grid>
              </Grid>
            </TabPanel>
          )}

          {results.shodan && (
            <TabPanel value={activeTab} index={1}>
              <Typography variant="h6" gutterBottom>
                Shodan Results
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Paper elevation={1} sx={{ p: 2, bgcolor: 'background.default' }}>
                    <Typography variant="subtitle1" gutterBottom>
                      Open Ports: {results.shodan.ports?.join(', ')}
                    </Typography>
                    <Divider sx={{ my: 2 }} />
                    <Typography variant="subtitle1" gutterBottom>
                      Services:
                    </Typography>
                    {results.shodan.services?.map((service, index) => (
                      <Chip
                        key={index}
                        label={`${service.port}: ${service.name}`}
                        sx={{ m: 0.5 }}
                      />
                    ))}
                  </Paper>
                </Grid>
              </Grid>
            </TabPanel>
          )}

          {results.history && (
            <TabPanel value={activeTab} index={2}>
              <Typography variant="h6" gutterBottom>
                Lookup History
              </Typography>
              <Grid container spacing={2}>
                {results.history.map((entry, index) => (
                  <Grid item xs={12} key={index}>
                    <Paper elevation={1} sx={{ p: 2, bgcolor: 'background.default' }}>
                      <Typography variant="subtitle2" color="text.secondary">
                        {new Date(entry.timestamp).toLocaleString()}
                      </Typography>
                      <Typography variant="body1">
                        Found in: {entry.sources.join(', ')}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </TabPanel>
          )}
        </Paper>
      </Box>
    );
  };

  return (
    <Box sx={{ p: 4 }}>
      <Typography variant="h4" gutterBottom>
        Threat Lookup
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
        Search for information about IP addresses, domains, or file hashes
      </Typography>

      <Paper elevation={3} sx={{ p: 3, mb: 4 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={9}>
            <TextField
              fullWidth
              variant="outlined"
              placeholder="Enter IP address, domain, or hash..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              InputProps={{
                startAdornment: (
                  <Box sx={{ mr: 2, color: 'text.secondary' }}>
                    {queryType === 'ip' && <IpIcon />}
                    {queryType === 'domain' && <DomainIcon />}
                    {queryType === 'hash' && <HashIcon />}
                  </Box>
                ),
              }}
            />
          </Grid>
          <Grid item xs={12} md={3}>
            <Button
              fullWidth
              variant="contained"
              color="primary"
              onClick={handleSearch}
              disabled={loading}
              startIcon={loading ? <CircularProgress size={20} /> : <SearchIcon />}
            >
              {loading ? 'Searching...' : 'Search'}
            </Button>
          </Grid>
        </Grid>

        {error && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {error}
          </Alert>
        )}
      </Paper>

      {renderResults()}
    </Box>
  );
};

export default ThreatLookup;
