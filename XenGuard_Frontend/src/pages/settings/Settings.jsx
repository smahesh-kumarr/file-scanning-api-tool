import React from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Switch,
  FormControlLabel,
  TextField,
  Button,
  Divider,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Security as SecurityIcon,
  Language as LanguageIcon,
  ColorLens as ColorLensIcon,
} from '@mui/icons-material';

const SettingCard = ({ title, icon: Icon, children }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <Icon sx={{ mr: 1, color: 'primary.main' }} />
        <Typography variant="h6">{title}</Typography>
      </Box>
      {children}
    </CardContent>
  </Card>
);

const Settings = () => {
  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" sx={{ mb: 4, fontWeight: 'bold' }}>
        Settings
      </Typography>

      <Grid container spacing={3}>
        {/* Notification Settings */}
        <Grid item xs={12} md={6}>
          <SettingCard title="Notification Preferences" icon={NotificationsIcon}>
            <FormControlLabel
              control={<Switch defaultChecked />}
              label="Email Notifications"
              sx={{ width: '100%', mb: 2 }}
            />
            <FormControlLabel
              control={<Switch defaultChecked />}
              label="Push Notifications"
              sx={{ width: '100%', mb: 2 }}
            />
            <FormControlLabel
              control={<Switch defaultChecked />}
              label="Critical Alert Notifications"
              sx={{ width: '100%', mb: 2 }}
            />
            <FormControlLabel
              control={<Switch />}
              label="Weekly Report Notifications"
              sx={{ width: '100%' }}
            />
          </SettingCard>
        </Grid>

        {/* Security Settings */}
        <Grid item xs={12} md={6}>
          <SettingCard title="Security Settings" icon={SecurityIcon}>
            <FormControlLabel
              control={<Switch defaultChecked />}
              label="Two-Factor Authentication"
              sx={{ width: '100%', mb: 2 }}
            />
            <FormControlLabel
              control={<Switch defaultChecked />}
              label="Login Alerts"
              sx={{ width: '100%', mb: 2 }}
            />
            <Button variant="outlined" color="primary" sx={{ mb: 2 }}>
              Change Password
            </Button>
            <Button variant="outlined" color="primary">
              Manage API Keys
            </Button>
          </SettingCard>
        </Grid>

        {/* Display Settings */}
        <Grid item xs={12} md={6}>
          <SettingCard title="Display Settings" icon={ColorLensIcon}>
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Theme</InputLabel>
              <Select defaultValue="dark" label="Theme">
                <MenuItem value="light">Light</MenuItem>
                <MenuItem value="dark">Dark</MenuItem>
                <MenuItem value="system">System</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Date Format</InputLabel>
              <Select defaultValue="24" label="Date Format">
                <MenuItem value="12">12-hour</MenuItem>
                <MenuItem value="24">24-hour</MenuItem>
              </Select>
            </FormControl>
            <FormControlLabel
              control={<Switch defaultChecked />}
              label="Compact View"
              sx={{ width: '100%' }}
            />
          </SettingCard>
        </Grid>

        {/* Regional Settings */}
        <Grid item xs={12} md={6}>
          <SettingCard title="Regional Settings" icon={LanguageIcon}>
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Language</InputLabel>
              <Select defaultValue="en" label="Language">
                <MenuItem value="en">English</MenuItem>
                <MenuItem value="es">Spanish</MenuItem>
                <MenuItem value="fr">French</MenuItem>
                <MenuItem value="de">German</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Timezone</InputLabel>
              <Select defaultValue="utc" label="Timezone">
                <MenuItem value="utc">UTC</MenuItem>
                <MenuItem value="est">EST</MenuItem>
                <MenuItem value="pst">PST</MenuItem>
                <MenuItem value="ist">IST</MenuItem>
              </Select>
            </FormControl>
          </SettingCard>
        </Grid>

        {/* API Settings */}
        <Grid item xs={12}>
          <SettingCard title="API Integration Settings" icon={SecurityIcon}>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="API Endpoint"
                  defaultValue="https://api.xenguard.com/v1"
                  sx={{ mb: 2 }}
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="API Key"
                  type="password"
                  defaultValue="••••••••••••••••"
                  sx={{ mb: 2 }}
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="API Secret"
                  type="password"
                  defaultValue="••••••••••••••••"
                  sx={{ mb: 2 }}
                />
              </Grid>
              <Grid item xs={12}>
                <Button variant="contained" color="primary">
                  Save API Settings
                </Button>
              </Grid>
            </Grid>
          </SettingCard>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Settings;
