import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from '@mui/material/styles';
import { CssBaseline } from '@mui/material';
import { Provider } from 'react-redux';
import { useSelector } from 'react-redux';
import theme from './theme';
import store from './store';
import DashboardLayout from './components/layout/DashboardLayout';
import './styles/auth.css';

// Lazy load components
import React, { Suspense } from 'react';
const AuthPage = React.lazy(() => import('./pages/auth/AuthPage'));
const Dashboard = React.lazy(() => import('./pages/dashboard/Dashboard'));
const Threats = React.lazy(() => import('./pages/threats/Threats'));
const ThreatLookup = React.lazy(() => import('./pages/lookup/ThreatLookup'));
const Alerts = React.lazy(() => import('./pages/alerts/Alerts'));
const Incidents = React.lazy(() => import('./pages/incidents/Incidents'));
const Settings = React.lazy(() => import('./pages/settings/Settings'));

// Loading component
const LoadingScreen = () => (
  <div style={{ 
    display: 'flex', 
    justifyContent: 'center', 
    alignItems: 'center', 
    height: '100vh',
    backgroundColor: theme.palette.background.default 
  }}>
    <img 
      src="/logo.svg" 
      alt="Loading" 
      style={{ 
        width: '100px',
        animation: 'pulse 1.5s infinite'
      }} 
    />
  </div>
);

// Auth Route component
const AuthRoute = ({ children }) => {
  const { isAuthenticated } = useSelector((state) => state.auth);
  
  // If authenticated, redirect to dashboard
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

// Protected Route component
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated } = useSelector((state) => state.auth);
  
  // If not authenticated, redirect to login
  if (!isAuthenticated) {
    return <Navigate to="/auth" replace />;
  }

  return <DashboardLayout>{children}</DashboardLayout>;
};

function App() {
  return (
    <Provider store={store}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <BrowserRouter>
          <Suspense fallback={<LoadingScreen />}>
            <Routes>
              {/* Auth Routes */}
              <Route
                path="/auth"
                element={
                  <AuthRoute>
                    <AuthPage />
                  </AuthRoute>
                }
              />
              
              {/* Root Route - Redirect to auth by default */}
              <Route path="/" element={<Navigate to="/auth" replace />} />

              {/* Protected Routes */}
              <Route
                path="/dashboard"
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/threats"
                element={
                  <ProtectedRoute>
                    <Threats />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/lookup"
                element={
                  <ProtectedRoute>
                    <ThreatLookup />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/alerts"
                element={
                  <ProtectedRoute>
                    <Alerts />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/incidents"
                element={
                  <ProtectedRoute>
                    <Incidents />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/settings"
                element={
                  <ProtectedRoute>
                    <Settings />
                  </ProtectedRoute>
                }
              />

              {/* Catch all - redirect to auth */}
              <Route path="*" element={<Navigate to="/auth" replace />} />
            </Routes>
          </Suspense>
        </BrowserRouter>
      </ThemeProvider>
    </Provider>
  );
}

export default App;
