import React, { useState } from 'react';
import {
  Box,
  TextField,
  Button,
  Typography,
  IconButton,
  InputAdornment,
  Checkbox,
  FormControlLabel,
  Link,
  CircularProgress,
  Snackbar,
  Alert,
  Divider,
  Container,
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Mail as MailIcon,
  Lock as LockIcon,
  Person as PersonIcon,
  Facebook as FacebookIcon,
  Twitter as TwitterIcon,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { loginStart, loginSuccess, loginFailure } from '../../store/slices/authSlice';
import axios from 'axios';

// Styled components
const AuthContainer = styled(Box)({
  display: 'flex',
  minHeight: '100vh',
  width: '100vw',
  overflow: 'hidden',
});

const FormSection = styled(Box)(({ theme }) => ({
  width: '50%',
  minWidth: '50%',
  maxWidth: '50%',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
  padding: theme.spacing(8),
  backgroundColor: '#fff',
}));

const FormContent = styled(Box)({
  maxWidth: '440px',
  width: '100%',
  margin: '0 auto',
});

const ImageSection = styled(Box)(({ theme }) => ({
  width: '50%',
  minWidth: '50%',
  maxWidth: '50%',
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  background: 'linear-gradient(135deg, #1a237e 0%, #0d47a1 100%)',
  position: 'relative',
  padding: theme.spacing(4),
  overflow: 'hidden',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundImage: 'url("/cyber-pattern.svg")',
    backgroundSize: 'cover',
    backgroundPosition: 'center',
    opacity: 0.1,
    animation: 'pulse 4s infinite',
  },
}));

const StyledTextField = styled(TextField)(({ theme }) => ({
  marginBottom: theme.spacing(3),
  '& .MuiOutlinedInput-root': {
    backgroundColor: '#f8f9fa',
    borderRadius: '12px',
    height: '56px',
    transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
    '&:hover': {
      backgroundColor: '#f8f9fa',
      transform: 'translateY(-1px)',
    },
    '&.Mui-focused': {
      backgroundColor: '#f8f9fa',
      transform: 'translateY(-2px)',
    },
    '& input': {
      padding: '15.5px 14px',
      fontSize: '0.95rem',
      color: '#2c3e50',
      '&::placeholder': {
        color: '#9e9e9e',
        opacity: 1,
        fontSize: '0.95rem',
      },
    },
    '& .MuiInputAdornment-root': {
      margin: '0 0 0 12px',
      '& .MuiSvgIcon-root': {
        fontSize: '20px',
      },
    },
  },
  '& .MuiOutlinedInput-notchedOutline': {
    border: '1.5px solid #e0e0e0',
    borderRadius: '12px',
    transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
  },
  '& .Mui-focused .MuiOutlinedInput-notchedOutline': {
    borderColor: '#2196f3',
    borderWidth: '1.5px',
    boxShadow: '0 0 0 4px rgba(33, 150, 243, 0.1)',
  },
  '& .MuiFormHelperText-root': {
    marginLeft: '14px',
    marginTop: '6px',
    fontSize: '0.8rem',
  },
  '& .MuiFormHelperText-root.Mui-error': {
    color: theme.palette.error.main,
  },
}));

const SocialButton = styled(IconButton)(({ theme }) => ({
  width: '48px',
  height: '48px',
  margin: theme.spacing(0, 1),
  backgroundColor: '#fff',
  border: '1.5px solid #e0e0e0',
  borderRadius: '12px',
  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
  '&:hover': {
    backgroundColor: '#f5f5f5',
    transform: 'translateY(-2px)',
    boxShadow: '0 4px 8px rgba(0, 0, 0, 0.1)',
  },
  '&:active': {
    transform: 'translateY(0)',
  },
}));

const AnimatedButton = styled(Button)(({ theme }) => ({
  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
  '&:hover': {
    transform: 'translateY(-2px)',
    boxShadow: '0 4px 8px rgba(0, 0, 0, 0.1)',
  },
  '&:active': {
    transform: 'translateY(0)',
  },
}));

const AuthPage = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: '',
    severity: 'success'
  });

  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: '',
    confirmPassword: '',
    agreeToTerms: false
  });

  const validateForm = () => {
    const newErrors = {};
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!formData.email) {
      newErrors.email = 'Email is required';
    } else if (!emailRegex.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    // Password validation
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters long';
    }

    // Registration specific validations
    if (!isLogin) {
      if (!formData.name) {
        newErrors.name = 'Full name is required';
      }

      if (!formData.confirmPassword) {
        newErrors.confirmPassword = 'Please confirm your password';
      } else if (formData.password !== formData.confirmPassword) {
        newErrors.confirmPassword = 'Passwords do not match';
      }

      if (!formData.agreeToTerms) {
        newErrors.agreeToTerms = 'You must agree to the Terms and Privacy Policy';
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: name === 'agreeToTerms' ? checked : value
    }));
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      setSnackbar({
        open: true,
        message: 'Please fix the errors in the form',
        severity: 'error'
      });
      return;
    }

    setLoading(true);
    const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';
    
    try {
      if (isLogin) {
        // Login logic
        const response = await axios.post(`${API_BASE_URL}/api/auth/login`, {
          email: formData.email,
          password: formData.password
        });

        if (response.data.success) {
          dispatch(loginSuccess(response.data.data));
          setSnackbar({
            open: true,
            message: 'Successfully logged in!',
            severity: 'success'
          });
          navigate('/dashboard');
        }
      } else {
        // Register logic
        const response = await axios.post(`${API_BASE_URL}/api/auth/signup`, {
          name: formData.name,
          email: formData.email,
          password: formData.password
        });

        if (response.data.success) {
          setSnackbar({
            open: true,
            message: 'Account created successfully! Please log in.',
            severity: 'success'
          });
          setIsLogin(true);
        }
      }
    } catch (error) {
      console.error('Auth error:', error);
      setSnackbar({
        open: true,
        message: error.response?.data?.error || error.message || 'An error occurred. Please try again.',
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCloseSnackbar = () => {
    setSnackbar(prev => ({ ...prev, open: false }));
  };

  return (
    <AuthContainer>
      <FormSection>
        <FormContent>
          <Box sx={{ mb: 5 }}>
            <Typography 
              variant="h3" 
              sx={{ 
                fontWeight: 500, 
                mb: 2,
                fontSize: '2.5rem',
                color: '#2c3e50'
              }}
            >
              {isLogin ? 'Welcome Back :)' : 'Create Account'}
            </Typography>
            <Typography 
              color="text.secondary" 
              sx={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: 1,
                fontSize: '0.95rem',
                lineHeight: 1.5,
                color: '#7f8c8d'
              }}
            >
              {isLogin 
                ? 'To keep connected with us please login with your personal information by email address and password'
                : 'Get started with your free account. Please enter your personal details to continue'
              }
              <Box component="span" role="img" aria-label="warning" sx={{ fontSize: '1.2rem' }}>
                ⚠️
              </Box>
            </Typography>
          </Box>

          <form onSubmit={handleSubmit} style={{ width: '100%' }} className="form-content">
            {!isLogin && (
              <StyledTextField
                fullWidth
                placeholder="Full Name"
                name="name"
                value={formData.name}
                onChange={handleChange}
                error={!!errors.name}
                helperText={errors.name}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <PersonIcon sx={{ color: errors.name ? 'error.main' : '#9e9e9e', fontSize: '20px' }} />
                    </InputAdornment>
                  ),
                }}
              />
            )}

            <StyledTextField
              fullWidth
              placeholder="Email Address"
              name="email"
              type="email"
              value={formData.email}
              onChange={handleChange}
              error={!!errors.email}
              helperText={errors.email}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <MailIcon sx={{ color: errors.email ? 'error.main' : '#9e9e9e', fontSize: '20px' }} />
                  </InputAdornment>
                ),
              }}
            />

            <StyledTextField
              fullWidth
              placeholder="Password"
              name="password"
              type={showPassword ? 'text' : 'password'}
              value={formData.password}
              onChange={handleChange}
              error={!!errors.password}
              helperText={errors.password}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <LockIcon sx={{ color: errors.password ? 'error.main' : '#9e9e9e', fontSize: '20px' }} />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton 
                      onClick={() => setShowPassword(!showPassword)} 
                      edge="end"
                      sx={{ color: errors.password ? 'error.main' : '#9e9e9e' }}
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />

            {!isLogin && (
              <StyledTextField
                fullWidth
                placeholder="Confirm Password"
                name="confirmPassword"
                type={showPassword ? 'text' : 'password'}
                value={formData.confirmPassword}
                onChange={handleChange}
                error={!!errors.confirmPassword}
                helperText={errors.confirmPassword}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <LockIcon sx={{ color: errors.confirmPassword ? 'error.main' : '#9e9e9e', fontSize: '20px' }} />
                    </InputAdornment>
                  ),
                }}
              />
            )}

            {isLogin && (
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 4, mt: 1 }}>
                <FormControlLabel
                  control={
                    <Checkbox
                      sx={{
                        color: '#9e9e9e',
                        '&.Mui-checked': { color: '#2196f3' },
                        '& .MuiSvgIcon-root': { fontSize: 20 }
                      }}
                    />
                  }
                  label={
                    <Typography sx={{ color: '#7f8c8d', fontSize: '0.95rem' }}>
                      Remember Me
                    </Typography>
                  }
                />
                <Link
                  component="button"
                  variant="body2"
                  onClick={(e) => {
                    e.preventDefault();
                    // TODO: Implement forgot password
                    setSnackbar({
                      open: true,
                      message: 'Password reset functionality coming soon!',
                      severity: 'info'
                    });
                  }}
                  sx={{ 
                    color: '#7f8c8d', 
                    textDecoration: 'none',
                    fontSize: '0.95rem',
                    '&:hover': {
                      color: '#2196f3'
                    }
                  }}
                >
                  Forget Password?
                </Link>
              </Box>
            )}

            {!isLogin && (
              <FormControlLabel
                control={
                  <Checkbox
                    name="agreeToTerms"
                    checked={formData.agreeToTerms}
                    onChange={handleChange}
                    sx={{
                      color: errors.agreeToTerms ? 'error.main' : '#9e9e9e',
                      '&.Mui-checked': { color: '#2196f3' },
                      '& .MuiSvgIcon-root': { fontSize: 20 }
                    }}
                  />
                }
                label={
                  <Typography sx={{ 
                    color: errors.agreeToTerms ? 'error.main' : '#7f8c8d', 
                    fontSize: '0.95rem' 
                  }}>
                    I agree to the Terms of Service and Privacy Policy
                  </Typography>
                }
                sx={{ mb: 4, mt: 1 }}
              />
            )}

            <Box sx={{ display: 'flex', gap: 2, mb: 5 }}>
              <AnimatedButton
                variant="contained"
                size="large"
                type="submit"
                disabled={loading}
                sx={{
                  flex: 1,
                  py: 1.8,
                  borderRadius: '12px',
                  textTransform: 'none',
                  fontSize: '1rem',
                  fontWeight: 500,
                  backgroundColor: '#2196f3',
                  '&:hover': {
                    backgroundColor: '#1976d2'
                  }
                }}
              >
                {loading ? (
                  <CircularProgress size={24} color="inherit" />
                ) : (
                  isLogin ? 'Login Now' : 'Create Account'
                )}
              </AnimatedButton>
              <AnimatedButton
                variant="outlined"
                size="large"
                onClick={() => {
                  setIsLogin(!isLogin);
                  setErrors({});
                  setFormData({
                    email: '',
                    password: '',
                    name: '',
                    confirmPassword: '',
                    agreeToTerms: false
                  });
                }}
                disabled={loading}
                sx={{
                  flex: 1,
                  py: 1.8,
                  borderRadius: '12px',
                  textTransform: 'none',
                  fontSize: '1rem',
                  fontWeight: 500,
                  borderColor: '#e0e0e0',
                  color: '#7f8c8d',
                  '&:hover': {
                    borderColor: '#bdbdbd',
                    backgroundColor: '#f5f5f5',
                  }
                }}
              >
                {isLogin ? 'Create Account' : 'Back to Login'}
              </AnimatedButton>
            </Box>
          </form>

          <Box sx={{ textAlign: 'center' }}>
            <Typography 
              color="text.secondary" 
              sx={{ 
                mb: 2.5,
                fontSize: '0.95rem',
                color: '#7f8c8d'
              }}
            >
              Or you can join with
            </Typography>
            <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2 }}>
              <SocialButton>
                <img src="/google.svg" alt="Google" style={{ width: 22, height: 22 }} />
              </SocialButton>
              <SocialButton sx={{ backgroundColor: '#1877f2', '&:hover': { backgroundColor: '#1865d1' } }}>
                <FacebookIcon sx={{ color: '#fff', fontSize: 22 }} />
              </SocialButton>
              <SocialButton sx={{ backgroundColor: '#1da1f2', '&:hover': { backgroundColor: '#1a91da' } }}>
                <TwitterIcon sx={{ color: '#fff', fontSize: 22 }} />
              </SocialButton>
            </Box>
          </Box>
        </FormContent>
      </FormSection>

      <ImageSection>
        <Box
          sx={{
            position: 'relative',
            zIndex: 1,
            textAlign: 'center',
            width: '100%',
            px: 4,
          }}
        >
          <Typography
            variant="h2"
            sx={{
              color: 'white',
              fontWeight: 'bold',
              mb: 3,
              textShadow: '0 2px 4px rgba(0,0,0,0.2)',
              fontSize: { xs: '2rem', sm: '2.5rem', md: '3rem' },
            }}
          >
            {isLogin ? 'Welcome Back!' : 'Join XenGuard'}
          </Typography>
          <Typography
            variant="h5"
            sx={{
              color: 'rgba(255,255,255,0.9)',
              maxWidth: '500px',
              mx: 'auto',
              lineHeight: 1.6,
              mb: 6,
              fontSize: { xs: '1rem', sm: '1.25rem' },
            }}
          >
            {isLogin 
              ? 'Advanced threat detection and response platform'
              : 'Start securing your digital assets with our advanced security platform'
            }
          </Typography>
          <Box
            sx={{
              position: 'relative',
              width: '100%',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
            }}
          >
            <Box
              component="img"
              src="/logo.svg"
              alt="Security"
              sx={{
                width: { xs: '150px', sm: '180px', md: '200px' },
                animation: 'float 6s infinite ease-in-out',
                filter: 'drop-shadow(0 4px 8px rgba(0,0,0,0.2))',
              }}
            />
          </Box>
        </Box>
      </ImageSection>
      <Snackbar 
        open={snackbar.open} 
        autoHideDuration={6000} 
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <Alert 
          onClose={handleCloseSnackbar} 
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </AuthContainer>
  );
};

export default AuthPage;
