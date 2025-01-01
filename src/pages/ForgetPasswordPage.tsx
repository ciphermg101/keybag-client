import React, { useState } from 'react';
import {
  Avatar,
  Box,
  Button,
  Container,
  CssBaseline,
  TextField,
  Typography,
  Snackbar,
  Alert,
} from '@mui/material';
import { LockOutlined } from '@mui/icons-material';
import axiosInstance from "../utils/axiosInstance";
import { AxiosError } from 'axios';
import validator from 'validator';

// Define an interface for the error response data structure
interface ErrorResponse {
  message: string;
}

const ForgotPasswordPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState<string>('');
  const [snackbarSeverity, setSnackbarSeverity] = useState<'success' | 'error' | 'warning' | 'info'>('info');
  const [openSnackbar, setOpenSnackbar] = useState(false);

  const handleReset = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate email
    if (!validator.isEmail(email)) {
      setSnackbarMessage('Please enter a valid email address.');
      setSnackbarSeverity('warning');
      setOpenSnackbar(true);
      return;
    }

    setLoading(true);

    try {
      const response = await axiosInstance.post('/auth/password-reset', { email }, { withCredentials: true });

      if (response.status === 200) {
        setSnackbarMessage(`A password reset link has been sent to ${email}. Please check your inbox.`);
        setSnackbarSeverity('success');
      } else {
        setSnackbarMessage('Unable to send reset link at the moment. Please try again later.');
        setSnackbarSeverity('error');
      }
    } catch (error) {
      const axiosError = error as AxiosError<ErrorResponse>;

      if (axiosError.response) {
        // Handle backend errors
        switch (axiosError.response.status) {
          case 400:
            setSnackbarMessage('Invalid email format or request. Please check and try again.');
            setSnackbarSeverity('error');
            break;
          case 404:
            setSnackbarMessage('We could not find an account associated with that email.');
            setSnackbarSeverity('warning');
            break;
          case 500:
            setSnackbarMessage('Server error. Please try again later.');
            setSnackbarSeverity('error');
            break;
          default:
            setSnackbarMessage(axiosError.response.data.message || 'An unexpected error occurred.');
            setSnackbarSeverity('error');
        }
      } else if (axiosError.request) {
        // Handle network errors
        setSnackbarMessage('Network error. Please check your connection and try again.');
        setSnackbarSeverity('error');
      } else {
        // Handle unexpected errors
        setSnackbarMessage(`Error: ${axiosError.message || 'An unexpected error occurred.'}`);
        setSnackbarSeverity('error');
      }
    } finally {
      setOpenSnackbar(true);
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="xs">
      <CssBaseline />
      <Box
        sx={{
          mt: 20,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
        }}
      >
        <Avatar sx={{ m: 1, bgcolor: 'primary.light' }}>
          <LockOutlined />
        </Avatar>
        <Typography variant="h5">Forgot Password</Typography>
        <Box component="form" onSubmit={handleReset} sx={{ mt: 3 }}>
          <TextField
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            label="Email Address"
            variant="outlined"
            required
            fullWidth
            autoFocus
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            sx={{ mt: 3, mb: 2 }}
            disabled={loading}
          >
            {loading ? 'Sending...' : 'Send Reset Link'}
          </Button>
        </Box>
      </Box>

      <Snackbar
        open={openSnackbar}
        autoHideDuration={5000}
        onClose={() => setOpenSnackbar(false)}
      >
        <Alert
          onClose={() => setOpenSnackbar(false)}
          severity={snackbarSeverity}
          sx={{ width: '100%' }}
        >
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default ForgotPasswordPage;
