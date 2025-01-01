import React, { useState, useEffect } from "react";
import { LockOutlined, Visibility, VisibilityOff } from "@mui/icons-material";
import {
  Container,
  CssBaseline,
  Box,
  Avatar,
  Typography,
  TextField,
  Button,
  Snackbar,
  Alert,
  IconButton,
} from "@mui/material";
import { useNavigate, useParams } from "react-router-dom";
import axiosInstance from "../utils/axiosInstance";
import axios from "axios";

const ResetPassword: React.FC = () => {
  const [newPassword, setPassword] = useState<string>("");
  const [confirmPassword, setConfirmPassword] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState<string>("");
  const [snackbarSeverity, setSnackbarSeverity] = useState<"success" | "error" | "info" | "warning">("info");
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [showPassword, setShowPassword] = useState(false); 
  const [isTokenValid, setIsTokenValid] = useState<boolean | null>(null);
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();

  useEffect(() => {
    const verifyToken = async () => {
      if (!token) {
        setSnackbarMessage("Token is missing.");
        setSnackbarSeverity("error");
        setOpenSnackbar(true);
        return;
      }

      try {
        await axiosInstance.get(`/auth/verify-reset/${token}`);
        setIsTokenValid(true);
      } catch {
        setIsTokenValid(false);
        setSnackbarMessage("Invalid or expired token.");
        setSnackbarSeverity("error");
        setOpenSnackbar(true);
      }
    };

    verifyToken();
  }, [token]);

  const validateForm = (): string | null => {
    if (!newPassword || !confirmPassword) {
      return "Both fields are required.";
    }
    if (newPassword.length < 8) {
      return "Password must be at least 8 characters long.";
    }
    if (newPassword !== confirmPassword) {
      return "Passwords do not match.";
    }
    return null;
  };

  const handleTogglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  }; 

  const handleResetPassword = async () => {
    const validationError = validateForm();
    if (validationError) {
      setSnackbarMessage(validationError);
      setSnackbarSeverity("warning");
      setOpenSnackbar(true);
      return;
    }

    if (!isTokenValid) {
      setSnackbarMessage("Token is invalid or expired.");
      setSnackbarSeverity("error");
      setOpenSnackbar(true);
      return;
    }

    setLoading(true);
    try {
      const response = await axiosInstance.post(`/auth/reset-password/${token}`, {
        newPassword,
      });

      if (response.status === 200) {
        setSnackbarMessage("Password reset successful! Redirecting...");
        setSnackbarSeverity("success");
        setOpenSnackbar(true);
        setTimeout(() => navigate("/login"), 2000);
      } else {
        setSnackbarMessage(response.data?.message || "An error occurred.");
        setSnackbarSeverity("error");
        setOpenSnackbar(true);
      }
    } catch (error: unknown) {
      if (axios.isAxiosError(error) && error.response) {
        setSnackbarMessage("An error occurred while resetting the password.");
      } else {
        setSnackbarMessage("Network or unknown error occurred. Please try again.");
      }
      setSnackbarSeverity("error");
      setOpenSnackbar(true);
    } finally {
      setLoading(false);
    }
  };

  if (isTokenValid === null) {
    return (
      <Container component="main" maxWidth="xs">
        <CssBaseline />
        <Box
          sx={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            minHeight: "100vh",
          }}
        >
          <Typography variant="h5">Verifying Token...</Typography>
        </Box>
      </Container>
    );
  }

  if (isTokenValid === false) {
    return (
      <Container component="main" maxWidth="xs">
        <CssBaseline />
        <Box
          sx={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            minHeight: "100vh",
          }}
        >
          <Typography variant="h5" color="error">
            Invalid or expired token. Please request a new password reset.
          </Typography>
        </Box>
      </Container>
    );
  }

  return (
    <Container component="main" maxWidth="xs">
      <CssBaseline />
      <Box
        sx={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "100vh",
        }}
      >
        <Avatar sx={{ m: 1, bgcolor: "primary.main" }}>
          <LockOutlined />
        </Avatar>
        <Typography variant="h5">Reset Password</Typography>
        <Box
          sx={{
            mt: 2,
            width: "100%",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 2,
          }}
        >
          <TextField
            margin="normal"
            required
            fullWidth
            id="password"
            label="New Password"
            name="password"
            type={showPassword ? "text" : "password"}
            value={newPassword}
            onChange={(e) => setPassword(e.target.value)}
            InputProps={{
              endAdornment: (
                <IconButton onClick={handleTogglePasswordVisibility} edge="end">
                  {showPassword ? <VisibilityOff /> : <Visibility />}
                </IconButton>
              ),
            }}
          />
          <TextField
            margin="normal"
            required
            fullWidth
            id="confirmPassword"
            name="confirmPassword"
            label="Confirm Password"
            type={showPassword ? "text" : "password"}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            InputProps={{
              endAdornment: (
                <IconButton onClick={handleTogglePasswordVisibility} edge="end">
                  {showPassword ? <VisibilityOff /> : <Visibility />}
                </IconButton>
              ),
            }}
          />
          <Button
            fullWidth
            variant="contained"
            sx={{ mt: 2 }}
            onClick={handleResetPassword}
            disabled={loading}
          >
            {loading ? "Resetting Password..." : "Reset Password"}
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
          sx={{ width: "100%" }}
        >
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default ResetPassword;
