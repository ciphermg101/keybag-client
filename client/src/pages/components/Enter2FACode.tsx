import React, { useState } from "react";
import {
  Avatar,
  Box,
  Button,
  CircularProgress,
  Container,
  CssBaseline,
  TextField,
  Typography,
  Snackbar,
  Alert,
} from "@mui/material";
import { LockOutlined } from "@mui/icons-material";
import axiosInstance from "../../utils/axiosInstance";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const Enter2FACode: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [twoFactorCode, setTwoFactorCode] = useState<string>("");
  const [snackbarMessage, setSnackbarMessage] = useState<string>("");
  const [snackbarSeverity, setSnackbarSeverity] = useState<"success" | "error" | "info" | "warning">("info");
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const navigate = useNavigate();

  // Fetch userId from sessionStorage

  const handleSubmit2FACode = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
  
    setSnackbarMessage("");
    setSnackbarSeverity("info");
  
    if (!twoFactorCode.trim()) {
      setSnackbarMessage("Please enter the 2FA code.");
      setSnackbarSeverity("warning");
      setOpenSnackbar(true);
      return;
    }
  
    const userId = sessionStorage.getItem("userId");
    if (!userId) {
      setSnackbarMessage("User ID not found. Please log in again.");
      setSnackbarSeverity("error");
      setOpenSnackbar(true);
      return;
    }

    const token = sessionStorage.getItem("token");
  
    if (!token) {
      setSnackbarMessage("Failed to fetch authentication token. Please try again.");
      setSnackbarSeverity("error");
      setOpenSnackbar(true);
      setLoading(false);
      return;
    }
  
    setLoading(true);
  
    try {
      const response = await axiosInstance.post(
        "/auth/verify-2fa",
        { mf_token: twoFactorCode, userId: userId },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
          withCredentials: true,
        }
      );
    
      if (response.status === 200) {
        setSnackbarMessage("2FA verified successfully!");
        setSnackbarSeverity("success");
        setTimeout(() => {
          navigate("/dashboard");
        }, 2000);
      }
    } catch (error) {
      if (axios.isAxiosError(error)) {
        // Handle Axios errors
        const status = error.response?.status;
    
        switch (status) {
          case 400:
            setSnackbarMessage(error.response?.data?.message || "Bad request. Please check your inputs.");
            break;
          case 404:
            setSnackbarMessage("2FA record not found. Please contact support.");
            break;
          case 401:
            setSnackbarMessage("Invalid or expired 2FA token. Please try again.");
            break;
          case 429:
            setSnackbarMessage("Too Many Login Attempts. Please try again Later.");
            break;
          case 501:
            setSnackbarMessage("Failed to verify 2FA. Please try again later.");
            break;
          default:
            setSnackbarMessage("An unexpected error occurred. Please try again.");
            break;
        }
        setSnackbarSeverity("error");
      } else {
        // Handle non-Axios errors
        console.error("Unexpected error:", error);
        setSnackbarMessage("A network error occurred. Please check your connection and try again.");
        setSnackbarSeverity("error");
      }
    } finally {
      setLoading(false);
      setOpenSnackbar(true);
    }

  };

  return (
    <Container
      component="main"
      sx={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        height: "100vh",
        backgroundColor: "#f0f0f0",
      }}
    >
      <CssBaseline />
      <Box
        sx={{
          marginTop: 8,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          backgroundColor: "#90A7B6FF",
          padding: "2rem",
          borderRadius: "10px",
          boxShadow: 3,
          width: "60%",
        }}
      >
        <Avatar sx={{ m: 1, bgcolor: "primary.main", width: 56, height: 56 }}>
          <LockOutlined />
        </Avatar>
        <Typography component="h1" variant="h5" sx={{ color: "white", textAlign: "center" }}>
          Enter Two-Factor Authentication Code
        </Typography>
        <Box component="form" onSubmit={handleSubmit2FACode} sx={{ mt: 3 }}>
          <TextField
            label="Enter 2FA Code"
            variant="outlined"
            type="text"
            value={twoFactorCode}
            onChange={(e) => setTwoFactorCode(e.target.value)}
            disabled={loading}
            fullWidth
            required
            sx={{
              input: { color: "white" },
              label: { color: "white" },
              "& .MuiOutlinedInput-root": {
                "& fieldset": {
                  borderColor: "rgba(255, 255, 255, 0.5)",
                },
                "&:hover fieldset": {
                  borderColor: "white",
                },
              },
            }}
          />
          <Button
            type="submit"
            fullWidth
            variant="contained"
            sx={{
              mt: 3,
              mb: 2,
              backgroundColor: "primary.main",
              "&:hover": {
                backgroundColor: "primary.dark",
              },
            }}
            disabled={loading || !twoFactorCode.trim()}
          >
            {loading ? <CircularProgress size={24} /> : "Verify 2FA"}
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

export default Enter2FACode;
