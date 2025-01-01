import { useState } from "react";
import { LockOutlined, Visibility, VisibilityOff } from "@mui/icons-material";
import {
  Container,
  CssBaseline,
  Box,
  Avatar,
  Typography,
  TextField,
  Button,
  Grid,
  Snackbar,
  IconButton,
  Alert,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import { GoogleLogin, CredentialResponse } from "@react-oauth/google";
import axiosInstance from "../utils/axiosInstance";
import axios from "axios";

// Define types for Google credential response and decoded JWT
const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState<boolean>(false);
  const [, setError] = useState<string | null>(null);
  const [openSnackbar, setOpenSnackbar] = useState<boolean>(false);
  const [snackbarMessage, setSnackbarMessage] = useState<string>("");
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false); 
  const [snackbarSeverity, setSnackbarSeverity] = useState<"success" | "error" | "info" | "warning">("info");

  const validateForm = (): string | null => {
    if (!email || !password) {
      return "Both fields are required.";
    }
    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      return "Please enter a valid email address.";
    }
    return null;
  };   

  const handleTogglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };  

  const handleLogin = async (event: React.MouseEvent<HTMLButtonElement>) => {
    setError(null);
    setLoading(true);
    event.preventDefault();
  
    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      setSnackbarMessage(validationError);
      setSnackbarSeverity("error");
      setOpenSnackbar(true);
      setLoading(false); // Stop loading if validation fails
      return;
    }
  
    try {
      const response = await axiosInstance.post( "/auth/login", { email, password }, { withCredentials: true });
      
      if (response.status === 200 && response.data) {
        const { action, message, token, email, userId } = response.data;
  
        // Handle successful login messages and redirects
        setSnackbarMessage(message);
        setSnackbarSeverity("success");
        setOpenSnackbar(true);
  
        if (action === "redirect_to_2fa") {
          // Redirect for 2FA
          sessionStorage.setItem("userId", userId);
          sessionStorage.setItem("token", token);
          document.cookie = `userEmail=${email}; path=/; max-age=36000000;`;
  
          setTimeout(() => {
            navigate(`/enter-two-fa-code`);
          }, 2000);
  
        } else if (action === "login_successful") {
          // Successful login (no 2FA needed)
          setSnackbarMessage("Login successful! Redirecting...");
          setSnackbarSeverity("success");
          setTimeout(() => {
            navigate("/dashboard");
          }, 2000);
  
          // Store the user email in cookies
          document.cookie = `userEmail=${email}; path=/; max-age=36000000;`;
        }
      }
    } catch (error) {
      setLoading(false); // Ensure loading stops on error
  
      if (axios.isAxiosError(error)) {
        if (error.response) {
          // Handle specific backend error responses
          switch (error.response.status) {
            case 400:
              setSnackbarMessage("Invalid credentials. Please try again.");
              setSnackbarSeverity("error");
              break;
            case 401:
              setSnackbarMessage("Invalid credentials. Please try again.");
              setSnackbarSeverity("error");
              break;
            case 403:
              setSnackbarMessage("Your account is not verified. Please check your email.");
              setSnackbarSeverity("warning");
              break;
            case 404:
              setSnackbarMessage("User not found. Kindly register.");
              setSnackbarSeverity("warning");
              break;
            case 429:
              setSnackbarMessage("Too many tries. Please try again Later.");
              setSnackbarSeverity("error");
              break;
            case 500:
              setSnackbarMessage("Internal server error. Please try again later.");
              setSnackbarSeverity("error");
              break;
            default:
              setSnackbarMessage("An unexpected error occurred.");
              setSnackbarSeverity("error");
              break;
          }
        } else if (error.request) {
          // Handle network errors
          setSnackbarMessage("Network error. Please check your connection.");
          setSnackbarSeverity("error");
        } else {
          // Handle unexpected request errors
          setSnackbarMessage(`Request error: ${error.message}`);
          setSnackbarSeverity("error");
        }
      } else {
        // Handle unknown error types
        setSnackbarMessage("An unknown error occurred.");
        setSnackbarSeverity("error");
      }
  
      setOpenSnackbar(true);
    } finally {
      setLoading(false); // Ensure loading always stops
    }
  };   

  const handleGoogleLogin = async (credentialResponse: CredentialResponse) => {
    try {
      if (!credentialResponse.credential) {
        throw new Error("No credential provided in response");
      }
  
      const googleToken = credentialResponse.credential; // The token provided by Google
  
      // Send the token to the backend for verification and to receive backend tokens
      const response = await axiosInstance.post("/auth/login/google", { googleToken }, { withCredentials: true });
  
      if (response.status === 200 && response.data) {
        const { action, message, token, refreshToken, userId, email } = response.data;
  
        setSnackbarMessage(message);
        setSnackbarSeverity("success");
        setOpenSnackbar(true);
  
        if (action === "redirect_to_2fa") {
          // 2FA is enabled, redirect to the 2FA page
          sessionStorage.setItem("userId", userId);
          sessionStorage.setItem("token", token);
          document.cookie = `userEmail=${email}; path=/; max-age=36000000;`;
  
          setTimeout(() => {
            navigate(`/enter-two-fa-code`); // Navigate to the 2FA input page
          }, 2000);
        } else if (action === "login_successful") {
          // No 2FA needed, proceed to the dashboard
          document.cookie = `token=${token}; path=/; max-age=3600`; // Set the login token
          document.cookie = `refreshToken=${refreshToken}; path=/; max-age=604800`; // Set the refresh token
  
          setSnackbarMessage("Login successful! Redirecting...");
          setSnackbarSeverity("success");
  
          setTimeout(() => {
            navigate("/dashboard"); // Redirect to the dashboard
          }, 2000);
        }
      } else {
        setSnackbarMessage("Google login failed. Please try again.");
        setSnackbarSeverity("error");
        setOpenSnackbar(true);
      }
    } catch (error) {
      console.error("Google login failed:", error);
      setSnackbarMessage("Google login failed. Please try again.");
      setSnackbarSeverity("error");
      setOpenSnackbar(true);
    }
  };  

  return (
    <Container component="main" maxWidth="xs">
      <CssBaseline />
      <Box
        sx={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "100vh", // Ensure the container takes up the full viewport height
        }}
      >
        <Avatar sx={{ m: 1, bgcolor: "primary.main" }}>
          <LockOutlined />
        </Avatar>
        <Typography variant="h5">Login</Typography>
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
            id="email"
            label="Student Email Address"
            name="email"
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <TextField
            margin="normal"
            required
            fullWidth
            id="password"
            name="password"
            label="Password"
            type={showPassword ? "text" : "password"} 
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
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
            onClick={handleLogin}
            disabled={loading}
          >
            {loading ? "Logging in..." : "Login"}
          </Button>

          <GoogleLogin
            onSuccess={handleGoogleLogin}
            onError={() => {
              setSnackbarMessage("Google login failed.");
              setSnackbarSeverity("error");
              setOpenSnackbar(true);
            }}
            useOneTap
            width="100%"
          />

          <Grid container justifyContent="center" sx={{ mt: 2 }}>
            <Grid item>
              <Link to="/register">Don't have an account? Register</Link>
            </Grid>
            <Grid item sx={{ ml: 3 }}>
              <Link to="/forgot_password">Forgot Your Password?</Link>
            </Grid>
          </Grid>

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

export default Login;
