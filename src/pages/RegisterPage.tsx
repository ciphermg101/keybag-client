import {
  Avatar,
  Box,
  Button,
  Container,
  CssBaseline,
  Grid,
  TextField,
  Typography,
  Snackbar,
  InputAdornment,
  IconButton,
  Alert,
} from "@mui/material";
import { LockOutlined, Visibility, VisibilityOff } from "@mui/icons-material";
import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import axiosInstance, { getCsrfToken } from "../utils/axiosInstance";

interface FormData {
  username: string;
  email: string;
  password: string;
  confirmPassword: string;
}

const Register = () => {
  const [formData, setFormData] = useState<FormData>({
    username: "",
    email: "",
    password: "",
    confirmPassword: "",
  });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const navigate = useNavigate();
  const [csrfToken, setCsrfToken] = useState<string | undefined>(undefined);
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState("");
  const [showPassword, setShowPassword] = useState<boolean>(false); // Toggle for password visibility
  const [showConfirmPassword, setShowConfirmPassword] = useState<boolean>(false); // Toggle for confirm password visibility
  const [snackbarSeverity, setSnackbarSeverity] = useState<"success" | "error" | "info" | "warning">("info");

  useEffect(() => {
    // Fetch CSRF token once when the component mounts
    const fetchToken = async () => {
      try {
        const token = await getCsrfToken();
        setCsrfToken(token);
      } catch (error) {
        console.error("Failed to fetch CSRF token:", error);
        setError("Failed to fetch security token. Please try again.");
      }
    };
    fetchToken();
  }, []);

  // Improved email validation regex
  const validateForm = () => {
    if (!formData.username || !formData.email || !formData.password) {
      return "All fields are required.";
    }
    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(formData.email)) {
      return "Please enter a valid email address.";
    }
    if (formData.password.length < 8) {
      return "Password must be at least 8 characters long.";
    }
    if (formData.password !== formData.confirmPassword) {
      return "Passwords do not match.";
    }
    return null;
  };

  const handleRegister = async (event: React.MouseEvent<HTMLButtonElement>) => {
    event.preventDefault(); 
    setError(null);
    setLoading(true);

    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      setSnackbarMessage(validationError);
      setSnackbarSeverity("error");
      setOpenSnackbar(true);
      setLoading(false);
      return;
    }

    try {
      if (!csrfToken) {
        setError("CSRF token not found. Please try again.");
        setSnackbarMessage("CSRF token not found. Please try again.");
        setSnackbarSeverity("error");
        setOpenSnackbar(true);
        setLoading(false);
        return; // Early return if CSRF token is missing
      }

      const headers = {
        "X-CSRF-Token": csrfToken,
      };

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { confirmPassword, ...signupData } = formData;
      const response = await axiosInstance.post("/auth/signup", signupData, {
        withCredentials: true,  
        headers: headers, 
      });

      if (response.status === 201) {
        setSnackbarMessage("Registration successful! Please check your email to verify your account.");
        setSnackbarSeverity("success");
        setOpenSnackbar(true);
        setTimeout(() => {
          navigate("/login");  // Redirect after 3 seconds
        }, 3000);
      } else if (response.status === 400) {
        // Handle "User already registered" case (conflict)
        setSnackbarMessage("User already registered. Please login.");
        setSnackbarSeverity("warning");
        setOpenSnackbar(true);
      } else if (response.status === 403) {
        setSnackbarMessage("You are not authorized to perform this action.");
        setSnackbarSeverity("error");
        setOpenSnackbar(true);
      } else {
        setSnackbarMessage("An unexpected error occurred.");
        setSnackbarSeverity("error");
        setOpenSnackbar(true);
      }
    } catch (error) {
      setLoading(false);

      // Enhanced error handling
      if (axios.isAxiosError(error)) {
        if (error.response) {
          // Server-side error (e.g., 400, 500, etc.)
          if (error.response.status === 400) {
            setSnackbarMessage("User already registered. Please login.");
            setSnackbarSeverity("warning");
          } else {
            setSnackbarMessage("An unexpected error occurred.");
            setSnackbarSeverity("error");
          }
        } else if (error.request) {
          // No response received from server
          setSnackbarMessage("Network error. Please try again later.");
          setSnackbarSeverity("error");
        } else {
          // Something went wrong during setup of the request
          setSnackbarMessage("An unexpected error occurred.");
          setSnackbarSeverity("error");
        }
      } else {
        // Unknown error type
        setSnackbarMessage("An unknown error occurred.");
        setSnackbarSeverity("error");
      }
      setOpenSnackbar(true);
    } finally {
      setLoading(false);
    }
  };

  // Handle form input change
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  // Handle password visibility toggle
  const handleTogglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  // Handle confirm password visibility toggle
  const handleToggleConfirmPasswordVisibility = () => {
    setShowConfirmPassword(!showConfirmPassword);
  };

  // Show loading spinner or error message if CSRF token is not yet fetched
  if (!csrfToken) {
    return <Typography>Loading...</Typography>;
  }

  return (
    <Container component="main" maxWidth="xs">
      <CssBaseline />
      <Box
        sx={{
          marginTop: 8,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <Avatar sx={{ m: 1 }}>
          <LockOutlined />
        </Avatar>
        <Typography component="h1" variant="h5">
          Register
        </Typography>
        <Box component="form" noValidate sx={{ mt: 3 }}>
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <TextField
                label="Registration Number"
                fullWidth
                name="username"
                value={formData.username}
                onChange={handleChange}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                label="Student Email Address"
                fullWidth
                name="email"
                value={formData.email}
                onChange={handleChange}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                label="Password"
                type={showPassword ? "text" : "password"}
                fullWidth
                name="password"
                value={formData.password}
                onChange={handleChange}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton onClick={handleTogglePasswordVisibility}>
                        {showPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                label="Confirm Password"
                type={showConfirmPassword ? "text" : "password"}
                fullWidth
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton onClick={handleToggleConfirmPasswordVisibility}>
                        {showConfirmPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />
            </Grid>
          </Grid>
          <Button
            type="button"
            fullWidth
            variant="contained"
            sx={{ mt: 3, mb: 2 }}
            onClick={handleRegister}
            disabled={loading || !csrfToken} // Disable if loading or csrfToken is not available
          >
            {loading ? "Registering..." : "Register"}
          </Button>
          {error && <Typography color="error">{error}</Typography>}
          <Grid container justifyContent="flex-end">
            <Grid item>
              <Link to="/login">Already have an account? Sign in</Link>
            </Grid>
          </Grid>
        </Box>
      </Box>

      {/* Snackbar for success or error messages */}
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

export default Register;
