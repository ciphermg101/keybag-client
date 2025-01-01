import { useState } from "react";
import { LockOutlined, Visibility, VisibilityOff } from "@mui/icons-material";
import {
  Container,
  CssBaseline,
  Box,
  Avatar,
  Typography,
  TextField,
  InputAdornment,
  Button,
  Snackbar,
  IconButton,
  Alert,
} from "@mui/material";
import { useNavigate } from "react-router-dom";
import axiosInstance from "../../utils/axiosInstance";
import { AxiosError } from "axios";
import { getAuthToken, getCsrfToken } from "../../utils/axiosInstance";

const ManageProfilePage: React.FC = () => {
  const [password, setPassword] = useState<string>("");
  const [confirmPassword, setConfirmPassword] = useState<string>("");
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [loading, setLoading] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState<string>("");
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [error, setError] = useState<string | null>(null); // To hold validation errors
  const [snackbarSeverity, setSnackbarSeverity] = useState<"success" | "error" | "info" | "warning">("info");

  const navigate = useNavigate(); // Initialize useNavigate hook

  // Form validation function
  const validateForm = (): string | null => {
    if (!password || !confirmPassword) {
      return "All fields are required.";
    }
    if (password !== confirmPassword) {
      return "Passwords do not match.";
    }
    return null;
  };

  const handlePasswordChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  };

  const handleConfirmPasswordChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setConfirmPassword(event.target.value);
  };

  const handleTogglePasswordVisibility = () => {
    setShowPassword((prevState) => !prevState);
  };

    const handleSave = async () => {
        setError(null); // Reset error message before validation

        const validationError = validateForm();
        if (validationError) {
            setError(validationError);
            setSnackbarMessage(validationError);
            setSnackbarSeverity("error");
            setOpenSnackbar(true);
            return; // Stop execution if form is invalid
        }
        setLoading(true);
        try {
            const csrfToken = await getCsrfToken();
            const authToken = getAuthToken();
            const response = await axiosInstance.put("account/change-password",{ newPassword: password },
                {
                    headers: {
                        "X-CSRF-Token": csrfToken,
                        "Authorization": `Bearer ${authToken}`,
                    },
                }
            );
            // Handle success response
            if (response.status === 200) {
                setSnackbarMessage("Password changed successfully!");
                setSnackbarSeverity("success");
            } else {
                setSnackbarMessage("Failed to change password.");
                setSnackbarSeverity("error");
            }
            setOpenSnackbar(true);
        } catch (error: unknown) {
            if (error instanceof AxiosError) {
                if (error.response) {
                    // Backend error (non-200 status code)
                    setSnackbarMessage("Failed to change password.");
                    setSnackbarSeverity("error");
                } else if (error.request) {
                    // No response received
                    setSnackbarMessage("No response received from server. Please try again.");
                    setSnackbarSeverity("error");
                } else {
                    // Error in setting up the request
                    setSnackbarMessage("An unexpected error occurred. Please try again.");
                    setSnackbarSeverity("error");
                }
            } else {
                // General error handling
                setSnackbarMessage("An unexpected error occurred. Please try again.");
                setSnackbarSeverity("error");
            }
            setOpenSnackbar(true);
        } finally {
            setLoading(false); // Stop loading state
        }
    };

    const handleBackToDashboard = () => {
        navigate("/dashboard"); // Navigate to the dashboard route
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
          minHeight: "100vh",
        }}
      >
        <Avatar sx={{ m: 1, bgcolor: "primary.main" }}>
          <LockOutlined />
        </Avatar>
        <Typography variant="h5">Manage Profile</Typography>
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
            label="Change Password"
            name="password"
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={handlePasswordChange}
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton onClick={handleTogglePasswordVisibility}>
                    {showPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
            error={!!error} // Highlight input with error
            helperText={error && error === "Passwords do not match." ? error : ""}
          />
          <TextField
            margin="normal"
            required
            fullWidth
            id="confirmPassword"
            label="Confirm Password"
            name="confirmPassword"
            type={showPassword ? "text" : "password"}
            value={confirmPassword}
            onChange={handleConfirmPasswordChange}
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton onClick={handleTogglePasswordVisibility}>
                    {showPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
            error={!!error} // Highlight input with error
            helperText={error && error === "Passwords do not match." ? error : ""}
          />
          <Button
            fullWidth
            variant="contained"
            sx={{ mt: 2 }}
            onClick={handleSave}
            disabled={loading}
          >
            {loading ? "Saving..." : "Save Changes"}
          </Button>
          <Button
            fullWidth
            variant="outlined"
            sx={{ mt: 2 }}
            onClick={handleBackToDashboard}
          >
            Back to Dashboard
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

export default ManageProfilePage;
