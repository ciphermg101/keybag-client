import {
    Container,
    Box,
    Typography,
    Snackbar,
    Alert,
  } from "@mui/material";
  import { useState, useEffect } from "react";
  import { useNavigate, useParams } from "react-router-dom";
  import axiosInstance from "../utils/axiosInstance";
  
  const EmailVerificationPage = () => {
    const { token } = useParams();  // Get the token from the URL
    const navigate = useNavigate();
    const [message] = useState<string | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const [openSnackbar, setOpenSnackbar] = useState(false);
    const [snackbarMessage, setSnackbarMessage] = useState("");
    const [snackbarSeverity, setSnackbarSeverity] = useState<"success" | "error" | "info" | "warning">("info");
  
    useEffect(() => {
      const verifyEmail = async () => {
        try {
          // Make API call to verify email
          const response = await axiosInstance.get(`/auth/verify-email/${token}`);
  
          if (response.status === 200) {
            setSnackbarMessage("Email verified successfully! You can now log in.");
            setSnackbarSeverity("success");
            setOpenSnackbar(true);
            setTimeout(() => {
              navigate("/login");  // Redirect after 3 seconds
            }, 3000);
          } else {
            setSnackbarMessage("Something went wrong. Please try again.");
            setSnackbarSeverity("error");
            setOpenSnackbar(true);
          }
        } catch {
          setSnackbarMessage("Error verifying email. Please try again.");
          setSnackbarSeverity("error");
          setOpenSnackbar(true);
        } finally {
          setLoading(false);
        }
      };
  
      verifyEmail();
    }, [token, navigate]);
  
    return (
      <Container component="main" maxWidth="xs">
        <Box
          sx={{
            marginTop: 8,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
          }}
        >
          <Typography component="h1" variant="h5">
            Email Verification
          </Typography>
          <Box sx={{ mt: 3 }}>
            {loading ? (
              <Typography>Verifying your email...</Typography>
            ) : (
              <Typography>{message}</Typography>
            )}
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
  
  export default EmailVerificationPage;
  