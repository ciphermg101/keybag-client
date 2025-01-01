import React, { useState } from "react";
import { Switch, Snackbar, Alert, CircularProgress, Typography } from "@mui/material";
import axiosInstance from "../../utils/axiosInstance";
import { AxiosError } from "axios";

const TwoFactorAuthToggle: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [is2FAEnabled, setIs2FAEnabled] = useState(false);
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null);
  const [snackbarMessage, setSnackbarMessage] = useState<string>("");
  const [snackbarSeverity, setSnackbarSeverity] = useState<"success" | "error" | "info" | "warning">("info");
  const [openSnackbar, setOpenSnackbar] = useState(false);

  const handleToggle2FA = async (enabled: boolean) => {
    setLoading(true);
    setQrCodeUrl(null);

    try {
      const endpoint = enabled ? "/account/enable-2fa" : "/account/disable-2fa";
      const response = await axiosInstance.post(endpoint);

      if (response.status === 200) {
        setIs2FAEnabled(enabled);

        if (enabled) {
          setQrCodeUrl(response.data.qrCodeUrl);
          setSnackbarMessage("Two-factor authentication enabled successfully.");
        } else {
          setSnackbarMessage("Two-factor authentication disabled successfully.");
        }
        setSnackbarSeverity("success");
      } else {
        setSnackbarMessage(`Failed to ${enabled ? "enable" : "disable"} 2FA.`);
        setSnackbarSeverity("error");
      }
    } catch (error: unknown) {
      if (error instanceof AxiosError) {
        if (error.response) {
          setSnackbarMessage(`Failed to ${enabled ? "enable" : "disable"} 2FA. Please try again.`);
        } else if (error.request) {
          setSnackbarMessage("No response received from the server. Please try again.");
        } else {
          setSnackbarMessage("An unexpected error occurred. Please try again.");
        }
      } else {
        setSnackbarMessage("An unexpected error occurred. Please try again.");
      }
      setSnackbarSeverity("error");
    } finally {
      setOpenSnackbar(true);
      setLoading(false);
    }
  };

  return (
    <div>
      <Typography variant="h6" gutterBottom>
        Two-Factor Authentication
      </Typography>
      <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        <Switch
          checked={is2FAEnabled}
          onChange={(e) => handleToggle2FA(e.target.checked)}
          disabled={loading}
          color="primary"
        />
        {loading && <CircularProgress size={24} />}
        <Typography variant="body1">{is2FAEnabled ? "Enabled" : "Disabled"}</Typography>
      </div>

      {qrCodeUrl && is2FAEnabled && (
        <div>
          <Typography variant="h6" sx={{ mt: 2 }}>
            Scan the QR code below with your authenticator app:
          </Typography>
          <img src={qrCodeUrl} alt="QR code for 2FA" />
        </div>
      )}

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
    </div>
  );
};

export default TwoFactorAuthToggle;
