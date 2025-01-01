import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { GoogleOAuthProvider } from '@react-oauth/google';
import LandingPage from './pages/LandingPage';
import AboutPage from './pages/AboutPage';
import LoginPage from './pages/LoginPage';
import Register from './pages/RegisterPage';
import ForgotPasswordPage from './pages/ForgetPasswordPage';
import Dashboard from './pages/DashboardPage';
import PrivateRoute from './utils/PrivateRoute';
import ResetPassword from './pages/ResetPassword';
import EmailVerificationPage from './pages/EmailVerificationPage';
import ManageProfilePage from './pages/components/ManageProfilePage';
import EnableTwoFactorAuth from './pages/components/EnableTwoFactorAuth';
import Enter2FACode from './pages/components/Enter2FACode';

const App: React.FC = () => {
    const username = "User"; 
    const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;

    // Fallback for missing clientId
    if (!googleClientId) {
        console.error("Google client ID is not set. Please check your .env file.");
        return <div>Error: Google client ID is missing.</div>;
    }

    return (
        <GoogleOAuthProvider clientId={googleClientId}> {/* Wrap the app with GoogleOAuthProvider */}
            <Router>
                <Routes>
                    <Route path="/" element={<LandingPage />} />
                    <Route path="/about" element={<AboutPage />} />
                    <Route path="/login" element={<LoginPage />} />
                    <Route path="/register" element={<Register />} />
                    <Route path="/verify-email/:token" element={<EmailVerificationPage />} />
                    <Route path="/forgot_password" element={<ForgotPasswordPage />} />
                    <Route path="/reset-password/:token" element={<ResetPassword />} />

                    
                    {/* Wrap Dashboard route with PrivateRoute */}
                    <Route 
                        path="/dashboard" 
                        element={
                            <PrivateRoute>
                                <Dashboard 
                                    username={username} 
                                    onLogout={() => { 
                                    }} 
                                />
                            </PrivateRoute>
                        } 
                    />
                    <Route 
                        path="/manage-profile" 
                        element={
                            <PrivateRoute>
                                <ManageProfilePage />
                            </PrivateRoute>
                        } 
                    />
                    <Route 
                        path="/manage-two-fa" 
                        element={
                            <PrivateRoute>
                                <EnableTwoFactorAuth />
                            </PrivateRoute>
                        } 
                    />
                    <Route 
                        path="/enter-two-fa-code" 
                        element={
                            <PrivateRoute>
                                <Enter2FACode />
                            </PrivateRoute>
                        } 
                    />
                </Routes>
            </Router>
        </GoogleOAuthProvider>
    );
};

export default App;
