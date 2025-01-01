import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axiosInstance from './axiosInstance';
import axios, { AxiosError } from 'axios';

const PrivateRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const navigate = useNavigate();
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);

  useEffect(() => {
    let isMounted = true; // Track if component is still mounted

    // Function to fetch token from the backend
    const fetchToken = async (): Promise<string | null> => {
      try {
        const response = await axiosInstance.get('/auth/get-token', {
          withCredentials: true, // Ensures cookies are sent with the request
        });

        if (response.status === 200) {
          return response.data.token;
        } else {
          throw new Error('Failed to fetch token');
        }
      } catch (error: unknown) {
        if (axios.isAxiosError(error)) {
          const axiosError = error as AxiosError;
          console.error('Error fetching token:', axiosError.response ? axiosError.response.data : axiosError.message);
        } else {
          console.error('Unexpected error:', error);
        }
        return null; // Return null to indicate failure
      }
    };

    // Function to check authentication status
    const checkAuth = async () => {
      try {
        const authToken = await fetchToken();
        
        if (!authToken) {
          console.error('Access denied: Token not found');
          if (isMounted) setIsAuthenticated(false);
          navigate('/login'); // Redirect to login if no token
          return;
        }

        // Use the token for authorization
        await axiosInstance.get('/account/check-auth', {
          headers: { Authorization: `Bearer ${authToken}` },
          withCredentials: true,
        });

        if (isMounted) setIsAuthenticated(true); // User is authenticated
      } catch (error) {
        console.error('Access denied: You are not logged in', error);
        if (isMounted) {
          setIsAuthenticated(false);
          navigate('/login'); // Redirect to login if not authenticated
        }
      }
    };

    checkAuth();

    return () => {
      isMounted = false; // Cleanup flag on unmount
    };
  }, [navigate]);

  if (isAuthenticated === null) return <div>Loading...</div>; // Loading state

  return isAuthenticated ? <>{children}</> : null; // Render children if authenticated
};

export default PrivateRoute;
