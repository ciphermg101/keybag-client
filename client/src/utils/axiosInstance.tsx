import axios, { AxiosInstance, InternalAxiosRequestConfig, AxiosError } from 'axios';
import getAuthToken  from './authTokenUtils'; // Only import the function, not the cache
const baseURL: string = import.meta.env.REACT_APP_BACKEND_URL || 'http://localhost:3000';

// CSRF Token logic
let csrfTokenCache: string | null = null;

// Function to get CSRF Token
const getCookieByName = (name: string): string | undefined => {
    const cookies = document.cookie.split("; ");
    for (const cookie of cookies) {
        const [key, value] = cookie.split("=");
        if (key === name) {
            return decodeURIComponent(value); // Decode in case of URL-encoded characters
        }
    }
    return undefined;
};

const getCsrfToken = async (): Promise<string | undefined> => {
    if (csrfTokenCache) {
        console.log("Returning cached CSRF token:", csrfTokenCache);
        return csrfTokenCache;
    }

    // Get the CSRF token directly by its name
    const csrfToken = getCookieByName("XSRF-TOKEN");
    if (csrfToken) {
        csrfTokenCache = csrfToken;
        console.log("Extracted CSRF token from cookies:", csrfTokenCache);
        return csrfTokenCache;
    }

    console.error("CSRF token not found in cookies");
    return undefined;
};

// Axios Instance
const axiosInstance: AxiosInstance = axios.create({
    baseURL,
    timeout: 5000,
    headers: { 'Content-Type': 'application/json' },
    withCredentials: true,
});

// Flag to track the state of the refresh token process
let isRefreshing = false;
let failedQueue: Array<{ resolve: (token: string) => void; reject: (error: AxiosError) => void }> = [];

// Process the queue after the token is refreshed
const processQueue = (error: AxiosError | null, token: string | null) => {
    failedQueue.forEach((prom) => {
        if (token) {
            prom.resolve(token); // Resolve all the failed requests with the new token
        } else if (error) {
            prom.reject(error); // Reject failed requests if token refresh failed
        }
    });

    failedQueue = []; // Reset the failed queue
};

// Extend Axios Request Configuration to include _retry property
interface ExtendedAxiosRequestConfig extends InternalAxiosRequestConfig {
    _retry?: boolean;
}

// Request interceptor for adding tokens
axiosInstance.interceptors.request.use(
    async (config: ExtendedAxiosRequestConfig) => {
        try {
            const csrfToken = await getCsrfToken();
            const authToken = await getAuthToken(); // Ensure we await the token fetch

            if (csrfToken) config.headers['X-CSRF-Token'] = csrfToken;
            if (authToken) config.headers['Authorization'] = `Bearer ${authToken}`;

            return config;
        } catch (error) {
            console.error('Error in request interceptor:', error);
            return Promise.reject(error); // Reject the request in case of errors
        }
    },
    (error) => {
        console.error('Request Interceptor Error:', error);
        return Promise.reject(error);
    }
);

// Response interceptor for handling 498 errors
axiosInstance.interceptors.response.use(
    (response) => response,
    async (error) => {
        const originalRequest = error.config as ExtendedAxiosRequestConfig;

        if (axios.isAxiosError(error) && error.response?.status === 498 && !originalRequest._retry) {
            if (isRefreshing) {
                // If a refresh is already in progress, add the request to the failed queue
                return new Promise((resolve, reject) => {
                    failedQueue.push({ resolve, reject });
                });
            }

            originalRequest._retry = true;
            isRefreshing = true;

            try {
                const response = await axios.post<{ token: string }>(
                    `${baseURL}/auth/refresh-token`,
                    {},
                    { withCredentials: true }
                );
                const { token } = response.data;

                if (token) {
                    // Do not directly mutate authTokenCache here
                    axiosInstance.defaults.headers['Authorization'] = `Bearer ${token}`;
                    originalRequest.headers['Authorization'] = `Bearer ${token}`;
                    processQueue(null, token); // Resolve all the failed requests
                    return axiosInstance(originalRequest); // Retry the failed request with the new token
                }
            } catch (err) {
                processQueue(error, null); // Reject all failed requests if token refresh fails
                console.error('Token refresh failed:', err);
                window.location.href = '/login'; // Redirect to login
            } finally {
                isRefreshing = false;
            }
        }

        return Promise.reject(error);
    }
);

export default axiosInstance;
export { getCsrfToken, getAuthToken }; // Export the functions for use in other components
