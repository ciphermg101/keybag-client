const baseURL: string = import.meta.env.REACT_APP_BACKEND_URL || 'http://localhost:3000';

export let authTokenCache: string | null = null;

// CSRF Token logic
let csrfTokenCache: string | null = null;
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

// Function to get Auth Token
const getAuthToken = async (retryDelay: number = 1000): Promise<string | null> => {
  if (authTokenCache) return authTokenCache;

  let attempt = 0;
  const maxRetries = 2; // 1 initial attempt + 1 retry
  const csrfToken = await getCsrfToken();

  while (attempt < maxRetries) {
    try {
      const headers: HeadersInit = {};
      
      // Add the CSRF token to headers if available
      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }

      const response = await fetch(`${baseURL}/auth/get-token`, {
        method: 'GET',
        credentials: 'include',
        headers,
      });

      if (!response.ok) {
        throw new Error('Failed to fetch token');
      }

      const data = await response.json();
      authTokenCache = data.token;
      return authTokenCache; // Return the token if successful
    } catch (error) {
      attempt++;
      console.error(`Attempt ${attempt} - Error fetching token:`, error instanceof Error ? error.message : error);

      if (attempt < maxRetries) {
        console.log(`Retrying in ${retryDelay}ms...`);
        await new Promise((resolve) => setTimeout(resolve, retryDelay)); // Wait before retrying
      }
    }
  }

  // If we exhaust all attempts, return null to indicate failure
  console.error('Max retries reached. Could not fetch token.');
  return null;
};

export default getAuthToken;
