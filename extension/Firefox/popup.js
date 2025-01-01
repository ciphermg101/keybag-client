// Base URL for API requests
const baseURL = 'http://localhost:3000/';

// Helper function to construct full URLs
const getFullUrl = (path) => new URL(path, baseURL).href;

// Cache DOM elements
const masterPasswordForm = document.getElementById('master-password-form');
const googleLoginBtn = document.getElementById('login-with-google-btn');
const statusText = document.getElementById('status');
const welcomeMessage = document.getElementById('welcome-message');

// Initialize the popup
masterPasswordForm.addEventListener('submit', handleMasterPasswordLogin);
googleLoginBtn.addEventListener('click', initializeGoogleAuth);
document.addEventListener('DOMContentLoaded', displayWelcomeMessage);

// Loading state functions
function showLoadingState(button) {
  button.disabled = true;
  button.innerHTML = '<span class="spinner"></span> Loading...';
}

function resetButton(button, text = 'Login with Google') {
  button.disabled = false;
  button.innerHTML = text;
}

// Logging utility functions
function logError(context, error) {
  console.error(`[${context}]`, error);
}

function logInfo(context, message, additionalData = null) {
  if (additionalData) {
    console.info(`[${context}] ${message}`, additionalData);
  } else {
    console.info(`[${context}] ${message}`);
  }
}

// Optimized CSRF token caching
let csrfTokenCache = null;
let csrfTokenTimestamp = 0;

const getCsrfToken = async () => {
  const now = Date.now();
  if (csrfTokenCache && (now - csrfTokenTimestamp < 5 * 60 * 1000)) {
    return csrfTokenCache;
  }

  try {
    const csrfResponse = await fetch(getFullUrl('/csrf-token'), {
      method: 'GET',
      credentials: 'include',
    });

    if (!csrfResponse.ok) {
      throw new Error(`Failed to fetch CSRF token: ${csrfResponse.statusText}`);
    }

    const { csrfToken } = await csrfResponse.json();
    csrfTokenCache = csrfToken;
    csrfTokenTimestamp = now;
    return csrfTokenCache;
  } catch (error) {
    logError('CSRF', error);
    return null;
  }
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getCsrfToken') {
    getCsrfToken()
      .then((csrfToken) => {
        if (csrfToken) {
          sendResponse({ csrfToken });
        } else {
          console.warn('CSRF token retrieval failed or returned null');
          sendResponse({ error: 'Failed to retrieve CSRF token' });
        }
      })
      .catch((error) => {
        console.error('Error fetching CSRF token:', error);
        sendResponse({ error: 'Error fetching CSRF token' });
      });
    return true;
  }
});

const getAccessToken = () => {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(['accessToken'], (result) => {
      const token = result.accessToken;

      if (!token) {
        console.error('No access token found in chrome.storage.local');
        reject('No access token found');
      } else {
        resolve(token);
      }
    });
  });
};

const parseJwt = (token) => {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = atob(base64);
  return JSON.parse(decodeURIComponent(escape(jsonPayload)));
};

async function initializeGoogleAuth() {
  showLoadingState(googleLoginBtn);

  try {
    const csrfToken = await getCsrfToken();
    if (!csrfToken) throw new Error('CSRF token is not available');

    const clientIdResponse = await fetch(getFullUrl('/api/google-client-id'), {
      method: 'GET',
      headers: { 'X-CSRF-Token': csrfToken },
    });

    if (!clientIdResponse.ok) {
      throw new Error('Failed to fetch Google client ID');
    }

    const { client_id } = await clientIdResponse.json();

    const nonce = Math.random().toString(36).substring(2);
    sessionStorage.setItem('nonce', nonce);

    const redirectUri = `moz-extension://32e7c3a9-af2e-448f-b769-dc76127e9f8d/manifest.json`;
    const oauthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
      `client_id=${client_id}&` +
      `response_type=id_token&` +
      `scope=profile email&` +
      `redirect_uri=${redirectUri}&` +
      `nonce=${nonce}`;

    chrome.identity.launchWebAuthFlow(
      { url: oauthUrl, interactive: true },
      function (redirectUrl) {
        if (!redirectUrl) {
          console.error('No redirect URL received');
          resetButton(googleLoginBtn);
          return;
        }

        const urlHash = new URL(redirectUrl).hash;
        if (!urlHash) {
          console.error('No URL hash found in redirect URL');
          return;
        }

        const urlParams = new URLSearchParams(urlHash.substring(1));
        const idToken = urlParams.get('id_token');
        if (idToken) {
          const decodedToken = parseJwt(idToken);
          const returnedNonce = decodedToken.nonce;
          const storedNonce = sessionStorage.getItem('nonce');

          if (returnedNonce !== storedNonce) {
            console.error('Nonce mismatch: potential replay attack');
          } else {
            onGoogleSignInWithIdToken(idToken);
          }
        } else {
          console.error('Google OAuth failed: No id_token received');
        }

        sessionStorage.removeItem('nonce');
      }
    );
  } catch (error) {
    logError('GoogleAuth', error);
    resetButton(googleLoginBtn);
  }
}

async function onGoogleSignInWithIdToken(idToken) {
  try {
    const csrfToken = await getCsrfToken();
    const res = await fetch(getFullUrl('/auth/login/google'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ googleToken: idToken }),
      credentials: 'include',
    });

    const data = await res.json();
    if (res.ok) {
      const loginTimestamp = Date.now();
      chrome.storage.local.set({
        loginTimestamp:loginTimestamp,
        accessToken: data.token,
        deviceId: data.deviceId,
        googleEmail: data.email,
      }, () => {
        displayWelcomeMessage();
        statusText.textContent = "Google login successful. Autofill is ready!";
        initializeAutoFill();
      });
    } else {
      statusText.textContent = data.message || "Google login failed. Please try again.";
    }
  } catch (error) {
    logError('GoogleLogin', error);
    statusText.textContent = 'Google login failed. Please try again.';
  } finally {
    resetButton(googleLoginBtn);
  }
}

async function displayWelcomeMessage() {
  chrome.storage.local.get(['googleEmail'], ({ googleEmail }) => {
    if (googleEmail) {
      welcomeMessage.textContent = `Welcome, ${googleEmail}`;
    } else {
      chrome.storage.local.get(['userEmail'], ({ userEmail }) => {
        if (userEmail) {
          welcomeMessage.textContent = `Welcome, ${userEmail}`;
        } else {
          welcomeMessage.textContent = 'Welcome! Please log in.';
        }
      });
    }
  });
}

async function handleMasterPasswordLogin(event) {
  event.preventDefault();
  const masterPassword = document.getElementById('master-password').value;
  const masterPasswordBtn = document.getElementById('master-password-btn');
  showLoadingState(masterPasswordBtn);

  try {
    const csrfToken = await getCsrfToken();

    // Retrieve the userEmail from cookies
    async function getUserEmailFromCookies(domain) {
      return new Promise((resolve, reject) => {
        chrome.cookies.get({ url: domain, name: 'userEmail' }, (cookie) => {
          if (cookie) {
            resolve(cookie.value);
          } else {
            reject('No email found in cookies');
          }
        });
      });
    }
    const domain = 'http://localhost:5173/';
    const storedEmail = await getUserEmailFromCookies(domain);
    if (storedEmail) {
      console.log('Email retrieved from cookie:', storedEmail);
    } else {
      console.log('No email found in cookies');
    }

    // Ensure that userEmail and masterPassword are sent in the correct format
    const response = await fetch(getFullUrl('auth/login'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({
        email: storedEmail,
        password: masterPassword,
      }),
      credentials: 'include',
    });

    const data = await response.json();
    if (response.ok) {
      const loginTimestamp = Date.now();
      chrome.storage.local.set(
        {
          loginTimestamp,
          accessToken: data.token,
          deviceId: data.deviceId,
          userEmail: data.email, // Store the decrypted email
        },
        () => {
          displayWelcomeMessage();
          statusText.textContent = 'Master password login successful. Autofill is ready!';
          initializeAutoFill();
        }
      );
    } else {
      statusText.textContent = data.message || 'Invalid master password.';
    }
  } catch (error) {
    logError('MasterPasswordLogin', error);
    statusText.textContent = 'Error during login.';
  } finally {
    resetButton(masterPasswordBtn, 'Login');
  }
}

async function fetchCredentialsForSite() {
  try {
    // Retrieve the siteUrl from chrome.storage.local
    const { siteUrl } = await new Promise((resolve) => {
      chrome.storage.local.get(['siteUrl'], (result) => resolve(result));
    });

    if (!siteUrl) {
      statusText.textContent = 'No site URL available.';
      return null;
    }

    // Normalize the siteUrl: trim, convert to lowercase, and remove trailing slash if any
    const normalizedSiteUrl = siteUrl.trim().toLowerCase().replace(/\/$/, '');

    const userEmail = await new Promise((resolve) => {
      chrome.storage.local.get(['userEmail'], ({ userEmail }) => resolve(userEmail));
    });

    if (!userEmail) {
      statusText.textContent = 'Session expired. Please log in again.';
      return null;
    }

    const csrfToken = await getCsrfToken();
    const accessToken = await getAccessToken();

    if (!csrfToken || !accessToken) throw new Error('Authentication tokens are unavailable.');
    
    // Send the request with the normalized siteUrl
    const response = await fetch(getFullUrl(`/account/get-credentials?site_url=${encodeURIComponent(normalizedSiteUrl)}`), {
      method: 'GET',
      headers: {
        'X-CSRF-Token': csrfToken,
        'Authorization': `Bearer ${accessToken}`,
      },
      credentials: 'include',
    });

    const data = await response.json();
    if (response.ok) {
      return data;
    } else {
      logError('Credentials', `Failed to fetch credentials: ${data.message || 'Unknown error'}`);
      statusText.textContent = 'No credentials found for this site.';
      return null;
    }
  } catch (error) {
    logError('FetchCredentials', error);
    statusText.textContent = 'Error fetching credentials.';
    return null;
  }
}

async function initializeAutoFill() {
  try {
    const credentials = await fetchCredentialsForSite();

    if (credentials && credentials.length > 0) {
      const { username, password } = credentials[0];

      chrome.runtime.sendMessage(
        {
          action: 'autofillCredentials', 
          credential: { username, password },
        },
        (response) => {
          if (response && response.success) {
            statusText.textContent = 'Credentials auto-filled successfully. Closing popup...';

            setTimeout(() => {
              window.close();
            }, 1000); 
          } else {
            statusText.textContent = `Auto-fill failed: ${response.error || 'Unknown error'}`;
          }
        }
      );
    } else {
      statusText.textContent = 'No credentials found for this site. Please ensure you have saved credentials.';
    }
  } catch (error) {
    logError('AutoFill', error);
    statusText.textContent = `Error during auto-fill: ${error.message || 'Unexpected error occurred'}`;
  }
}
