chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case 'log':
      handleLogAction(sendResponse);
      break;

    case 'debug':
      handleDebugAction(message, sendResponse);
      break;

    case 'fetchAndOpenPopup':
      handleFetchAndOpenPopup(sendResponse);
      break;

    case 'autofillCredentials':
      handleAutofillCredentials(message, sendResponse);
      break;

    case 'showCredentialSelection':
      handleShowCredentialSelection(message, sendResponse);
      break;

    default:
      sendResponse({ success: false, error: 'Unknown action' });
      break;
  }
  return true; // Keep the message channel open for async response
});

// Handle 'log' action
function handleLogAction(sendResponse) {
  sendResponse({ success: true, message: 'Logged successfully.' });
}

// Handle 'debug' action
function handleDebugAction(message, sendResponse) {
  console.debug(message.data || 'Debugging information unavailable');
  sendResponse({ success: true, message: 'Debugging complete.' });
}

// Handle 'fetchAndOpenPopup' action
function handleFetchAndOpenPopup(sendResponse) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      const siteUrl = tabs[0].url;
      const tabId = tabs[0].id;

      // Store both siteUrl and tabId in chrome.storage.local
      chrome.storage.local.set({ siteUrl, tabId }, () => {

        // Open the popup after storing the site URL and tab ID
        chrome.windows.create({
          url: chrome.runtime.getURL('popup.html'),
          type: 'popup',
          width: 360,
          height: 360,
        });

        sendResponse({ success: true, message: 'Popup opened with site URL and tab ID stored.' });
      });
    } else {
      sendResponse({ success: false, error: 'No active tab found.' });
    }
  });
  return true; // Keep the channel open for async response
}

// Handle 'showCredentialSelection' action
function handleShowCredentialSelection(message, sendResponse) {
  if (Array.isArray(message.credentials) && message.fields) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      chrome.tabs.sendMessage(tabs[0].id, { action: 'showCredentialSelection', credentials: message.credentials, fields: message.fields }, (response) => {
        if (response && response.success) {
          sendResponse({ success: true });
        } else {
          sendResponse({ success: false, error: 'Failed to show credential selection' });
        }
      });
    });
  } else {
    sendResponse({ success: false, error: 'Invalid credentials or fields' });
  }
  return true; // Keep the message channel open
}

// Handle 'autofillCredentials' action
function handleAutofillCredentials(message, sendResponse) {
  const { username, password } = message.credential;
  
  // Retrieve the stored tabId from chrome.storage.local
  chrome.storage.local.get(['tabId'], (result) => {
    const tabId = result.tabId;

    if (tabId) {
      // Send message to content script to autofill credentials for the stored tab ID
      chrome.tabs.sendMessage(
        tabId,
        {
          action: 'autofillCredentials',
          credential: { username, password },
        },
        (response) => {
          if (chrome.runtime.lastError) {
            console.error('Error sending message to content script:', chrome.runtime.lastError);
            sendResponse({ success: false, error: 'Error sending message to content script' });
            return;
          }

          if (response && response.success) {
            sendResponse({ success: true });
          } else {
            console.error('Failed to autofill credentials in content script.');
            sendResponse({ success: false, error: 'Failed to autofill credentials' });
          }
        }
      );
    } else {
      console.error('No stored tab ID found in chrome storage.');
      sendResponse({ success: false, error: 'No stored tab ID found' });
    }
  });

  return true; // Keep the message channel open for async response
}