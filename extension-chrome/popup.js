// popup.js
// AutoShield Popup — opens the side panel where all analysis lives.
// The popup is now just a launcher; the sidepanel is the real UI.

document.addEventListener('DOMContentLoaded', () => {
  const statusDiv = document.getElementById('status');

  // Open side panel immediately when popup loads
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const tab = tabs[0];
    if (!tab) return;

    const url = tab.url || '';

    // Can't scan chrome:// or extension pages
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
      statusDiv.innerText = 'Cannot scan browser internal pages.';
      statusDiv.style.color = '#cc7700';
      return;
    }

    try {
      await chrome.sidePanel.open({ tabId: tab.id });
      // Popup will close itself when side panel opens — this is expected Chrome behaviour
    } catch (e) {
      statusDiv.innerText = 'Open the side panel from the toolbar icon.';
      statusDiv.style.color = '#886000';
    }
  });

  // Fallback scan button still works for quick backend ping
  const scanBtn = document.getElementById('scanBtn');
  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      statusDiv.innerText = 'Opening side panel...';
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id) {
        try {
          await chrome.sidePanel.open({ tabId: tab.id });
        } catch (e) {
          statusDiv.innerText = 'Click the AutoShield icon in the toolbar to open the panel.';
          statusDiv.style.color = '#cc7700';
        }
      }
    });
  }
});