// background.js
// Service worker for AutoShield Chrome Extension
// Handles side panel opening and message routing between content script and side panel

chrome.runtime.onInstalled.addListener(async () => {
  console.log('[AutoShield] Extension installed / updated');

  try {
    await chrome.sidePanel.setPanelBehavior({
      openPanelOnActionClick: true
    });
    console.log('[AutoShield] Side panel behavior set');
  } catch (e) {
    console.error('[AutoShield] Failed to set panel behavior:', e);
  }
});

// Open side panel when the toolbar icon is clicked
chrome.action.onClicked.addListener(async (tab) => {
  try {
    await chrome.sidePanel.open({ tabId: tab.id });
  } catch (e) {
    console.warn('[AutoShield] Side panel open failed:', e);
  }
});

// Enable side panel for all URLs
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

// ─── Message Router ─────────────────────────────────────────────────────────
// Routes messages from content script → side panel and vice versa

let sidePanelPort = null;

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'autoshield-sidepanel') {
    sidePanelPort = port;
    port.onDisconnect.addListener(() => {
      sidePanelPort = null;
    });
    port.onMessage.addListener((msg) => {
      // Side panel → content script (e.g., trigger extraction)
      handleSidePanelMessage(msg);
    });
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Content script → side panel
  if (msg.source === 'autoshield-content') {
    if (sidePanelPort) {
      sidePanelPort.postMessage(msg);
    }
    sendResponse({ ok: true });
    return true;
  }
});

function sendStep(step) {
  if (sidePanelPort) {
    sidePanelPort.postMessage({ type: 'progress', step });
  }
}

async function handleSidePanelMessage(msg) {
  if (msg.type === 'triggerExtraction') {
    try {
      sendStep('🚀 Starting scan...');
      
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (tab?.id) {
        sendStep('📄 Extracting page data...');

        chrome.tabs.sendMessage(tab.id, { type: 'extractPageData' }, (response) => {

          if (chrome.runtime.lastError) {
            sendStep('⚙️ Injecting content script...');

            chrome.scripting.executeScript({
              target: { tabId: tab.id },
              files: ['content.js']
            }).then(() => {
              setTimeout(() => {
                sendStep('📄 Extracting after injection...');
                chrome.tabs.sendMessage(tab.id, { type: 'extractPageData' });
              }, 500);
            });

          } else {
            sendStep('📦 Page data extracted');
          }
        });
      }

    } catch (e) {
      sendStep('❌ Extraction failed');
      console.warn('[AutoShield BG] triggerExtraction error:', e);
    }
  }
}