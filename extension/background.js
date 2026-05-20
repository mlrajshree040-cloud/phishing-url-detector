// background.js – Combined phishing detector service worker

const API_URL = "http://127.0.0.1:5001/scan";   // change to your deployed URL later

// ========== Helper: call the API and return parsed data ==========
async function scanUrl(url) {
  const response = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ url: url })
  });
  const data = await response.json();
  if (data.error) throw new Error(data.error);
  return data;
}

// ========== 1. Context menu for right‑click link checking ==========
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "checkPhishing",
    title: "Check this link with Phishing Detector",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "checkPhishing") {
    const linkUrl = info.linkUrl;
    try {
      const result = await scanUrl(linkUrl);
      // Try to send the result to the content script of the current tab
      chrome.tabs.sendMessage(tab.id, {
        action: "showManualCheckResult",
        url: linkUrl,
        riskLevel: result.risk_level,
        riskScore: result.risk_score,
        issues: result.issues || [],
        warnings: result.warnings || []
      }).catch(() => {
        // Content script not reachable – fallback to notification
        showNotificationFromResult(linkUrl, result);
      });
    } catch (error) {
      showNotification("Error", error.message || "Could not scan the link.", "error");
    }
  }
});

// Fallback notification when content script is unavailable
function showNotificationFromResult(url, data) {
  const riskLevel = data.risk_level || "UNKNOWN";
  let message = "";
  let iconUrl = "";

  if (riskLevel === "SAFE") {
    message = "✅ This link appears safe.";
    iconUrl = "icon128.png";
  } else if (riskLevel === "MEDIUM_RISK") {
    message = "⚠️ This link looks suspicious. Be careful.";
    iconUrl = "icon48.png";
  } else if (riskLevel === "DANGEROUS") {
    message = "🔴 DANGEROUS! Do NOT open this link.";
    iconUrl = "icon128.png";
  } else {
    message = `Risk level: ${riskLevel}`;
    iconUrl = "icon48.png";
  }

  showNotification("Phishing Detector Result", message, iconUrl);
}

function showNotification(title, message, iconUrl) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: iconUrl,
    title: title,
    message: message,
    priority: 2
  });
}

// ========== 2. Real‑time detection: listen to messages from content script ==========
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkUrl") {
    const url = request.url;

    scanUrl(url)
      .then(data => {
        sendResponse({
          riskLevel: data.risk_level,
          riskScore: data.risk_score,
          issues: data.issues || [],
          warnings: data.warnings || []
        });
      })
      .catch(error => {
        console.error("API error:", error);
        sendResponse({ error: true, message: error.message });
      });

    return true; // keep channel open for async response
  }
});

// Note: The content script is already injected via manifest.json content_scripts,
// so no need for programmatic injection here.