// content.js – runs on every page the user visits
// Handles: automatic page scanning, SPA navigation, and manual right‑click link checks

// ========== Helper: send a URL to the background API ==========
function checkUrl(url, callback) {
  chrome.runtime.sendMessage({ action: "checkUrl", url: url }, (response) => {
    if (chrome.runtime.lastError) {
      console.error("Runtime error:", chrome.runtime.lastError.message);
      if (callback) callback({ error: true });
      return;
    }
    if (response && response.error) {
      console.error("API error:", response.message);
      if (callback) callback({ error: true });
      return;
    }
    if (callback) callback(response);
  });
}

// ========== Warning banner management ==========
function showWarning(riskLevel, riskScore) {
  removeWarning(); // remove any existing banner first

  const banner = document.createElement("div");
  banner.id = "phishing-detector-warning";
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: ${riskLevel === "DANGEROUS" ? "#d32f2f" : "#f57c00"};
    color: white;
    padding: 12px 20px;
    text-align: center;
    z-index: 10000;
    font-family: system-ui, sans-serif;
    font-size: 14px;
    font-weight: 500;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
  `;

  let message = `⚠️ Phishing Detector: This page is ${riskLevel.toLowerCase()}`;
  if (riskScore !== undefined && riskScore !== null) {
    message += ` (Risk Score: ${riskScore}/100)`;
  }

  const textSpan = document.createElement("span");
  textSpan.textContent = message;

  const closeBtn = document.createElement("button");
  closeBtn.textContent = "×";
  closeBtn.style.cssText = `
    background: none;
    border: none;
    color: white;
    font-size: 20px;
    cursor: pointer;
    font-weight: bold;
    padding: 0 8px;
  `;
  closeBtn.onclick = () => banner.remove();

  banner.appendChild(textSpan);
  banner.appendChild(closeBtn);
  document.body.insertBefore(banner, document.body.firstChild);
}

function removeWarning() {
  const existing = document.getElementById("phishing-detector-warning");
  if (existing) existing.remove();
}

// ========== Automatic page scanning ==========
function scanCurrentPage() {
  const currentUrl = window.location.href;
  checkUrl(currentUrl, (response) => {
    if (response && !response.error) {
      const riskLevel = response.riskLevel;
      if (riskLevel === "MEDIUM_RISK" || riskLevel === "DANGEROUS") {
        showWarning(riskLevel, response.riskScore);
      } else {
        // Page is safe – remove any leftover warning
        removeWarning();
      }
    }
  });
}

// ========== Manual right‑click link check ==========
// Listens for messages sent from background after a right‑click
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "showManualCheckResult") {
    const linkUrl = request.url;
    // Check the clicked link via the API
    checkUrl(linkUrl, (response) => {
      if (response && !response.error) {
        const riskLevel = response.riskLevel;
        const riskScore = response.riskScore;
        let alertMsg = `Phishing Check for: ${linkUrl}\n\nRisk Level: ${riskLevel}`;
        if (riskScore !== undefined) alertMsg += `\nRisk Score: ${riskScore}/100`;
        if (response.issues && response.issues.length) {
          alertMsg += `\n\nIssues: ${response.issues.join(", ")}`;
        }
        if (response.warnings && response.warnings.length) {
          alertMsg += `\n\nWarnings: ${response.warnings.join(", ")}`;
        }
        alert(alertMsg);
      } else {
        alert("Could not check the link. Please ensure the backend is running.");
      }
    });
    sendResponse({ received: true });
  }
});

// ========== Initial scan & SPA navigation detection ==========
scanCurrentPage();

let lastUrl = window.location.href;
new MutationObserver(() => {
  const newUrl = window.location.href;
  if (newUrl !== lastUrl) {
    lastUrl = newUrl;
    scanCurrentPage();
  }
}).observe(document, { subtree: true, childList: true });