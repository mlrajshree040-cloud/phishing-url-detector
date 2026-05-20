// popup.js
// Your backend URL (local or deployed)
const API_URL = "http://127.0.0.1:5001/scan";   // change to your Render URL later

// When popup opens, check if there's a pending URL from context menu
chrome.storage.local.get(["pendingUrl"], (result) => {
  if (result.pendingUrl) {
    document.getElementById("urlInput").value = result.pendingUrl;
    checkUrl(result.pendingUrl);
    chrome.storage.local.remove("pendingUrl");
  }
});

document.getElementById("checkBtn").addEventListener("click", () => {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) return;
  checkUrl(url);
});

async function checkUrl(url) {
  const resultDiv = document.getElementById("result");
  resultDiv.innerHTML = "🔎 Scanning...";

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ url: url })
    });
    const data = await response.json();

    if (data.error) {
      resultDiv.innerHTML = `<span style="color:red">❌ ${data.error}</span>`;
      return;
    }

    const riskScore = data.risk_score ?? 0;
    let verdictClass = "";
    if (data.risk_level === "SAFE") verdictClass = "safe";
    else if (data.risk_level === "MEDIUM_RISK") verdictClass = "medium";
    else verdictClass = "danger";

    let html = `<p><strong>URL:</strong> ${url}</p>`;
    html += `<p><strong>Verdict:</strong> <span class="${verdictClass}">${data.risk_level}</span></p>`;
    html += `<p><strong>Risk Score:</strong> ${riskScore}/100</p>`;
    if (data.issues && data.issues.length) {
      html += `<p><strong>⚠️ Issues:</strong></p><ul>${data.issues.map(i => `<li>${i}</li>`).join('')}</ul>`;
    }
    if (data.warnings && data.warnings.length) {
      html += `<p><strong>📌 Warnings:</strong></p><ul>${data.warnings.map(w => `<li>${w}</li>`).join('')}</ul>`;
    }
    resultDiv.innerHTML = html;
  } catch (err) {
    resultDiv.innerHTML = `<span style="color:red">❌ Network error. Is your backend running?</span>`;
  }
}