// static/script.js – Combined version with language switcher

console.log("✅ script.js loaded");

// Helper: escape text to prevent XSS
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    });
}

// Helper: create a list from array with escaping
function renderList(items, label) {
    if (!items || items.length === 0) return '';
    return `<p><strong>${escapeHtml(label)}</strong></p><ul>${items.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>`;
}

// Risk level mapping
const riskConfig = {
    SAFE: { riskClass: 'risk-safe', progressClass: 'progress-safe', badgeText: '🟢 SAFE' },
    MEDIUM_RISK: { riskClass: 'risk-medium', progressClass: 'progress-medium', badgeText: '🟡 MEDIUM RISK' },
    DANGEROUS: { riskClass: 'risk-danger', progressClass: 'progress-danger', badgeText: '🔴 DANGEROUS' },
    UNKNOWN: { riskClass: 'risk-medium', progressClass: 'progress-medium', badgeText: '🟡 UNKNOWN RISK' }
};

document.addEventListener('DOMContentLoaded', () => {
    // ---------- Language Switcher ----------
    const langSelect = document.getElementById('langSelect');
    if (langSelect) {
        langSelect.addEventListener('change', function() {
            window.location.href = '/?lang=' + this.value;
        });
    }

    // ---------- Phishing Scanner ----------
    const form = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');
    const resultDiv = document.getElementById('result');
    const scanBtn = form?.querySelector('button[type="submit"]');
    
    if (!form || !urlInput || !resultDiv) {
        console.warn("Required scanner DOM elements missing – skipping scanner init.");
        return;
    }

    // Create download button once (if not already in HTML)
    let downloadBtn = document.getElementById('downloadReportBtn');
    if (!downloadBtn) {
        downloadBtn = document.createElement('button');
        downloadBtn.id = 'downloadReportBtn';
        downloadBtn.textContent = '📄 Download PDF Report';
        downloadBtn.className = 'download-btn';
        downloadBtn.style.display = 'none';
        downloadBtn.style.marginTop = '20px';
        document.querySelector('.container')?.appendChild(downloadBtn);
    }

    // Store the last scanned URL for download
    let lastScannedUrl = '';

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) {
            alert('Please enter a URL');
            return;
        }

        // Basic URL validation
        try {
            new URL(url);
        } catch (_) {
            alert('Please enter a valid URL (include http:// or https://)');
            return;
        }

        // Disable form and hide download button
        if (scanBtn) scanBtn.disabled = true;
        urlInput.disabled = true;
        downloadBtn.style.display = 'none';
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = '<div class="loading">🔎 Scanning URL...</div>';
        resultDiv.className = 'result';

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ url })
            });

            const data = await response.json();

            if (data.error) {
                resultDiv.innerHTML = `<div class="error">❌ ${escapeHtml(data.error)}</div>`;
                return;
            }

            // Risk score & level
            const riskScore = Math.min(100, Math.max(0, Number(data.risk_score) || 0));
            const riskLevel = data.risk_level && riskConfig[data.risk_level] ? data.risk_level : 'UNKNOWN';
            const config = riskConfig[riskLevel];
            
            // Background class
            resultDiv.className = `result ${riskLevel === 'SAFE' ? 'safe' : 'suspicious'}`;

            // Issues & warnings
            let issuesHtml = renderList(data.issues, '⚠️ Issues');
            let warningsHtml = renderList(data.warnings, '📌 Warnings');
            if (!data.issues?.length && !data.warnings?.length) {
                issuesHtml = '<p>✅ No obvious signs of phishing.</p>';
            }

            // API results (with extra VirusTotal count)
            let apiResultsHtml = '';
            if (data.api_results) {
                const vtMalCount = data.api_results.virustotal_malicious_count;
                const vtLine = vtMalCount !== null && vtMalCount !== undefined 
                    ? `<li>📊 VirusTotal Detections: ${vtMalCount} malicious engines</li>` 
                    : '';
                apiResultsHtml = `
                    <hr>
                    <p><strong>🌐 Real-time API Intelligence:</strong></p>
                    <ul>
                        <li>🔒 Google Safe Browsing: ${escapeHtml(data.api_results.google_safe_browsing || 'N/A')}</li>
                        <li>🛡️ VirusTotal: ${escapeHtml(data.api_results.virustotal || 'N/A')}</li>
                        ${vtLine}
                    </ul>
                `;
            }

            // Machine Learning section
            let mlHtml = '';
            if (data.ml_prediction !== undefined && data.ml_prediction !== null) {
                const predictionText = data.ml_prediction === 1 ? '⚠️ Phishing' : '✅ Legitimate';
                const confidence = data.ml_probability ? (data.ml_probability * 100).toFixed(1) + '%' : 'N/A';
                mlHtml = `
                    <hr>
                    <p><strong>🤖 Machine Learning verdict:</strong></p>
                    <ul>
                        <li>ML Prediction: ${escapeHtml(predictionText)}</li>
                        <li>Confidence: ${escapeHtml(confidence)}</li>
                    </ul>
                `;
            }

            // Build final result
            resultDiv.innerHTML = `
                <div class="verdict">
                    <span class="risk-badge ${config.riskClass}">${config.badgeText}</span>
                    <div class="risk-score">Risk Score: ${riskScore}/100</div>
                    <div class="progress-bar-container">
                        <div class="progress-bar ${config.progressClass}" style="width: ${riskScore}%;"></div>
                    </div>
                </div>
                <div class="details">
                    ${issuesHtml}
                    ${warningsHtml}
                    <hr>
                    <p><strong>🔍 Scan details:</strong></p>
                    <ul>
                        <li>HTTPS: ${data.details?.https ? 'Yes ✅' : 'No ❌'}</li>
                        <li>Domain age: ${data.details?.domain_age_days ? data.details.domain_age_days + ' days' : 'Unknown'}</li>
                        <li>Suspicious keywords in path: ${data.details?.suspicious_keyword_count ?? 0}</li>
                        <li>URL length: ${data.details?.url_length ?? 0} chars</li>
                        <li>Uses IP: ${data.details?.has_ip ? 'Yes ⚠️' : 'No'}</li>
                        <li>Shortened: ${data.details?.is_shortened ? 'Yes ⚠️' : 'No'}</li>
                        <li>Contains '@': ${data.details?.has_at_symbol ? 'Yes ⚠️' : 'No'}</li>
                        <li>Double slashes in path: ${data.details?.has_double_slash ? 'Yes ⚠️' : 'No'}</li>
                        <li>Homoglyph domain: ${data.details?.homoglyph_detected ? 'Yes ⚠️' : 'No'}</li>
                    </ul>
                    ${apiResultsHtml}
                    ${mlHtml}
                </div>
            `;

            // Store last scanned URL and show download button
            lastScannedUrl = url;
            downloadBtn.style.display = 'block';

        } catch (err) {
            console.error('Fetch error:', err);
            resultDiv.innerHTML = '<div class="error">❌ Network error. Is the server running?</div>';
        } finally {
            // Re-enable form
            if (scanBtn) scanBtn.disabled = false;
            urlInput.disabled = false;
            urlInput.focus();
        }
    });

    // Download button click handler (reusable, always uses lastScannedUrl)
    if (downloadBtn) {
        downloadBtn.addEventListener('click', async () => {
            if (!lastScannedUrl) return;
            try {
                const response = await fetch('/download_report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({ url: lastScannedUrl })
                });
                if (response.ok) {
                    const blob = await response.blob();
                    const link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    const cd = response.headers.get('Content-Disposition');
                    let filename = 'phishing_report.pdf';
                    if (cd && cd.includes('filename=')) {
                        filename = cd.split('filename=')[1].replace(/["']/g, '');
                    }
                    link.download = filename;
                    link.click();
                    URL.revokeObjectURL(link.href);
                } else {
                    alert('Failed to generate report');
                }
            } catch (err) {
                console.error('Download error:', err);
                alert('Could not download report');
            }
        });
    }
});
// Voice input
