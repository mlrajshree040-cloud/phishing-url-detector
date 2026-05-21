// static/script.js
document.getElementById('scanForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    if (!url) return;

    // Hide download button when starting a new scan
    const downloadBtn = document.getElementById('downloadReportBtn');
    if (downloadBtn) downloadBtn.style.display = 'none';

    const resultDiv = document.getElementById('result');
    resultDiv.classList.add('hidden');
    resultDiv.innerHTML = '<div class="loading">🔎 Scanning URL...</div>';
    resultDiv.classList.remove('hidden');

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ url: url })
        });

        const data = await response.json();

        if (data.error) {
            resultDiv.innerHTML = `<div class="error">❌ ${data.error}</div>`;
            return;
        }

        // --- Risk Score & Level (with safe fallbacks) ---
        const riskScore = typeof data.risk_score === 'number' ? data.risk_score : 0;
        const riskLevel = data.risk_level || 'UNKNOWN';
        
        let riskClass = 'risk-safe';
        let progressClass = 'progress-safe';
        let badgeText = '🟢 SAFE';

        if (riskLevel === 'SAFE') {
            riskClass = 'risk-safe';
            progressClass = 'progress-safe';
            badgeText = '🟢 SAFE';
        } else if (riskLevel === 'MEDIUM_RISK') {
            riskClass = 'risk-medium';
            progressClass = 'progress-medium';
            badgeText = '🟡 MEDIUM RISK';
        } else if (riskLevel === 'DANGEROUS') {
            riskClass = 'risk-danger';
            progressClass = 'progress-danger';
            badgeText = '🔴 DANGEROUS';
        } else {
            // fallback for unknown risk level
            riskClass = 'risk-medium';
            progressClass = 'progress-medium';
            badgeText = '🟡 UNKNOWN RISK';
        }

        // Set result background based on risk level
        resultDiv.className = `result ${riskLevel === 'SAFE' ? 'safe' : 'suspicious'}`;

        // --- Issues & Warnings ---
        let issuesHtml = '';
        if (data.issues && data.issues.length) {
            issuesHtml += `<p><strong>⚠️ Issues:</strong></p><ul>${data.issues.map(i => `<li>${i}</li>`).join('')}</ul>`;
        }
        if (data.warnings && data.warnings.length) {
            issuesHtml += `<p><strong>📌 Warnings:</strong></p><ul>${data.warnings.map(w => `<li>${w}</li>`).join('')}</ul>`;
        }
        if ((!data.issues || data.issues.length === 0) && (!data.warnings || data.warnings.length === 0)) {
            issuesHtml = '<p>✅ No obvious signs of phishing.</p>';
        }

        // --- API Results Section ---
        let apiResultsHtml = '';
        if (data.api_results) {
            apiResultsHtml = `
                <hr>
                <p><strong>🌐 Real-time API Intelligence:</strong></p>
                <ul>
                    <li>🔒 Google Safe Browsing: ${data.api_results.google_safe_browsing || 'N/A'}</li>
                    <li>🛡️ VirusTotal: ${data.api_results.virustotal || 'N/A'}</li>
                    ${data.api_results.virustotal_malicious_count !== null && data.api_results.virustotal_malicious_count !== undefined ? 
                        `<li>📊 VirusTotal Detections: ${data.api_results.virustotal_malicious_count} malicious engines</li>` : ''}
                </ul>
            `;
        }

        // --- Machine Learning Section ---
        let mlHtml = '';
        if (data.ml_prediction !== undefined && data.ml_prediction !== null) {
            mlHtml = `
                <hr>
                <p><strong>🤖 Machine Learning verdict:</strong></p>
                <ul>
                    <li>ML Prediction: ${data.ml_prediction === 1 ? '⚠️ Phishing' : '✅ Legitimate'}</li>
                    <li>Confidence: ${data.ml_probability ? (data.ml_probability * 100).toFixed(1) + '%' : 'N/A'}</li>
                </ul>
            `;
        }

        // --- Full HTML with progress bar ---
        resultDiv.innerHTML = `
            <div class="verdict">
                <span class="risk-badge ${riskClass}">${badgeText}</span>
                <div class="risk-score">Risk Score: ${riskScore}/100</div>
                <div class="progress-bar-container">
                    <div class="progress-bar ${progressClass}" style="width: ${riskScore}%;"></div>
                </div>
            </div>
            <div class="details">
                ${issuesHtml}
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

        // --- Show download button and attach event (avoid duplicates) ---
        if (downloadBtn) {
            downloadBtn.style.display = 'block';
            // Clone and replace to remove previous listeners
            const newBtn = downloadBtn.cloneNode(true);
            downloadBtn.parentNode.replaceChild(newBtn, downloadBtn);
            newBtn.addEventListener('click', async () => {
                const formData = new URLSearchParams();
                formData.append('url', url);
                const reportResponse = await fetch('/download_report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: formData
                });
                if (reportResponse.ok) {
                    const blob = await reportResponse.blob();
                    const link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    // Extract filename from Content-Disposition header or use default
                    const cd = reportResponse.headers.get('Content-Disposition');
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
            });
        }

    } catch (err) {
        console.error('Fetch error:', err);
        resultDiv.innerHTML = '<div class="error">❌ Network error. Is the server running?</div>';
    }
});// static/script.js

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
    const form = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');
    const resultDiv = document.getElementById('result');
    const scanBtn = form.querySelector('button[type="submit"]');
    
    // Create download button once (if not already in HTML)
    let downloadBtn = document.getElementById('downloadReportBtn');
    if (!downloadBtn) {
        downloadBtn = document.createElement('button');
        downloadBtn.id = 'downloadReportBtn';
        downloadBtn.textContent = '📄 Download PDF Report';
        downloadBtn.className = 'download-btn';
        downloadBtn.style.display = 'none';
        downloadBtn.style.marginTop = '20px';
        document.querySelector('.container').appendChild(downloadBtn);
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

        // Basic URL validation (optional)
        try {
            new URL(url);
        } catch (_) {
            alert('Please enter a valid URL (include http:// or https://)');
            return;
        }

        // Disable form and hide download button
        scanBtn.disabled = true;
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
            scanBtn.disabled = false;
            urlInput.disabled = false;
            urlInput.focus();
        }
    });

    // Download button click handler (reusable, always uses lastScannedUrl)
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
});