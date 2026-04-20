# utils/report_generator.py
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from datetime import datetime
import os

def generate_pdf_report(url, result, filename=None):
    """
    Generate a PDF report of the phishing scan.
    result: dictionary from scanner.scan()
    returns: filename of the generated PDF
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"phishing_report_{timestamp}.pdf"
    
    # Create the document
    doc = SimpleDocTemplate(filename, pagesize=letter,
                            rightMargin=72, leftMargin=72,
                            topMargin=72, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    # Custom styles
    title_style = ParagraphStyle('TitleStyle', parent=styles['Title'],
                                 fontSize=24, textColor=colors.HexColor('#1a237e'))
    heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'],
                                   fontSize=16, textColor=colors.HexColor('#0d47a1'))
    risk_style = ParagraphStyle('RiskStyle', parent=styles['Normal'],
                                fontSize=18, textColor=colors.red)
    safe_style = ParagraphStyle('SafeStyle', parent=styles['Normal'],
                                fontSize=18, textColor=colors.green)
    
    story = []
    
    # Title
    story.append(Paragraph("Phishing URL Detection Report", title_style))
    story.append(Spacer(1, 0.3 * inch))
    
    # Date and URL
    story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Paragraph(f"<b>Scanned URL:</b> {url}", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))
    
    # Verdict and Risk Score
    verdict = result.get('verdict', 'UNKNOWN')
    risk_score = result.get('risk_score', 0)
    
    if verdict == 'SAFE':
        verdict_style = safe_style
        verdict_color = "green"
    elif verdict == 'MEDIUM_RISK':
        verdict_style = risk_style
        verdict_color = "orange"
    else:
        verdict_style = risk_style
        verdict_color = "red"
    
    story.append(Paragraph(f"<b>Verdict:</b> <font color='{verdict_color}'>{verdict}</font>", verdict_style))
    story.append(Paragraph(f"<b>Risk Score:</b> {risk_score}/100", styles['Normal']))
    story.append(Spacer(1, 0.2 * inch))
    
    # Issues and Warnings
    if result.get('issues'):
        story.append(Paragraph("⚠️ Issues Found", heading_style))
        for issue in result['issues']:
            story.append(Paragraph(f"• {issue}", styles['Normal']))
        story.append(Spacer(1, 0.1 * inch))
    
    if result.get('warnings'):
        story.append(Paragraph("📌 Warnings", heading_style))
        for warning in result['warnings']:
            story.append(Paragraph(f"• {warning}", styles['Normal']))
        story.append(Spacer(1, 0.1 * inch))
    
    if not result.get('issues') and not result.get('warnings'):
        story.append(Paragraph("✅ No issues or warnings detected.", styles['Normal']))
        story.append(Spacer(1, 0.1 * inch))
    
    # Scan Details Table
    details = result.get('details', {})
    data = [
        ["Check", "Result"],
        ["HTTPS", "Yes ✅" if details.get('https') else "No ❌"],
        ["Domain age", f"{details.get('domain_age_days', 'Unknown')} days" if details.get('domain_age_days') else "Unknown"],
        ["Suspicious keywords in path", str(details.get('suspicious_keyword_count', 0))],
        ["URL length", f"{details.get('url_length', 0)} chars"],
        ["Uses IP address", "Yes ⚠️" if details.get('has_ip') else "No"],
        ["URL shortened", "Yes ⚠️" if details.get('is_shortened') else "No"],
        ["Contains '@' symbol", "Yes ⚠️" if details.get('has_at_symbol') else "No"],
        ["Double slashes in path", "Yes ⚠️" if details.get('has_double_slash') else "No"],
        ["Homoglyph domain", "Yes ⚠️" if details.get('homoglyph_detected') else "No"],
    ]
    
    table = Table(data, colWidths=[2*inch, 3*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(Paragraph("🔍 Scan Details", heading_style))
    story.append(Spacer(1, 0.1 * inch))
    story.append(table)
    story.append(Spacer(1, 0.2 * inch))
    
    # API Results
    api = result.get('api_results', {})
    if api:
        story.append(Paragraph("🌐 Real-time API Intelligence", heading_style))
        story.append(Paragraph(f"<b>Google Safe Browsing:</b> {api.get('google_safe_browsing', 'N/A')}", styles['Normal']))
        story.append(Paragraph(f"<b>VirusTotal:</b> {api.get('virustotal', 'N/A')}", styles['Normal']))
        if api.get('virustotal_malicious_count') is not None:
            story.append(Paragraph(f"<b>VirusTotal Detections:</b> {api['virustotal_malicious_count']} malicious engines", styles['Normal']))
        story.append(Spacer(1, 0.1 * inch))
    
    # Machine Learning Results
    ml_pred = result.get('ml_prediction')
    if ml_pred is not None:
        story.append(Paragraph("🤖 Machine Learning Verdict", heading_style))
        ml_text = "⚠️ Phishing" if ml_pred == 1 else "✅ Legitimate"
        ml_conf = result.get('ml_probability')
        conf_text = f" ({ml_conf*100:.1f}% confidence)" if ml_conf else ""
        story.append(Paragraph(f"<b>Prediction:</b> {ml_text}{conf_text}", styles['Normal']))
        story.append(Spacer(1, 0.1 * inch))
    
    # Footer
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph("Report generated by Phishing URL Detector", styles['Normal']))
    
    # Build PDF
    doc.build(story)
    return filename