"""
AllysecLabs Report Exporter
Export security analysis reports to various formats (Markdown, PDF, HTML)
with professional-grade styling, cover pages, and data visualizations.

Requirements:
- markdown (for Markdown to HTML conversion)
- weasyprint or pdfkit (for PDF generation)
- matplotlib (for chart generation)
"""

import os
import re
import io
import base64
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List
import logging

logger = logging.getLogger(__name__)

# Report output directory
REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Branding assets
BRANDING_DIR = Path(__file__).parent.parent / "branding"
LOGO_PATH = BRANDING_DIR / "AllyShipSec-favicon.png"
FULL_LOGO_PATH = BRANDING_DIR / "asl-logo-full.png"


def get_logo_base64() -> str:
    """
    Get the branding logo as a base64-encoded data URI.
    Returns empty string if logo not found.
    """
    # Try full logo first, then favicon
    for logo_file in [FULL_LOGO_PATH, LOGO_PATH]:
        if logo_file.exists():
            try:
                with open(logo_file, "rb") as f:
                    logo_data = f.read()
                b64_data = base64.b64encode(logo_data).decode("utf-8")
                return f"data:image/png;base64,{b64_data}"
            except Exception as e:
                logger.warning(f"Failed to read logo {logo_file}: {e}")
    return ""


def generate_report_filename(prefix: str = "SIR", extension: str = "md") -> str:
    """Generate a timestamped report filename."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}.{extension}"


def save_markdown_report(
    content: str,
    filename: Optional[str] = None,
    query: Optional[str] = None,
) -> str:
    """
    Save analysis report as Markdown file.
    
    Args:
        content: Markdown content of the report
        filename: Optional custom filename
        query: Original query (for metadata)
    
    Returns:
        Path to saved file
    """
    if not filename:
        filename = generate_report_filename(extension="md")
    
    filepath = REPORTS_DIR / filename
    
    # Add metadata header
    header = f"""---
title: Security Intelligence Report
generated: {datetime.now().isoformat()}
platform: AllysecLabs Security Intelligence Platform
query: {query or 'N/A'}
---

"""
    
    full_content = header + content
    
    filepath.write_text(full_content, encoding="utf-8")
    logger.info(f"Report saved: {filepath}")
    
    return str(filepath)


def markdown_to_html(markdown_content: str, stats: Dict = None, report_metadata: Dict = None) -> str:
    """
    Convert Markdown content to professionally styled HTML for PDF export.
    Includes cover page, modern typography, data visualizations, and compliance references.
    
    Args:
        markdown_content: Markdown report content
        stats: Optional alert statistics dict for chart generation
        report_metadata: Optional dict with query, threat_level, alert_count, report_depth
    """
    try:
        import markdown
        html_body = markdown.markdown(
            markdown_content,
            extensions=['tables', 'fenced_code', 'toc', 'attr_list']
        )
    except ImportError:
        html_body = basic_markdown_to_html(markdown_content)
    
    # Get branding logo
    logo_data_uri = get_logo_base64()
    logo_html = f'<img src="{logo_data_uri}" alt="AllysecLabs" class="logo">' if logo_data_uri else ""
    logo_cover_html = f'<img src="{logo_data_uri}" alt="AllysecLabs" class="cover-logo">' if logo_data_uri else '<div class="cover-logo-text">AllysecLabs</div>'
    
    # Generate charts if stats available
    charts_html = ""
    if stats:
        charts_html = _generate_charts_html(stats)
    
    # Build cover page if full report
    is_full_report = report_metadata and report_metadata.get('report_depth') == 'full'
    cover_page_html = ""
    if is_full_report and report_metadata:
        cover_page_html = _generate_cover_page(
            logo_html=logo_cover_html,
            metadata=report_metadata,
        )
    
    now = datetime.now()
    
    # Inject charts before "## Threat Assessment" or after "## At-a-Glance"
    if charts_html and "## Threat Assessment" in markdown_content:
        # Insert charts section as HTML after At-a-Glance section
        html_body = html_body + charts_html
    elif charts_html:
        html_body = html_body + charts_html
    
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Intelligence Report - AllysecLabs</title>
    <style>
{_get_professional_css()}
    </style>
</head>
<body>
    {cover_page_html}
    
    <div class="report-body">
        <div class="header">
            {logo_html}
            <div class="header-text">
                <div class="header-title">Security Intelligence Report</div>
                <div class="header-subtitle">AllysecLabs Security Intelligence Platform</div>
                <div class="header-date">Generated: {now.strftime('%B %d, %Y — %H:%M:%S UTC')}</div>
            </div>
        </div>
        
        {html_body}
        
        <div class="footer">
            <div class="footer-line"></div>
            <div class="footer-content">
                <div class="footer-logo">{logo_html}</div>
                <p class="footer-legal">&copy; {now.year} AllysecLabs | Security Intelligence Platform</p>
                <p class="footer-legal">This report is classified as <strong>CONFIDENTIAL</strong> and intended for authorized personnel only.</p>
                <p class="footer-legal">All findings should be validated against your organization's change management process before taking action.</p>
            </div>
        </div>
    </div>
</body>
</html>"""
    
    return html_template


def _get_professional_css() -> str:
    """Return the full professional CSS for report styling."""
    return """
        /* ═══════════════════════════════════════════════════════════════
           AllysecLabs Professional Report CSS — Modern Enterprise Edition
           ═══════════════════════════════════════════════════════════════ */

        @page {
            size: A4;
            margin: 2cm 1.8cm 2.5cm 1.8cm;
            
            @top-left {
                content: "AllysecLabs Security Intelligence Platform";
                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                font-size: 8pt;
                color: #94a3b8;
                font-weight: 500;
            }
            @top-right {
                content: "CONFIDENTIAL";
                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                font-size: 8pt;
                color: #dc2626;
                font-weight: 700;
                letter-spacing: 1px;
            }
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                font-size: 8pt;
                color: #94a3b8;
            }
        }
        
        @page :first {
            @top-left { content: none; }
            @top-right { content: none; }
            @bottom-center { content: none; }
        }

        /* ── Base Typography ── */
        * { box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, 'Helvetica Neue', sans-serif;
            font-size: 10.5pt;
            line-height: 1.7;
            color: #1e293b;
            max-width: 100%;
            margin: 0;
            padding: 0;
            background: #fff;
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
        }

        /* ── Cover Page ── */
        .cover-page {
            page-break-after: always;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            background: linear-gradient(145deg, #0f172a 0%, #1e3a8a 40%, #1d4ed8 100%);
            color: white;
            margin: -2cm -1.8cm 0 -1.8cm;
            padding: 0;
            position: relative;
            overflow: hidden;
        }
        
        .cover-page::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -30%;
            width: 80%;
            height: 200%;
            background: radial-gradient(ellipse, rgba(59, 130, 246, 0.15) 0%, transparent 70%);
            pointer-events: none;
        }

        .cover-classification-top, .cover-classification-bottom {
            background: #dc2626;
            color: white;
            text-align: center;
            padding: 10px 20px;
            font-weight: 700;
            font-size: 11pt;
            letter-spacing: 3px;
            text-transform: uppercase;
        }

        .cover-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            padding: 60px 50px;
            position: relative;
            z-index: 1;
        }

        .cover-logo {
            max-width: 220px;
            max-height: 100px;
            margin-bottom: 50px;
            filter: brightness(0) invert(1);
        }
        
        .cover-logo-text {
            font-size: 36pt;
            font-weight: 700;
            letter-spacing: 2px;
            margin-bottom: 50px;
            color: white;
        }

        .cover-title {
            font-size: 38pt;
            font-weight: 700;
            margin: 0;
            line-height: 1.1;
            letter-spacing: -0.5px;
            text-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }

        .cover-subtitle {
            font-size: 16pt;
            font-weight: 300;
            margin-top: 12px;
            color: #bfdbfe;
            letter-spacing: 1px;
        }

        .cover-edition {
            display: inline-block;
            margin-top: 20px;
            padding: 6px 24px;
            background: rgba(255,255,255,0.15);
            border: 1px solid rgba(255,255,255,0.25);
            border-radius: 20px;
            font-size: 9pt;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: #e0e7ff;
        }

        .cover-meta-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-top: 50px;
            width: 100%;
            max-width: 520px;
        }

        .cover-meta-item {
            background: rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(8px);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 10px;
            padding: 14px 18px;
            text-align: left;
        }

        .cover-meta-label {
            font-size: 7pt;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #93c5fd;
            margin-bottom: 4px;
        }

        .cover-meta-value {
            font-size: 11pt;
            font-weight: 600;
            color: white;
        }

        .cover-summary-box {
            margin-top: 40px;
            background: rgba(255, 255, 255, 0.95);
            color: #1e293b;
            padding: 28px 32px;
            border-radius: 14px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
            max-width: 560px;
            width: 100%;
            text-align: left;
        }

        .cover-summary-title {
            font-size: 11pt;
            font-weight: 700;
            color: #1e40af;
            margin: 0 0 12px 0;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .cover-summary-row {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid #f1f5f9;
            font-size: 9.5pt;
        }

        .cover-summary-row:last-child {
            border-bottom: none;
        }

        .cover-summary-key {
            color: #64748b;
            font-weight: 500;
        }

        .cover-summary-val {
            font-weight: 600;
            color: #1e293b;
        }

        .risk-badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 9pt;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .risk-badge-critical { background: #dc2626; color: white; }
        .risk-badge-high { background: #ea580c; color: white; }
        .risk-badge-medium { background: #d97706; color: white; }
        .risk-badge-low { background: #16a34a; color: white; }
        .risk-badge-minimal { background: #0ea5e9; color: white; }

        /* ── Report Body ── */
        .report-body {
            padding: 0 10px;
        }

        .header {
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 3px solid #1e40af;
        }

        .header .logo {
            max-width: 140px;
            max-height: 60px;
        }

        .header-text {
            flex: 1;
        }

        .header-title {
            font-size: 22pt;
            font-weight: 700;
            color: #0f172a;
            line-height: 1.2;
        }

        .header-subtitle {
            font-size: 10pt;
            color: #64748b;
            font-weight: 500;
            margin-top: 2px;
        }

        .header-date {
            font-size: 9pt;
            color: #94a3b8;
            margin-top: 4px;
        }

        /* ── Headings ── */
        h1 {
            font-size: 22pt;
            font-weight: 700;
            color: #0f172a;
            border-bottom: 3px solid #2563eb;
            padding-bottom: 10px;
            margin-top: 35px;
            margin-bottom: 18px;
            letter-spacing: -0.3px;
        }

        h2 {
            font-size: 16pt;
            font-weight: 600;
            color: #1e3a8a;
            margin-top: 35px;
            margin-bottom: 14px;
            padding-bottom: 8px;
            border-bottom: 2px solid #e2e8f0;
            page-break-after: avoid;
        }

        h3 {
            font-size: 13pt;
            font-weight: 600;
            color: #1e40af;
            margin-top: 22px;
            margin-bottom: 10px;
            page-break-after: avoid;
        }

        h4 {
            font-size: 11pt;
            font-weight: 600;
            color: #3730a3;
            margin-top: 18px;
            margin-bottom: 8px;
        }

        /* ── Tables ── */
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin: 18px 0;
            font-size: 9.5pt;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 4px rgba(0, 0, 0, 0.06);
            page-break-inside: auto;
        }

        thead {
            display: table-header-group;
        }
        
        tr {
            page-break-inside: avoid;
        }

        th {
            background: linear-gradient(180deg, #1e40af 0%, #1e3a8a 100%);
            color: white;
            padding: 10px 14px;
            text-align: left;
            font-weight: 600;
            font-size: 9pt;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }

        td {
            padding: 9px 14px;
            border-bottom: 1px solid #f1f5f9;
            vertical-align: top;
        }

        tr:nth-child(even) {
            background: #f8fafc;
        }

        tr:hover {
            background: #eff6ff;
        }

        tr:last-child td {
            border-bottom: none;
        }

        /* ── Severity Badges ── */
        .sev-critical, strong:has(+ :contains("CRITICAL")) {
            background: #dc2626;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 8.5pt;
        }
        .sev-high {
            background: #ea580c;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
        }
        .sev-medium {
            background: #d97706;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
        }
        .sev-low {
            background: #16a34a;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
        }

        /* ── Call-out Boxes ── */
        blockquote {
            border-left: 5px solid #2563eb;
            margin: 20px 0;
            padding: 14px 20px;
            background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
            border-radius: 0 8px 8px 0;
            font-style: normal;
        }

        /* Critical finding highlight */
        h3:has(+ ul) {
            page-break-after: avoid;
        }

        /* ── Code Blocks ── */
        code {
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Cascadia Code', 'Consolas', 'Monaco', monospace;
            font-size: 9pt;
            color: #be185d;
        }

        pre {
            background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            padding: 18px;
            border-radius: 10px;
            overflow-x: auto;
            font-size: 9pt;
            line-height: 1.5;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            page-break-inside: avoid;
        }

        pre code {
            background: transparent;
            color: inherit;
            padding: 0;
        }

        /* ── Links ── */
        a {
            color: #2563eb;
            text-decoration: none;
            font-weight: 500;
            border-bottom: 1px solid #93c5fd;
        }

        a:hover {
            color: #1d4ed8;
            border-bottom-color: #2563eb;
        }

        /* ── Lists ── */
        ul, ol {
            margin: 10px 0;
            padding-left: 24px;
        }

        li {
            margin: 4px 0;
            line-height: 1.6;
        }

        li::marker {
            color: #2563eb;
        }

        /* ── Horizontal Rules ── */
        hr {
            border: none;
            height: 2px;
            background: linear-gradient(to right, #2563eb, #e2e8f0);
            margin: 30px 0;
        }

        /* ── Data Visualization Section ── */
        .charts-section {
            page-break-inside: avoid;
            margin: 30px 0;
        }

        .charts-section h2 {
            text-align: center;
        }

        .chart-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin: 20px 0;
        }

        .chart-card {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
        }

        .chart-card-title {
            font-size: 10pt;
            font-weight: 600;
            color: #1e3a8a;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .chart-card img {
            max-width: 100%;
            height: auto;
            border-radius: 6px;
        }

        .chart-full-width {
            grid-column: 1 / -1;
        }

        /* ── Scorecard / KPI section ── */
        .scorecard-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin: 24px 0;
        }

        .scorecard-item {
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            border: 1px solid #e2e8f0;
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }

        .scorecard-value {
            font-size: 24pt;
            font-weight: 700;
            color: #0f172a;
            line-height: 1;
        }

        .scorecard-label {
            font-size: 8pt;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #64748b;
            margin-top: 6px;
        }

        /* ── Strong emphasis for warning text ── */
        strong {
            color: #0f172a;
        }

        p {
            margin: 8px 0;
        }

        /* ── Risk level callout ── */
        .risk-callout {
            padding: 16px 20px;
            border-radius: 10px;
            margin: 20px 0;
            font-weight: 600;
            text-align: center;
            font-size: 14pt;
        }

        .risk-callout-critical {
            background: linear-gradient(135deg, #fef2f2, #fee2e2);
            border: 2px solid #dc2626;
            color: #991b1b;
        }

        .risk-callout-high {
            background: linear-gradient(135deg, #fff7ed, #ffedd5);
            border: 2px solid #ea580c;
            color: #9a3412;
        }

        .risk-callout-medium {
            background: linear-gradient(135deg, #fffbeb, #fef3c7);
            border: 2px solid #d97706;
            color: #92400e;
        }

        .risk-callout-low {
            background: linear-gradient(135deg, #f0fdf4, #dcfce7);
            border: 2px solid #16a34a;
            color: #166534;
        }

        /* ── Footer ── */
        .footer {
            margin-top: 50px;
            page-break-inside: avoid;
        }

        .footer-line {
            height: 3px;
            background: linear-gradient(to right, #2563eb, #7c3aed, #2563eb);
            border-radius: 2px;
            margin-bottom: 20px;
        }

        .footer-content {
            text-align: center;
        }

        .footer-logo img, .footer-logo .logo {
            max-width: 80px;
            opacity: 0.6;
            margin-bottom: 10px;
        }

        .footer-legal {
            font-size: 8pt;
            color: #94a3b8;
            margin: 3px 0;
        }

        /* ── Print-specific ── */
        @media print {
            body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            .cover-page { page-break-after: always; }
            h2, h3 { page-break-after: avoid; }
            table, pre, .chart-card { page-break-inside: avoid; }
        }
"""


def _generate_cover_page(logo_html: str, metadata: Dict) -> str:
    """Generate a professional cover page for full reports."""
    now = datetime.now()
    query = metadata.get('query', 'Security Analysis')
    alert_count = metadata.get('alert_count', 0)
    threat_level = metadata.get('threat_level', 'N/A').upper()
    
    # Determine risk badge class
    risk_class = 'minimal'
    if 'CRITICAL' in threat_level:
        risk_class = 'critical'
    elif 'HIGH' in threat_level:
        risk_class = 'high'
    elif 'MEDIUM' in threat_level or 'MODERATE' in threat_level:
        risk_class = 'medium'
    elif 'LOW' in threat_level:
        risk_class = 'low'
    
    report_id = now.strftime("SIR-%Y%m%d-%H%M%S")
    
    return f"""
    <div class="cover-page">
        <div class="cover-classification-top">CONFIDENTIAL — INTERNAL USE ONLY</div>
        
        <div class="cover-content">
            {logo_html}
            
            <h1 class="cover-title">Security Intelligence<br>Report</h1>
            <p class="cover-subtitle">Full Professional Edition</p>
            <span class="cover-edition">Enterprise-Grade Analysis</span>
            
            <div class="cover-meta-grid">
                <div class="cover-meta-item">
                    <div class="cover-meta-label">Report ID</div>
                    <div class="cover-meta-value">{report_id}</div>
                </div>
                <div class="cover-meta-item">
                    <div class="cover-meta-label">Classification</div>
                    <div class="cover-meta-value">CONFIDENTIAL</div>
                </div>
                <div class="cover-meta-item">
                    <div class="cover-meta-label">Generated</div>
                    <div class="cover-meta-value">{now.strftime('%b %d, %Y %H:%M')}</div>
                </div>
                <div class="cover-meta-item">
                    <div class="cover-meta-label">Platform</div>
                    <div class="cover-meta-value">Wazuh SIEM v4.x</div>
                </div>
            </div>
            
            <div class="cover-summary-box">
                <div class="cover-summary-title">Report Summary</div>
                <div class="cover-summary-row">
                    <span class="cover-summary-key">Query</span>
                    <span class="cover-summary-val">{query[:60]}{'...' if len(query) > 60 else ''}</span>
                </div>
                <div class="cover-summary-row">
                    <span class="cover-summary-key">Alerts Analyzed</span>
                    <span class="cover-summary-val">{alert_count:,}</span>
                </div>
                <div class="cover-summary-row">
                    <span class="cover-summary-key">Risk Rating</span>
                    <span class="cover-summary-val"><span class="risk-badge risk-badge-{risk_class}">{threat_level}</span></span>
                </div>
                <div class="cover-summary-row">
                    <span class="cover-summary-key">Analyst</span>
                    <span class="cover-summary-val">AllysecLabs AI (Tier 3)</span>
                </div>
            </div>
        </div>
        
        <div class="cover-classification-bottom">CONFIDENTIAL — INTERNAL USE ONLY</div>
    </div>
    """


def _generate_charts_html(stats: Dict) -> str:
    """Generate embedded chart images from alert statistics."""
    charts = []
    
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.ticker as ticker
    except ImportError:
        logger.warning("matplotlib not available, skipping chart generation")
        return ""
    
    # Chart 1: Severity Distribution Donut
    levels = stats.get('levels', {})
    if levels:
        sev_chart = _create_severity_donut(plt, levels)
        if sev_chart:
            charts.append(('Severity Distribution', sev_chart, False))
    
    # Chart 2: Top Rules Bar Chart
    top_rules = stats.get('top_rules', [])
    if top_rules:
        rules_chart = _create_rules_bar_chart(plt, ticker, top_rules)
        if rules_chart:
            charts.append(('Top Triggered Rules', rules_chart, False))
    
    # Chart 3: Agent Distribution
    by_agent = stats.get('by_agent', {})
    if by_agent and len(by_agent) > 1:
        agent_chart = _create_agent_chart(plt, by_agent)
        if agent_chart:
            charts.append(('Alert Distribution by Agent', agent_chart, False))
    
    # Chart 4: MITRE ATT&CK Tactics
    mitre = stats.get('mitre_tactics', {})
    if mitre:
        mitre_chart = _create_mitre_chart(plt, ticker, mitre)
        if mitre_chart:
            charts.append(('MITRE ATT&CK Tactics', mitre_chart, True))
    
    if not charts:
        return ""
    
    html = '<div class="charts-section"><h2>📊 Visual Analytics Dashboard</h2><div class="chart-grid">'
    for title, data_uri, full_width in charts:
        fw_class = ' chart-full-width' if full_width else ''
        html += f'''
        <div class="chart-card{fw_class}">
            <div class="chart-card-title">{title}</div>
            <img src="{data_uri}" alt="{title}">
        </div>'''
    html += '</div></div>'
    return html


def _create_severity_donut(plt, levels: Dict) -> str:
    """Create a severity distribution donut chart."""
    try:
        # Map levels to severity names
        sev_map = {}
        for level_str, count in levels.items():
            level = int(level_str)
            if level >= 12:
                name = 'CRITICAL'
            elif level >= 8:
                name = 'HIGH'
            elif level >= 5:
                name = 'MEDIUM'
            else:
                name = 'LOW'
            sev_map[name] = sev_map.get(name, 0) + count
        
        if not sev_map:
            return ""
        
        # Colors matching the report theme
        colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#ea580c',
            'MEDIUM': '#d97706',
            'LOW': '#16a34a'
        }
        order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        labels = [s for s in order if s in sev_map]
        sizes = [sev_map[s] for s in labels]
        chart_colors = [colors[s] for s in labels]
        
        fig, ax = plt.subplots(figsize=(5, 4))
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            colors=chart_colors,
            autopct=lambda pct: f'{pct:.1f}%\n({int(pct/100.*sum(sizes)):,})',
            startangle=90,
            pctdistance=0.72,
            wedgeprops=dict(width=0.4, edgecolor='white', linewidth=2),
        )
        
        for text in texts:
            text.set_fontsize(9)
            text.set_fontweight('bold')
        for autotext in autotexts:
            autotext.set_fontsize(8)
            autotext.set_color('#374151')
        
        # Center text
        ax.text(0, 0, f'{sum(sizes):,}', ha='center', va='center',
                fontsize=18, fontweight='bold', color='#0f172a')
        ax.text(0, -0.15, 'Total', ha='center', va='center',
                fontsize=8, color='#64748b')
        
        plt.tight_layout()
        return _fig_to_base64(fig, plt)
    except Exception as e:
        logger.warning(f"Failed to create severity chart: {e}")
        return ""


def _create_rules_bar_chart(plt, ticker, top_rules: list) -> str:
    """Create a horizontal bar chart for top triggered rules."""
    try:
        rules = top_rules[:8]  # Top 8
        labels = [f"Rule {r['rule_id']}" for r in reversed(rules)]
        counts = [r['count'] for r in reversed(rules)]
        levels = [r.get('level', 5) for r in reversed(rules)]
        
        # Color by severity
        bar_colors = []
        for lv in levels:
            if lv >= 12:
                bar_colors.append('#dc2626')
            elif lv >= 8:
                bar_colors.append('#ea580c')
            elif lv >= 5:
                bar_colors.append('#d97706')
            else:
                bar_colors.append('#16a34a')
        
        fig, ax = plt.subplots(figsize=(5, 4))
        bars = ax.barh(labels, counts, color=bar_colors, edgecolor='white', linewidth=0.5, height=0.6)
        
        # Value labels
        for bar, count in zip(bars, counts):
            ax.text(bar.get_width() + max(counts) * 0.02, bar.get_y() + bar.get_height()/2,
                    f'{count:,}', va='center', fontsize=8, fontweight='bold', color='#374151')
        
        ax.set_xlabel('Alert Count', fontsize=9, fontweight='bold', color='#64748b')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_color('#e2e8f0')
        ax.spines['bottom'].set_color('#e2e8f0')
        ax.tick_params(axis='y', labelsize=8)
        ax.tick_params(axis='x', labelsize=8)
        ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f'{int(x):,}'))
        
        plt.tight_layout()
        return _fig_to_base64(fig, plt)
    except Exception as e:
        logger.warning(f"Failed to create rules chart: {e}")
        return ""


def _create_agent_chart(plt, by_agent: Dict) -> str:
    """Create a pie chart for agent distribution."""
    try:
        sorted_agents = sorted(by_agent.items(), key=lambda x: x[1], reverse=True)[:6]
        labels = [a[0] for a in sorted_agents]
        sizes = [a[1] for a in sorted_agents]
        
        palette = ['#2563eb', '#7c3aed', '#0ea5e9', '#14b8a6', '#f59e0b', '#ef4444']
        colors = palette[:len(labels)]
        
        fig, ax = plt.subplots(figsize=(5, 4))
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            colors=colors,
            autopct='%1.1f%%',
            startangle=90,
            textprops={'fontsize': 8},
            wedgeprops=dict(edgecolor='white', linewidth=2),
        )
        for autotext in autotexts:
            autotext.set_fontsize(8)
            autotext.set_fontweight('bold')
            autotext.set_color('white')
        
        plt.tight_layout()
        return _fig_to_base64(fig, plt)
    except Exception as e:
        logger.warning(f"Failed to create agent chart: {e}")
        return ""


def _create_mitre_chart(plt, ticker, mitre_tactics: Dict) -> str:
    """Create a horizontal bar chart for MITRE ATT&CK tactics."""
    try:
        sorted_tactics = sorted(mitre_tactics.items(), key=lambda x: x[1], reverse=True)[:10]
        if not sorted_tactics:
            return ""
        
        labels = [t[0] for t in reversed(sorted_tactics)]
        counts = [t[1] for t in reversed(sorted_tactics)]
        
        # ATT&CK-themed gradient colors
        cmap = plt.cm.get_cmap('RdYlBu_r')
        bar_colors = [cmap(i / max(len(counts), 1)) for i in range(len(counts))]
        
        fig, ax = plt.subplots(figsize=(10, 4))
        bars = ax.barh(labels, counts, color=bar_colors, edgecolor='white', linewidth=0.5, height=0.6)
        
        for bar, count in zip(bars, counts):
            ax.text(bar.get_width() + max(counts) * 0.02, bar.get_y() + bar.get_height()/2,
                    f'{count:,}', va='center', fontsize=8, fontweight='bold', color='#374151')
        
        ax.set_xlabel('Alert Count', fontsize=9, fontweight='bold', color='#64748b')
        ax.set_title('MITRE ATT&CK Coverage', fontsize=11, fontweight='bold', color='#0f172a', pad=10)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_color('#e2e8f0')
        ax.spines['bottom'].set_color('#e2e8f0')
        ax.tick_params(axis='y', labelsize=9)
        ax.tick_params(axis='x', labelsize=8)
        ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f'{int(x):,}'))
        
        plt.tight_layout()
        return _fig_to_base64(fig, plt)
    except Exception as e:
        logger.warning(f"Failed to create MITRE chart: {e}")
        return ""


def _fig_to_base64(fig, plt) -> str:
    """Convert a matplotlib figure to a base64 data URI."""
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=180, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close(fig)
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode()
    return f"data:image/png;base64,{b64}"


def basic_markdown_to_html(md: str) -> str:
    """
    Basic Markdown to HTML conversion without external dependencies.
    Handles common markdown elements.
    """
    html = md
    
    # Headers
    html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
    
    # Bold and italic
    html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
    html = re.sub(r'\*(.+?)\*', r'<em>\1</em>', html)
    
    # Code blocks
    html = re.sub(r'```(\w*)\n(.*?)\n```', r'<pre><code>\2</code></pre>', html, flags=re.DOTALL)
    html = re.sub(r'`(.+?)`', r'<code>\1</code>', html)
    
    # Lists
    html = re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=re.MULTILINE)
    html = re.sub(r'^(\d+)\. (.+)$', r'<li>\2</li>', html, flags=re.MULTILINE)
    
    # Wrap consecutive list items
    html = re.sub(r'(<li>.*?</li>\n?)+', r'<ul>\g<0></ul>', html)
    
    # Horizontal rules
    html = re.sub(r'^---+$', r'<hr>', html, flags=re.MULTILINE)
    
    # Paragraphs
    html = re.sub(r'\n\n+', r'</p><p>', html)
    html = f'<p>{html}</p>'
    
    # Clean up
    html = html.replace('<p></p>', '')
    html = html.replace('<p><h', '<h')
    html = html.replace('</h1></p>', '</h1>')
    html = html.replace('</h2></p>', '</h2>')
    html = html.replace('</h3></p>', '</h3>')
    
    return html


def save_html_report(
    markdown_content: str,
    filename: Optional[str] = None,
    stats: Dict = None,
    report_metadata: Dict = None,
) -> str:
    """
    Save analysis report as HTML file.
    
    Args:
        markdown_content: Markdown content to convert
        filename: Optional custom filename
        stats: Optional alert statistics for chart generation
        report_metadata: Optional metadata for cover page
    
    Returns:
        Path to saved file
    """
    if not filename:
        filename = generate_report_filename(extension="html")
    
    filepath = REPORTS_DIR / filename
    
    html_content = markdown_to_html(markdown_content, stats=stats, report_metadata=report_metadata)
    filepath.write_text(html_content, encoding="utf-8")
    
    logger.info(f"HTML report saved: {filepath}")
    return str(filepath)


def save_pdf_report(
    markdown_content: str,
    filename: Optional[str] = None,
    stats: Dict = None,
    report_metadata: Dict = None,
) -> Optional[str]:
    """
    Save analysis report as PDF file.
    
    Requires weasyprint or pdfkit to be installed.
    Falls back to HTML if PDF generation fails.
    
    Args:
        markdown_content: Markdown content to convert
        filename: Optional custom filename
        stats: Optional alert statistics for chart generation
        report_metadata: Optional metadata for cover page
    
    Returns:
        Path to saved file, or None if failed
    """
    if not filename:
        filename = generate_report_filename(extension="pdf")
    
    filepath = REPORTS_DIR / filename
    html_content = markdown_to_html(markdown_content, stats=stats, report_metadata=report_metadata)
    
    # Try weasyprint first (better quality)
    try:
        from weasyprint import HTML
        # Use custom URL fetcher to handle base64 logo images
        custom_fetcher = create_weasyprint_url_fetcher()
        HTML(string=html_content, url_fetcher=custom_fetcher).write_pdf(str(filepath))
        logger.info(f"PDF report saved (weasyprint): {filepath}")
        return str(filepath)
    except ImportError:
        logger.warning("weasyprint not installed, trying pdfkit...")
    except Exception as e:
        logger.warning(f"weasyprint failed: {e}, trying pdfkit...")
    
    # Try pdfkit (requires wkhtmltopdf)
    try:
        import pdfkit
        pdfkit.from_string(html_content, str(filepath))
        logger.info(f"PDF report saved (pdfkit): {filepath}")
        return str(filepath)
    except ImportError:
        logger.warning("pdfkit not installed")
    except Exception as e:
        logger.warning(f"pdfkit failed: {e}")
    
    # Fallback: save as HTML
    logger.warning("PDF generation unavailable. Saving as HTML instead.")
    html_path = save_html_report(markdown_content, filename.replace('.pdf', '.html'))
    return html_path


def create_weasyprint_url_fetcher():
    """
    Create a custom URL fetcher for WeasyPrint that handles:
    - Base64 data URIs (for embedded logos)
    - Local file paths
    - HTTP URLs
    """
    from weasyprint import default_url_fetcher
    import re
    
    def custom_fetcher(url, timeout=10, ssl_context=None):
        # Handle base64 data URIs
        if url.startswith('data:'):
            match = re.match(r'data:([^;,]+)(?:;base64)?,(.+)', url)
            if match:
                mime_type = match.group(1)
                data = match.group(2)
                try:
                    decoded_data = base64.b64decode(data)
                    return {
                        'string': decoded_data,
                        'mime_type': mime_type,
                    }
                except Exception as e:
                    logger.warning(f"Failed to decode data URI: {e}")
        
        # Handle local file paths
        if url.startswith('file://'):
            file_path = url[7:]
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                # Detect mime type
                if file_path.endswith('.png'):
                    mime_type = 'image/png'
                elif file_path.endswith('.jpg') or file_path.endswith('.jpeg'):
                    mime_type = 'image/jpeg'
                elif file_path.endswith('.svg'):
                    mime_type = 'image/svg+xml'
                else:
                    mime_type = 'application/octet-stream'
                return {
                    'string': content,
                    'mime_type': mime_type,
                }
            except Exception as e:
                logger.warning(f"Failed to read local file {file_path}: {e}")
        
        # Fall back to default fetcher for HTTP URLs
        return default_url_fetcher(url, timeout=timeout, ssl_context=ssl_context)
    
    return custom_fetcher


def get_report_as_bytes(content: str, format: str = "md", stats: Dict = None, report_metadata: Dict = None) -> tuple:
    """
    Get report content as bytes for download.
    
    Args:
        content: Markdown content
        format: 'md', 'html', 'pdf', or 'json'
        stats: Optional alert statistics for chart generation
        report_metadata: Optional metadata for cover page
    
    Returns:
        Tuple of (bytes, mime_type, filename)
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format == "md":
        return (
            content.encode('utf-8'),
            "text/markdown",
            f"SIR_{timestamp}.md"
        )
    
    elif format == "html":
        html = markdown_to_html(content, stats=stats, report_metadata=report_metadata)
        return (
            html.encode('utf-8'),
            "text/html",
            f"SIR_{timestamp}.html"
        )
    
    elif format == "pdf":
        html = markdown_to_html(content, stats=stats, report_metadata=report_metadata)
        try:
            from weasyprint import HTML
            pdf_buffer = io.BytesIO()
            
            # Use custom URL fetcher to properly handle base64 images
            custom_fetcher = create_weasyprint_url_fetcher()
            HTML(string=html, url_fetcher=custom_fetcher).write_pdf(pdf_buffer)
            
            return (
                pdf_buffer.getvalue(),
                "application/pdf",
                f"SIR_{timestamp}.pdf"
            )
        except ImportError:
            # Fallback to HTML
            return (
                html.encode('utf-8'),
                "text/html",
                f"SIR_{timestamp}.html"
            )
    
    return (content.encode('utf-8'), "text/plain", f"report_{timestamp}.txt")


def list_saved_reports() -> list:
    """List all saved reports in the reports directory."""
    reports = []
    for file in REPORTS_DIR.glob("*"):
        if file.is_file():
            reports.append({
                "name": file.name,
                "path": str(file),
                "size": file.stat().st_size,
                "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
            })
    return sorted(reports, key=lambda x: x["modified"], reverse=True)
