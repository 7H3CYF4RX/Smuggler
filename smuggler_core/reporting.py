"""HTML and JSON report generation for vulnerability findings."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List

from .types import Vulnerability, VulnType


class ReportGenerator:
    """Generate comprehensive HTML and JSON reports."""

    @staticmethod
    def generate_html_report(
        vulnerabilities: List[Vulnerability],
        domain: str,
        output_path: Path,
        scan_duration: float,
    ) -> None:
        """Generate a detailed HTML report with PoC payloads."""
        verified = [v for v in vulnerabilities if v.verified]
        potential = [v for v in vulnerabilities if not v.verified]

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smuggler - HTTP Request Smuggling Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card h3 {{
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        .summary-card.critical .value {{
            color: #dc3545;
        }}
        .summary-card.warning .value {{
            color: #ffc107;
        }}
        .content {{
            padding: 30px;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        .vulnerability {{
            background: #f8f9fa;
            border-left: 5px solid #dc3545;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        .vulnerability.potential {{
            border-left-color: #ffc107;
        }}
        .vulnerability h3 {{
            color: #333;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .badge.verified {{
            background: #dc3545;
            color: white;
        }}
        .badge.potential {{
            background: #ffc107;
            color: #333;
        }}
        .badge.type {{
            background: #667eea;
            color: white;
        }}
        .confidence {{
            margin: 10px 0;
            font-weight: 500;
        }}
        .confidence-bar {{
            background: #e9ecef;
            height: 20px;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 5px;
        }}
        .confidence-fill {{
            height: 100%;
            background: linear-gradient(90deg, #ffc107, #dc3545);
            transition: width 0.3s ease;
        }}
        .payload {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.5;
        }}
        .evidence {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            border: 1px solid #e9ecef;
        }}
        .evidence h4 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        .evidence-item {{
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid #f0f0f0;
        }}
        .evidence-item:last-child {{
            border-bottom: none;
        }}
        .evidence-key {{
            font-weight: 600;
            color: #333;
        }}
        .evidence-value {{
            color: #666;
            font-family: 'Courier New', monospace;
            word-break: break-all;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e9ecef;
        }}
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #666;
        }}
        .no-findings h3 {{
            color: #28a745;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 HTTP Request Smuggling Report</h1>
            <p>Advanced Detection & Analysis</p>
        </div>

        <div class="summary">
            <div class="summary-card critical">
                <h3>Verified Vulnerabilities</h3>
                <div class="value">{len(verified)}</div>
            </div>
            <div class="summary-card warning">
                <h3>Potential Issues</h3>
                <div class="value">{len(potential)}</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{len(vulnerabilities)}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <div class="value">{scan_duration:.2f}s</div>
            </div>
        </div>

        <div class="content">
            <div class="section">
                <h2>📋 Scan Information</h2>
                <div class="evidence">
                    <div class="evidence-item">
                        <span class="evidence-key">Target Domain:</span>
                        <span class="evidence-value">{domain}</span>
                    </div>
                    <div class="evidence-item">
                        <span class="evidence-key">Scan Date:</span>
                        <span class="evidence-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                    </div>
                    <div class="evidence-item">
                        <span class="evidence-key">Scan Duration:</span>
                        <span class="evidence-value">{scan_duration:.2f} seconds</span>
                    </div>
                </div>
            </div>

            {ReportGenerator._generate_verified_section(verified)}
            {ReportGenerator._generate_potential_section(potential)}
            {ReportGenerator._generate_no_findings_section(vulnerabilities)}
        </div>

        <div class="footer">
            <p>Generated by Smuggler - Advanced HTTP Request Smuggling Scanner</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        output_path.write_text(html_content, encoding="utf-8")

    @staticmethod
    def _generate_verified_section(vulnerabilities: List[Vulnerability]) -> str:
        if not vulnerabilities:
            return ""

        html = '<div class="section"><h2>🚨 Verified Vulnerabilities</h2>'
        for vuln in vulnerabilities:
            html += f"""
            <div class="vulnerability">
                <h3>
                    {vuln.vuln_type.short}
                    <span class="badge verified">VERIFIED</span>
                    <span class="badge type">{vuln.technique}</span>
                </h3>
                <p><strong>URL:</strong> {vuln.url}</p>
                <div class="confidence">
                    Confidence: {vuln.confidence:.1%}
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: {vuln.confidence*100}%"></div>
                    </div>
                </div>
                <p><strong>Server Behavior:</strong> {vuln.server_behavior}</p>
                <div class="payload"><pre>{ReportGenerator._escape_html(vuln.payload)}</pre></div>
                <div class="evidence">
                    <h4>Evidence</h4>
                    {ReportGenerator._generate_evidence_items(vuln.evidence)}
                </div>
            </div>
            """
        html += "</div>"
        return html

    @staticmethod
    def _generate_potential_section(vulnerabilities: List[Vulnerability]) -> str:
        if not vulnerabilities:
            return ""

        html = '<div class="section"><h2>⚠️ Potential Issues</h2>'
        for vuln in vulnerabilities:
            html += f"""
            <div class="vulnerability potential">
                <h3>
                    {vuln.vuln_type.short}
                    <span class="badge potential">POTENTIAL</span>
                    <span class="badge type">{vuln.technique}</span>
                </h3>
                <p><strong>URL:</strong> {vuln.url}</p>
                <div class="confidence">
                    Confidence: {vuln.confidence:.1%}
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: {vuln.confidence*100}%"></div>
                    </div>
                </div>
                <p><strong>Server Behavior:</strong> {vuln.server_behavior}</p>
                <div class="payload"><pre>{ReportGenerator._escape_html(vuln.payload)}</pre></div>
                <div class="evidence">
                    <h4>Evidence</h4>
                    {ReportGenerator._generate_evidence_items(vuln.evidence)}
                </div>
            </div>
            """
        html += "</div>"
        return html

    @staticmethod
    def _generate_no_findings_section(vulnerabilities: List[Vulnerability]) -> str:
        if vulnerabilities:
            return ""
        return """
        <div class="section">
            <div class="no-findings">
                <h3>✅ No Vulnerabilities Detected</h3>
                <p>The target appears to be properly configured and not vulnerable to HTTP request smuggling attacks.</p>
            </div>
        </div>
        """

    @staticmethod
    def _generate_evidence_items(evidence: dict) -> str:
        html = ""
        for key, value in evidence.items():
            html += f"""
            <div class="evidence-item">
                <span class="evidence-key">{key}:</span>
                <span class="evidence-value">{value}</span>
            </div>
            """
        return html

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    @staticmethod
    def generate_json_report(
        vulnerabilities: List[Vulnerability],
        domain: str,
        output_path: Path,
        scan_duration: float,
    ) -> None:
        """Generate a JSON report for programmatic access."""
        report = {
            "metadata": {
                "domain": domain,
                "scan_date": datetime.now().isoformat(),
                "scan_duration": scan_duration,
                "total_findings": len(vulnerabilities),
                "verified_count": len([v for v in vulnerabilities if v.verified]),
                "potential_count": len([v for v in vulnerabilities if not v.verified]),
            },
            "findings": [
                {
                    "url": v.url,
                    "type": v.vuln_type.short,
                    "description": v.vuln_type.desc,
                    "technique": v.technique,
                    "confidence": v.confidence,
                    "verified": v.verified,
                    "false_positive_score": v.false_positive_score,
                    "server_behavior": v.server_behavior,
                    "payload": v.payload,
                    "evidence": v.evidence,
                }
                for v in vulnerabilities
            ],
        }

        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
