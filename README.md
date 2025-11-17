# 🔍 Smuggler - Advanced HTTP Request Smuggling Scanner

A comprehensive, production-ready tool for detecting HTTP request smuggling vulnerabilities with deep validation and detailed reporting.

## Features

### ✨ Comprehensive Detection
- **CL.TE** - Content-Length vs Transfer-Encoding desynchronization
- **TE.CL** - Transfer-Encoding vs Content-Length with response queue poisoning
- **TE.TE** - Transfer-Encoding obfuscation variants
- **CL.CL** - Dual Content-Length conflicts
- **HTTP/2 Smuggling** - h2c upgrade and pseudo-header attacks
- **Header Smuggling** - Header normalization differences
- **Prefix Injection** - Cache poisoning via request prefixes

### 📊 Advanced Analysis
- **Timing-based detection** with statistical anomaly detection
- **Response fingerprinting** for differential analysis
- **Deep validation** with confidence scoring
- **False positive scoring** for result prioritization

### 📈 Professional Reporting
- **HTML Reports** with interactive vulnerability details
- **JSON Reports** for programmatic integration
- **PoC Payloads** included in reports
- **Evidence-based findings** with detailed analysis

### 🚀 Performance
- **Concurrent scanning** with configurable thread limits
- **Adaptive baselines** for accurate detection
- **Efficient URL enumeration** with multiple discovery methods
- **Smart caching** to avoid redundant tests

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/smuggler.git
cd smuggler

# Install dependencies
pip install aiohttp

# Make it executable
chmod +x smuggler.py
```

## Quick Start

### Basic Scan
```bash
python smuggler.py example.com
```

### Aggressive Scan with Threading
```bash
python smuggler.py example.com --aggressive --threads 30
```

### Generate HTML Report
```bash
python smuggler.py example.com --aggressive --report findings.html
```

### Full Scan with All Options
```bash
python smuggler.py example.com \
  --aggressive \
  --threads 20 \
  --max-urls 300 \
  --baseline-samples 5 \
  --report report.html \
  --log-level DEBUG
```

## Command-Line Options

```
usage: smuggler.py [-h] [--config CONFIG] [--threads THREADS] 
                   [--max-urls MAX_URLS] [--baseline-samples BASELINE_SAMPLES]
                   [--aggressive | --no-aggressive] 
                   [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                   [--log-file LOG_FILE] [--log-json | --no-log-json]
                   [--report REPORT] [--urls-file URLS_FILE]
                   domain

Positional Arguments:
  domain                Target domain to scan (e.g., example.com)

Optional Arguments:
  --config CONFIG       Path to JSON config file
  --threads N           Concurrent request limit (default: 15)
  --max-urls N          Maximum URLs to discover (default: 500)
  --baseline-samples N  Requests for timing baseline (default: 5)
  --aggressive          Enable aggressive enumeration modes
  --log-level LEVEL     Logging verbosity (default: INFO)
  --log-file FILE       Optional log file path
  --log-json            Emit logs in JSON format
  --report FILE         Path to save HTML report
  --urls-file FILE      Path to file with seed URLs
```

## Configuration File

Create a `config.json` for persistent settings:

```json
{
  "threads": 20,
  "aggressive": true,
  "max_urls": 300,
  "baseline_samples": 5,
  "log_level": "INFO",
  "log_json": false
}
```

Then use it:
```bash
python smuggler.py example.com --config config.json
```

## Vulnerability Types Explained

### CL.TE (Content-Length vs Transfer-Encoding)
Front-end uses Content-Length, back-end uses Transfer-Encoding. Attacker can smuggle requests by:
1. Sending a request with both headers
2. Front-end processes by Content-Length
3. Back-end processes by Transfer-Encoding
4. Smuggled content reaches back-end

**PoC Payload:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

### TE.CL (Transfer-Encoding vs Content-Length)
Front-end uses Transfer-Encoding, back-end uses Content-Length. Enables response queue poisoning.

**PoC Payload:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

44
GPOST / HTTP/1.1
Host: localhost
Content-Length: 10

x=
0

```

### TE.TE (Transfer-Encoding Obfuscation)
Both use Transfer-Encoding but handle obfuscation differently.

**Variants:**
- Double TE headers
- Case variation (Transfer-encoding vs Transfer-Encoding)
- Space variations
- Tab separators
- Line wrapping

### CL.CL (Dual Content-Length)
Multiple Content-Length headers with conflicting values.

### HTTP/2 Smuggling
Exploits h2c upgrade mechanisms or pseudo-header handling.

### Header Smuggling
Exploits differences in header normalization (X-Forwarded-For, Host, etc.)

### Prefix Injection
Injects request prefixes to poison caches or bypass security controls.

## Understanding Reports

### HTML Report
Open `report.html` in a browser to see:
- **Summary Statistics** - Verified vs potential findings
- **Detailed Findings** - Each vulnerability with evidence
- **PoC Payloads** - Exact payloads used for detection
- **Confidence Scores** - Reliability of each finding
- **False Positive Scores** - Likelihood of false positive

### JSON Report
Machine-readable format for integration:
```json
{
  "metadata": {
    "domain": "example.com",
    "scan_date": "2024-01-15T10:30:00",
    "total_findings": 3,
    "verified_count": 2
  },
  "findings": [
    {
      "url": "https://example.com/api",
      "type": "CL.TE",
      "technique": "CL.TE - Basic",
      "confidence": 0.95,
      "verified": true,
      "payload": "...",
      "evidence": {...}
    }
  ]
}
```

## Detection Methodology

### 1. Baseline Establishment
- Collect normal response timing and fingerprints
- Build statistical profile for anomaly detection

### 2. Payload Testing
- Send crafted smuggling payloads
- Monitor for timing anomalies
- Analyze response differences

### 3. Deep Validation
- Verify findings with follow-up tests
- Check for response queue poisoning
- Validate timing patterns

### 4. Confidence Scoring
- Combine multiple signals
- Calculate false positive probability
- Prioritize high-confidence findings

## Performance Tips

### For Large Targets
```bash
python smuggler.py example.com \
  --aggressive \
  --threads 50 \
  --max-urls 1000 \
  --baseline-samples 3
```

### For Stealth
```bash
python smuggler.py example.com \
  --threads 5 \
  --baseline-samples 2 \
  --log-level WARNING
```

### For Accuracy
```bash
python smuggler.py example.com \
  --aggressive \
  --threads 15 \
  --baseline-samples 10 \
  --max-urls 500
```

## Troubleshooting

### No URLs Found
- Check domain is accessible
- Try `--aggressive` flag
- Verify network connectivity

### False Positives
- Check confidence scores in report
- Review false positive scores
- Verify findings manually

### Slow Scans
- Reduce `--baseline-samples`
- Increase `--threads`
- Reduce `--max-urls`

### SSL Errors
- Tool accepts self-signed certificates by default
- For strict validation, modify `runner.py`

## Example Scenarios

### Scan Burp Suite Lab
```bash
python smuggler.py 0a1b0046036d454a80c89e1d00f20011.web-security-academy.net \
  --aggressive \
  --threads 20 \
  --report lab_findings.html
```

### Scan Internal API
```bash
python smuggler.py api.internal.local \
  --threads 30 \
  --max-urls 200 \
  --report api_audit.html
```

### Continuous Monitoring
```bash
# Create a cron job
0 2 * * * cd /opt/smuggler && python smuggler.py target.com --report reports/$(date +\%Y\%m\%d).html
```

## Advanced Usage

### Custom Configuration
```python
from smuggler_core import SmugglerConfig, SmugglerRunner, configure_logging

config = SmugglerConfig(
    domain="example.com",
    threads=20,
    aggressive=True,
    max_urls=500,
    baseline_samples=5,
)

logger = configure_logging(level="INFO", json_logs=False)
runner = SmugglerRunner(config, logger)

import asyncio
asyncio.run(runner.run())
```

### Programmatic Integration
```python
import json
from pathlib import Path

# Read JSON report
report = json.loads(Path("report.json").read_text())

for finding in report["findings"]:
    if finding["verified"]:
        print(f"CRITICAL: {finding['url']} - {finding['type']}")
```

## Security Considerations

- **Rate Limiting**: Adjust `--threads` to avoid DoS detection
- **Stealth**: Use lower thread counts and longer delays
- **Authorization**: Only scan systems you own or have permission to test
- **Logging**: Enable `--log-file` for audit trails

## Contributing

Contributions welcome! Areas for improvement:
- Additional payload variants
- Machine learning-based detection
- Textual UI implementation
- Integration with other tools

## License

MIT License - See LICENSE file

## Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before scanning.

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review example reports

---

**Smuggler** - Making HTTP Request Smuggling Detection Simple and Effective
