# Smuggler - Quick Start Guide

## 30-Second Setup

```bash
# Install
pip install aiohttp

# Run
python smuggler.py example.com --aggressive --report findings.html

# View results
open findings.html  # or your browser
```

## Common Commands

### 1. Basic Scan
```bash
python smuggler.py example.com
```
Scans the target with default settings (15 threads, 500 URLs max).

### 2. Aggressive Scan
```bash
python smuggler.py example.com --aggressive
```
Enables endpoint brute-forcing and parameter discovery.

### 3. Fast Scan (High Concurrency)
```bash
python smuggler.py example.com --aggressive --threads 50 --max-urls 200
```
Faster but more aggressive. Adjust threads based on target stability.

### 4. Detailed Scan (High Accuracy)
```bash
python smuggler.py example.com --baseline-samples 10 --threads 10
```
More baseline samples = more accurate timing detection.

### 5. Generate Report
```bash
python smuggler.py example.com --aggressive --report report.html
```
Creates both `report.html` and `report.json`.

### 6. Debug Mode
```bash
python smuggler.py example.com --log-level DEBUG --log-file debug.log
```
Detailed logging for troubleshooting.

### 7. Stealth Mode
```bash
python smuggler.py example.com --threads 3 --baseline-samples 2
```
Slower, less detectable. Good for sensitive targets.

## Understanding Results

### Terminal Output

**Verified Vulnerabilities** 🚨
- High confidence (90%+)
- Multiple validation passes
- Ready for exploitation

**Potential Issues** ⚠️
- Medium confidence (60-85%)
- Needs manual verification
- Possible false positives

### HTML Report

1. **Summary Cards** - Quick overview of findings
2. **Verified Section** - Critical vulnerabilities
3. **Potential Section** - Needs investigation
4. **Payloads** - Exact requests used
5. **Evidence** - Supporting data

### JSON Report

Machine-readable format for:
- Automated processing
- Integration with other tools
- Archival and tracking

## Vulnerability Types at a Glance

| Type | Risk | Detection | Exploitation |
|------|------|-----------|---------------|
| **CL.TE** | 🔴 High | Timing + Response | Request smuggling |
| **TE.CL** | 🔴 High | Response poisoning | Cache poisoning |
| **TE.TE** | 🟡 Medium | Response diff | Obfuscation bypass |
| **CL.CL** | 🟡 Medium | Unusual response | Request smuggling |
| **HTTP/2** | 🟡 Medium | h2c upgrade | Protocol downgrade |
| **Header** | 🟡 Medium | Header diff | Normalization bypass |
| **Prefix** | 🟡 Medium | Injected content | Cache poisoning |

## Configuration File

Create `config.json`:
```json
{
  "threads": 20,
  "aggressive": true,
  "max_urls": 300,
  "baseline_samples": 5,
  "log_level": "INFO"
}
```

Use it:
```bash
python smuggler.py example.com --config config.json
```

## Performance Tuning

### Slow Network / Unstable Target
```bash
python smuggler.py example.com \
  --threads 5 \
  --baseline-samples 3 \
  --max-urls 100
```

### Fast Network / Stable Target
```bash
python smuggler.py example.com \
  --aggressive \
  --threads 50 \
  --max-urls 1000
```

### Balanced (Recommended)
```bash
python smuggler.py example.com \
  --aggressive \
  --threads 20 \
  --max-urls 500
```

## Interpreting Confidence Scores

- **95%+** - Almost certainly vulnerable
- **85-95%** - Very likely vulnerable
- **70-85%** - Probably vulnerable
- **60-70%** - Possibly vulnerable
- **<60%** - Needs manual verification

## False Positive Scores

- **<5%** - Very reliable finding
- **5-10%** - Reliable finding
- **10-20%** - Needs verification
- **>20%** - High false positive risk

## Common Issues

### No URLs Found
```bash
# Try aggressive mode
python smuggler.py example.com --aggressive

# Or increase max URLs
python smuggler.py example.com --max-urls 1000
```

### Slow Scan
```bash
# Reduce baseline samples
python smuggler.py example.com --baseline-samples 2

# Increase threads
python smuggler.py example.com --threads 50

# Reduce URLs
python smuggler.py example.com --max-urls 200
```

### Too Many False Positives
```bash
# Check confidence scores in report
# Focus on findings with >85% confidence
# Verify manually using payloads in report
```

### Connection Errors
```bash
# Check domain is accessible
ping example.com

# Try with debug logging
python smuggler.py example.com --log-level DEBUG
```

## Real-World Examples

### Burp Suite Lab
```bash
python smuggler.py 0a1b0046036d454a80c89e1d00f20011.web-security-academy.net \
  --aggressive \
  --threads 20 \
  --report lab_findings.html
```

### Internal API
```bash
python smuggler.py api.internal.local \
  --threads 30 \
  --max-urls 200 \
  --report api_audit.html
```

### Production Audit
```bash
python smuggler.py production.example.com \
  --aggressive \
  --threads 15 \
  --baseline-samples 10 \
  --report production_audit.html \
  --log-file audit.log
```

## Next Steps

1. **Review Report** - Open HTML report in browser
2. **Verify Findings** - Check confidence scores
3. **Manual Testing** - Use payloads from report
4. **Document Results** - Save JSON report
5. **Remediate** - Fix identified vulnerabilities

## Tips & Tricks

### Save Results
```bash
# Both HTML and JSON
python smuggler.py example.com --report results/$(date +%Y%m%d_%H%M%S).html
```

### Batch Scanning
```bash
# Scan multiple domains
for domain in example.com test.com demo.com; do
  python smuggler.py $domain --report reports/$domain.html
done
```

### Continuous Monitoring
```bash
# Add to crontab for daily scans
0 2 * * * cd /opt/smuggler && python smuggler.py target.com --report reports/$(date +\%Y\%m\%d).html
```

### Integration
```bash
# Parse JSON report programmatically
python -c "
import json
report = json.load(open('report.json'))
for finding in report['findings']:
    if finding['verified']:
        print(f\"CRITICAL: {finding['url']} - {finding['type']}\")
"
```

## Support

- **Documentation**: See `README.md`
- **Implementation Details**: See `IMPLEMENTATION_SUMMARY.md`
- **Issues**: Check terminal output and debug logs
- **Questions**: Review example commands above

---

**Ready to scan?** Start with:
```bash
python smuggler.py example.com --aggressive --report findings.html
```
