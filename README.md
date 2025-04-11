# DorkSide - Advanced Security Dork Scanner

![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

DorkSide is an advanced security-oriented dork scanner designed to help security researchers and penetration testers discover sensitive information and potential vulnerabilities using Google dorks.

## Features

- **Multi-engine support**: Currently supports Google with extensible architecture
- **Smart URL extraction**: Advanced pattern matching for finding relevant URLs
- **User-Agent rotation**: Automatic rotation to avoid detection
- **Rate limiting**: Configurable delay between requests
- **Proxy support**: Optional proxy configuration for anonymity
- **Comprehensive reporting**: JSON and HTML report generation
- **Interesting file detection**: Flags potentially sensitive files (PDFs, docs, etc.)
- **Tracking parameter removal**: Cleans URLs by removing tracking parameters
- **Asynchronous processing**: Efficient concurrent scanning

## Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Installation Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/Cyberdemon73/DorkSide.git
   cd dorkside
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `security_dorks.json` configuration file (see example below), Or You can use mine if you like.

## Usage

### Basic Usage
```bash
python dorkside.py example.com
```

### Advanced Options
```bash
python dorkside.py example.com \
  -c custom_dorks.json \
  -o ./scan_results \
  -t 10 \
  -r 2.0 \
  -T 45 \
  -R 5 \
  -p socks5://127.0.0.1:9050 \
  -v
```

### Command Line Arguments
| Argument | Description | Default |
|----------|-------------|---------|
| `domain` | Target domain to scan | Required |
| `-c, --config` | Path to dorks configuration file | `security_dorks.json` |
| `-o, --output` | Output directory for results | `results` |
| `-t, --threads` | Number of concurrent threads | `5` |
| `-r, --rate-limit` | Rate limit between requests (seconds) | `1.0` |
| `-T, --timeout` | Request timeout (seconds) | `30` |
| `-R, --retries` | Maximum retries for failed requests | `3` |
| `-p, --proxy` | Proxy URL (e.g., `socks5://127.0.0.1:9050`) | None |
| `-v, --verbose` | Enable verbose output | False |

## Configuration File

Create a JSON file with your dork categories and queries. Example `security_dorks.json`:

```json
{
  "security_dorks": {
    "sensitive_files": [
      "site:example.com filetype:pdf",
      "site:example.com ext:docx"
    ],
    "login_pages": [
      "site:example.com inurl:login",
      "site:example.com intitle:\"login\""
    ],
    "admin_panels": [
      "site:example.com inurl:admin",
      "site:example.com intitle:\"admin\""
    ],
    "database_files": [
      "site:example.com ext:sql",
      "site:example.com ext:db"
    ],
    "config_files": [
      "site:example.com ext:env",
      "site:example.com ext:conf"
    ]
  }
}
```

## Sample Output

```
╔══════════════════════════════════════════╗
║        Enhanced Security Dork Scanner       ║
╚══════════════════════════════════════════╝
        
Target Domain: example.com
Start Time: 2023-07-15 14:30:22
Output Directory: results
Threads: 5
Rate Limit: 1.0 seconds

[+] Processing category: sensitive_files
Processing dork: site:example.com filetype:pdf
Using User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
✓ Found 12 URLs from google

Category Summary:
├─ Successful scans: 2/2
└─ Total URLs found: 18

✓ Results saved to: results/scan_results_20230715_143022.json
✓ HTML report generated: results/scan_report_20230715_143022.html
```

## Report Samples

### JSON Report
```json
{
  "sensitive_files": [
    {
      "dork": "site:example.com filetype:pdf",
      "engine": "google",
      "status": "success",
      "urls_found": [
        "https://example.com/docs/confidential.pdf",
        "https://example.com/reports/2023-financial.pdf"
      ],
      "count": 2
    }
  ]
}
```

### HTML Report
The HTML report provides a visual overview of the scan results with categorized findings.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for legal security research and penetration testing only. The developers are not responsible for any misuse of this software. Always obtain proper authorization before scanning any systems.
