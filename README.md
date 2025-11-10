# Subdomain Takeover Scanner

A Python tool for detecting potential subdomain takeover vulnerabilities by checking subdomains against known cloud services and their CNAME records.

## Overview

This script scans a list of subdomains to identify potential subdomain takeover vulnerabilities. It performs DNS lookups to find CNAME records, matches them against a database of known cloud services, and performs HTTP checks to verify potential vulnerabilities.

**Subdomain takeover** occurs when a subdomain (e.g., `subdomain.example.com`) points to a service (like GitHub Pages, Heroku, etc.) that has been removed or deleted. This allows an attacker to claim the subdomain by setting up a page on the service that was previously being used.

## Features

### Current Features
- ✅ DNS CNAME record enumeration for subdomains
- ✅ Cloud service detection via CNAME matching
- ✅ **Vulnerability status checking** based on [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) database
- ✅ **Automatic verification** of whether a cloud service is actually vulnerable or has been patched
- ✅ **Fingerprint matching** for accurate vulnerability detection
- ✅ **NXDOMAIN checking** for services that require non-existent domains
- ✅ **HTTP status code verification** for specific vulnerability patterns
- ✅ **CI/CD verification status** display
- ✅ HTTP vulnerability verification
- ✅ Colorized console output for easy reading
- ✅ Support for multiple cloud services (AWS, Azure, GitHub, Heroku, etc.)
- ✅ Backward compatibility with legacy cloud_services.json format

## Installation

### Prerequisites
- Python 3.6 or higher
- pip (Python package installer)

### Steps

1. Clone or download this repository:
```bash
git clone <repository-url>
cd SubdomainTakeOver
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

The required packages are:
- `colorama` - For colored terminal output
- `dnspython` - For DNS resolution
- `requests` - For HTTP requests

## Usage

### Basic Usage

#### Recommended: Using Fingerprints Database (New)

```bash
python subdomain_takeover.py -f subdomains.txt -p fingerprints.json
```

#### Legacy: Using Cloud Services Database

```bash
python subdomain_takeover.py -f subdomains.txt -s cloud_services.json
```

#### Using Both (Fingerprints Preferred, Cloud Services as Fallback)

```bash
python subdomain_takeover.py -f subdomains.txt -p fingerprints.json -s cloud_services.json
```

### Arguments

- `-f, --file, --filename`: Path to a text file containing a list of subdomains (one per line) **[Required]**
- `-p, --fingerprints`: Path to a JSON file containing fingerprints database (recommended) - e.g., `fingerprints.json`
- `-s, --service, --services`: Path to a JSON file containing cloud service mappings (legacy format) - e.g., `cloud_services.json`

**Note**: At least one of `-p` or `-s` must be provided.

### Examples

```bash
# Using fingerprints database (recommended - includes vulnerability status)
python subdomain_takeover.py -f subdomains.txt -p fingerprints.json

# Using legacy cloud services database
python subdomain_takeover.py -f subdomains.txt -s cloud_services.json

# Using both databases (fingerprints preferred)
python subdomain_takeover.py -f subdomains.txt -p fingerprints.json -s cloud_services.json

# Get help
python subdomain_takeover.py -h
```

### Input File Formats

#### Cloud Services JSON Format (`cloud_services.json`)

This file contains cloud services tracked by the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) project. Format:

```json
{
    "AWS/S3": "s3.amazonaws.com",
    "GitHub Pages": "github.io",
    "Heroku": "herokuapp.com",
    "Microsoft Azure": "azurewebsites.net"
}
```

#### Subdomains File Format (`subdomains.txt`)

```
subdomain1.example.com
subdomain2.example.com
subdomain3.example.com
```

## How It Works

1. **DNS Resolution**: For each subdomain, the script queries DNS for CNAME records
2. **Service Matching**: CNAME records are matched against known cloud service domains using regex
3. **Vulnerability Status Check**: If using fingerprints database:
   - Checks if the service is marked as vulnerable, patched, or edge case
   - Verifies CI/CD testing status
   - Only proceeds with verification for vulnerable services
4. **Fingerprint Verification**: For vulnerable services:
   - Checks for NXDOMAIN (non-existent domain) if required
   - Performs HTTP/HTTPS requests to verify fingerprint patterns
   - Matches response content against known vulnerability fingerprints
   - Verifies HTTP status codes if specified
5. **Output**: Results are displayed with color-coded output indicating:
   - Found CNAME records (Yellow)
   - Matched cloud services with status (Red/Yellow/Green)
   - Confirmed vulnerabilities (Red with 🚨)
   - CI/CD verification status
   - Discussion and documentation links

## Output

The script provides detailed, colorized output showing:
- CNAME records found for each subdomain
- Cloud services that match the CNAME records
- Vulnerability status (Vulnerable, Not vulnerable, Edge case)
- CI/CD verification status
- Fingerprint verification results
- Confirmed vulnerabilities with detailed information
- Discussion and documentation links

### Example Output

```
======================================================================
[*] Checking: subdomain.example.com
======================================================================
CNAMEs found for subdomain.example.com:
  [+] example.github.io

Cloud service matches (with vulnerability status):

  [+] CNAME: example.github.io
     Service: Github
     Status: 🟡 Edge case
     CI/CD Verified: ✗ Not verified
     ⚠ Edge case: Requires manual verification

======================================================================
[*] Checking: vulnerable.example.com
======================================================================
CNAMEs found for vulnerable.example.com:
  [+] example.s3.amazonaws.com

Cloud service matches (with vulnerability status):

  [+] CNAME: example.s3.amazonaws.com
     Service: AWS/S3
     Status: 🔴 Vulnerable
     CI/CD Verified: ✓ Pass
     [*] Verifying vulnerability fingerprint...
     🚨 VULNERABLE: vulnerable.example.com is confirmed vulnerable!
     Fingerprint matched: The specified bucket does not exist
     HTTP Status: 404
     Discussion: [Issue #36](https://github.com/EdOverflow/can-i-take-over-xyz/issues/36)

======================================================================
Summary:
  Total subdomains checked: 2
  Confirmed vulnerable: 1
======================================================================
```

## Configuration Files

### `cloud_services.json`
Contains a mapping of cloud service names to their domain patterns tracked by the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) project. This file lists cloud services that may be vulnerable to subdomain takeover. The file can be customized to include additional services.

### `fingerprints.json`
Contains detailed fingerprint data from the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) project, including:
- Service vulnerability status (`vulnerable`: true/false)
- Service status (`status`: "Vulnerable", "Not vulnerable", "Edge case")
- Fingerprint patterns for detection (regex patterns or "NXDOMAIN")
- CNAME domains (array of possible CNAME patterns)
- NXDOMAIN flag (whether the service requires NXDOMAIN)
- HTTP status codes (if specific status indicates vulnerability)
- CI/CD verification status (`cicd_pass`: true/false)
- Discussion links (GitHub issues)
- Documentation links

**Note**: This is the recommended database format as it includes actual vulnerability status and verification.

## Key Features of Vulnerability Status Checking

The script now integrates with the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) database to:

1. ✅ **Check Vulnerability Status**: Verify if a detected cloud service is actually vulnerable or has been patched
2. ✅ **Fingerprint Matching**: Use specific error messages and fingerprints to confirm vulnerabilities
3. ✅ **NXDOMAIN Detection**: Identify services that require non-existent domains (NXDOMAIN)
4. ✅ **Status Filtering**: Only report services that are confirmed vulnerable (not patched or edge cases)
5. ✅ **CI/CD Verification**: Show whether the vulnerability has been verified by automated CI/CD tests
6. ✅ **Smart Detection**: Skips fingerprint verification for services that are known to be patched or not vulnerable

### Vulnerability Status Types

- **🔴 Vulnerable**: Service is confirmed vulnerable to subdomain takeover
- **🟢 Not vulnerable**: Service has been patched or is not vulnerable
- **🟡 Edge case**: Service may be vulnerable but requires manual verification or specific conditions

## References

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - Comprehensive list of services and subdomain takeover status
- [Subdomain Takeover Guide](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers) - HackerOne's guide on subdomain takeovers
- [Hostile Subdomain Takeover](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/) - Detectify Labs article

## Disclaimer

⚠️ **This tool is for authorized security testing only.**

- Only use this tool on domains you own or have explicit permission to test
- Respect bug bounty program policies and scope
- The authors take no responsibility for misuse of this tool
- Always follow responsible disclosure practices

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

MIT License is a permissive free software license that allows commercial use, modification, distribution, and private use with minimal restrictions.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Author

**Ironsky Team - By Moyindu**

---

**Last Updated**: January 15, 2025
**Version**: 1.0.0

