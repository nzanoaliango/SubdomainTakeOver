# Subdomain Takeover Scanner

A Python tool for detecting potential subdomain takeover vulnerabilities by checking subdomains against known cloud services and their CNAME records.

## Overview

This script scans a list of subdomains to identify potential subdomain takeover vulnerabilities. It performs DNS lookups to find CNAME records, matches them against a database of known cloud services, and performs HTTP checks to verify potential vulnerabilities.

**Subdomain takeover** occurs when a subdomain (e.g., `subdomain.example.com`) points to a service (like GitHub Pages, Heroku, etc.) that has been removed or deleted. This allows an attacker to claim the subdomain by setting up a page on the service that was previously being used.

## Features

- DNS CNAME record enumeration for subdomains
- Cloud service detection via CNAME matching
- **Vulnerability status checking** based on the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) database
- **Automatic verification** of whether a cloud service is actually vulnerable or has been patched
- **Fingerprint matching** for accurate vulnerability detection
- **NXDOMAIN checking** for services that require non-existent domains
- **HTTP status code verification** for specific vulnerability patterns
- **CI/CD verification status** display
- HTTP vulnerability verification
- Colorized console output
- Optional text result file for every subdomain that matches a cloud service
- Built-in `fingerprints.json` and `cloud_services.json`, used unless you pass your own
- Support for multiple cloud services (AWS, Azure, GitHub, Heroku, and others)
- Backward compatibility with the legacy cloud services format

## Installation

### Prerequisites
- Python 3.6 or higher
- pip (Python package installer)

### Steps

1. Clone this repository:
```bash
git clone https://github.com/nzanoaliango/SubdomainTakeOver.git
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

The project ships with `fingerprints.json` and `cloud_services.json`. Those files are used automatically. The only required argument is the subdomain list.

```bash
python subdomain_takeover.py -f subdomains.txt
```

Pass `-p` or `-s` only when you want a different fingerprints or cloud services file.

```bash
python subdomain_takeover.py -f subdomains.txt -p custom_fingerprints.json
python subdomain_takeover.py -f subdomains.txt -s custom_cloud_services.json
```

Write a text result for each subdomain that matches a cloud service:

```bash
python subdomain_takeover.py -f subdomains.txt -o results.txt
```

### Arguments

- `-f, --file, --filename`: Path to a text file containing a list of subdomains (one per line) **[Required]**
- `-p, --fingerprints`: Path to a JSON fingerprints database. Optional. Defaults to `fingerprints.json` in the project directory.
- `-s, --service, --services`: Path to a JSON cloud service mappings file. Optional. Defaults to `cloud_services.json` in the project directory.
- `-o, --output`: Optional path for a text result file. One line for each subdomain that matches a cloud service: the subdomain, the service, and a status of `vulnerable`, `potentially vulnerable`, or `not vulnerable`. Subdomains with no cloud service are omitted.

Fingerprints are preferred. Cloud services are used as a fallback when a CNAME does not match the fingerprints database.

### Examples

```bash
# Scan with the project's fingerprints.json and cloud_services.json
python subdomain_takeover.py -f subdomains.txt

# Use a different fingerprints database
python subdomain_takeover.py -f subdomains.txt -p custom_fingerprints.json

# Use a different cloud services database
python subdomain_takeover.py -f subdomains.txt -s custom_cloud_services.json

# Save a text result for each subdomain that matches a cloud service
python subdomain_takeover.py -f subdomains.txt -o results.txt

# Get help
python subdomain_takeover.py -h
```

### Result file

`-o` writes plain text. The first line is a header, then one line for each subdomain that matches a cloud service:

```
subdomain | cloud service | status
shop.example.com | AWS/S3 | vulnerable
blog.example.com | Github | potentially vulnerable
cdn.example.com | AWS/Load Balancer (ELB) | not vulnerable
```

Subdomains with no matching cloud service are omitted.

- `vulnerable` means the fingerprint check confirmed a takeover.
- `potentially vulnerable` means the service is an edge case, the fingerprint could not be checked, or only the legacy cloud-service list matched.
- `not vulnerable` means the matched service is patched, or the fingerprint did not match.

When several services match one subdomain, the line keeps the most severe status and the service or services that have that status.

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
   - Confirmed vulnerabilities
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
[*] Checking: edge.example.com
======================================================================
CNAMEs found for edge.example.com:
  [+] nonexistent-example.vercel.com.

Cloud service matches (with vulnerability status):

  [+] CNAME: nonexistent-example.vercel.com.
     Service: Vercel
     Status: Edge case
     CI/CD Verified: Not verified
     Edge case: Requires manual verification

======================================================================
[*] Checking: vulnerable.example.com
======================================================================
CNAMEs found for vulnerable.example.com:
  [+] example.s3.amazonaws.com.

Cloud service matches (with vulnerability status):

  [+] CNAME: example.s3.amazonaws.com.
     Service: AWS/S3
     Status: Vulnerable
     CI/CD Verified: Pass
     [*] Verifying vulnerability fingerprint...
     VULNERABLE: vulnerable.example.com is confirmed vulnerable!
        Fingerprint matched: The specified bucket does not exist...
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
Contains a mapping of cloud service names to their domain patterns tracked by the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) project. This file is the default for `-s`. It can be customized, or replaced at runtime with another file.

### `cloud_services_all.json`
A broader cloud-service list, including entries that are not in `cloud_services.json`. Pass it with `-s cloud_services_all.json` when you want that wider set. `all_clouds.txt` is the same service names, one per line, for reference.

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

1.  **Check Vulnerability Status**: Verify if a detected cloud service is actually vulnerable or has been patched
2.  **Fingerprint Matching**: Use specific error messages and fingerprints to confirm vulnerabilities
3.  **NXDOMAIN Detection**: Identify services that require non-existent domains (NXDOMAIN)
4.  **Status reporting**: Show whether a matched service is vulnerable, not vulnerable, or an edge case
5.  **CI/CD Verification**: Show whether the vulnerability has been verified by automated CI/CD tests
6.  **Smart Detection**: Skips fingerprint verification for services that are known to be patched or not vulnerable

### Vulnerability Status Types

- ** Vulnerable**: Service is confirmed vulnerable to subdomain takeover
- ** Not vulnerable**: Service has been patched or is not vulnerable
- ** Edge case**: Service may be vulnerable but requires manual verification or specific conditions

## References

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - Comprehensive list of services and subdomain takeover status
- [Subdomain Takeover Guide](https://www.hackerone.com/blog/Guide-Subdomain-Takeovers) - HackerOne's guide on subdomain takeovers
- [Hostile Subdomain Takeover](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/) - Detectify Labs article

## Disclaimer

**This tool is for authorized security testing only.**

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

**Last Updated**: October 7, 2026
**Version**: 1.1.0

