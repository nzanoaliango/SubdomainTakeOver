#!/usr/bin/env python3
import dns.resolver
import json
import os
import requests
import argparse
import re
import urllib3

from colorama import Fore, Style, init

# Initialize colorama
init()

# Suppress SSL warnings (we use verify=False for compatibility)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ASCII art banner at https://patorjk.com/software/taag/
ascii_banner = r"""
          ______       _         _                   _          _______    _                                  
 / _____)     | |       | |                 (_)        (_______)  | |                                 
( (____  _   _| |__   __| | ___  ____  _____ _ ____        _ _____| |  _ _____  ___ _   _ _____  ____ 
 \____ \| | | |  _ \ / _  |/ _ \|    \(____ | |  _ \      | (____ | |_/ ) ___ |/ _ \ | | | ___ |/ ___)
 _____) ) |_| | |_) | (_| | |_| | | | / ___ | | | | |     | / ___ |  _ (| ____| |_| \ V /| ____| |    
(______/|____/|____/ \____|\___/|_|_|_\_____|_|_| |_|     |_\_____|_| \_)_____)\___/ \_/ |_____)_|    

Ironsky Team - By Moyindu
"""
# Databases shipped with the project. Used unless the user passes -p or -s.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FINGERPRINTS = os.path.join(SCRIPT_DIR, 'fingerprints.json')
DEFAULT_CLOUD_SERVICES = os.path.join(SCRIPT_DIR, 'cloud_services.json')

# Function to define all arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description='Subdomain Takeover Scanner - Detects potential subdomain takeover vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a subdomain list (uses project fingerprints.json and cloud_services.json)
  python subdomain_takeover.py -f subdomains.txt

  # Override the fingerprints database
  python subdomain_takeover.py -f subdomains.txt -p custom_fingerprints.json

  # Override the cloud services database
  python subdomain_takeover.py -f subdomains.txt -s custom_cloud_services.json

  # Write a text result for each subdomain that matches a cloud service
  python subdomain_takeover.py -f subdomains.txt -o results.txt
        """
    )
    parser.add_argument('-f', '--file', '--filename', dest='subdomains_file', required=True,
                       help='Text file containing list of subdomains (one per line)')
    parser.add_argument('-p', '--fingerprints', dest='fingerprints_file',
                       default=DEFAULT_FINGERPRINTS,
                       help='JSON file containing fingerprints database '
                            '(default: fingerprints.json in the project directory)')
    parser.add_argument('-s', '--service', '--services', dest='cloud_services_file',
                       default=DEFAULT_CLOUD_SERVICES,
                       help='JSON file containing cloud services '
                            '(default: cloud_services.json in the project directory)')
    parser.add_argument('-o', '--output', dest='output_file',
                       help='Write a text result for each subdomain that matches a cloud service: '
                            'subdomain, cloud service, and status '
                            '(vulnerable, potentially vulnerable, or not vulnerable). '
                            'Subdomains with no cloud service are omitted')
    return parser.parse_args()

# Function to load cloud services from a JSON file
def load_cloud_services(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        return json.load(file)

# Function to load fingerprints from a JSON file
def load_fingerprints(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        return json.load(file)

# Function to get CNAME records for a subdomain
def get_cnames(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        return [str(rdata.target) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return []

# Function to check if domain resolves (for NXDOMAIN checks)
def check_nxdomain(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return False  # Domain exists, not NXDOMAIN
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return True  # NXDOMAIN - domain doesn't exist
    except Exception:
        return None  # Could not determine

# Function to check if any CNAME matches cloud services using regex
def check_cnames_against_cloud_services(cnames, cloud_services):
    matches = []
    for cname in cnames:
        for service, domain in cloud_services.items():
            # Use regex to find the domain anywhere in the CNAME string
            if re.search(rf"\b{re.escape(domain)}\b", cname):
                matches.append((cname, service))
    return matches

# Function to check if any CNAME matches fingerprints database
def check_cnames_against_fingerprints(cnames, fingerprints):
    matches = []
    for cname in cnames:
        for fingerprint_data in fingerprints:
            service_cnames = fingerprint_data.get('cname', [])
            # Check if any of the service's CNAME patterns match
            for service_cname in service_cnames:
                # Clean service_cname (remove http/https if present)
                clean_service_cname = service_cname.replace('https://', '').replace('http://', '').rstrip('/')
                # Use regex to find the domain anywhere in the CNAME string
                if re.search(rf"\b{re.escape(clean_service_cname)}\b", cname, re.IGNORECASE):
                    matches.append({
                        'cname': cname,
                        'service': fingerprint_data.get('service', 'Unknown'),
                        'vulnerable': fingerprint_data.get('vulnerable', False),
                        'status': fingerprint_data.get('status', 'Unknown'),
                        'fingerprint': fingerprint_data.get('fingerprint', ''),
                        'nxdomain': fingerprint_data.get('nxdomain', False),
                        'http_status': fingerprint_data.get('http_status'),
                        'discussion': fingerprint_data.get('discussion', ''),
                        'documentation': fingerprint_data.get('documentation', ''),
                        'cicd_pass': fingerprint_data.get('cicd_pass', False)
                    })
                    break  # Don't add the same service twice
    return matches

# Function to check HTTP response against fingerprint pattern
def check_fingerprint(subdomain, fingerprint_data):
    """
    Check if the subdomain's HTTP response matches the vulnerability fingerprint.
    Returns tuple: (is_vulnerable, response_text, status_code)
    """
    fingerprint = fingerprint_data.get('fingerprint', '')
    nxdomain_required = fingerprint_data.get('nxdomain', False)
    expected_http_status = fingerprint_data.get('http_status')
    
    # If fingerprint is NXDOMAIN, check DNS
    if fingerprint == "NXDOMAIN" or nxdomain_required:
        is_nxdomain = check_nxdomain(subdomain)
        if is_nxdomain:
            return (True, "NXDOMAIN", None)
        return (False, "Domain resolves", None)
    
    # If no fingerprint pattern, can't verify
    if not fingerprint:
        return (None, "No fingerprint pattern", None)
    
    # Try HTTPS first, then HTTP
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{subdomain}"
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            response_text = response.text
            
            # Check HTTP status code if specified
            if expected_http_status and response.status_code != expected_http_status:
                continue
            
            # Check if fingerprint pattern matches response
            # Escape special regex characters in fingerprint, but allow regex patterns
            try:
                # Try as regex first
                pattern = re.compile(fingerprint, re.IGNORECASE | re.DOTALL)
                if pattern.search(response_text):
                    return (True, response_text[:200], response.status_code)
            except re.error:
                # If not valid regex, treat as plain text
                if fingerprint.lower() in response_text.lower():
                    return (True, response_text[:200], response.status_code)
            
            return (False, response_text[:200], response.status_code)
            
        except requests.exceptions.SSLError:
            # SSL error, try HTTP
            continue
        except requests.exceptions.RequestException:
            # Request failed, try next protocol
            continue
    
    return (False, "No matching response", None)

STATUS_NOT_VULNERABLE = "not vulnerable"
STATUS_POTENTIALLY_VULNERABLE = "potentially vulnerable"
STATUS_VULNERABLE = "vulnerable"
STATUS_RANK = {
    STATUS_NOT_VULNERABLE: 0,
    STATUS_POTENTIALLY_VULNERABLE: 1,
    STATUS_VULNERABLE: 2,
}

def summarize_findings(findings):
    """Collapse matches for one subdomain into a service name and one status."""
    if not findings:
        return "none", STATUS_NOT_VULNERABLE

    best_rank = max(STATUS_RANK[status] for _, status in findings)
    services = []
    seen = set()
    for service, status in findings:
        if STATUS_RANK[status] == best_rank and service not in seen:
            seen.add(service)
            services.append(service)
    status = next(name for name, rank in STATUS_RANK.items() if rank == best_rank)
    return ", ".join(services), status

def write_results(filename, results):
    with open(filename, 'w', encoding='utf-8') as handle:
        handle.write("subdomain | cloud service | status\n")
        for subdomain, service, status in results:
            handle.write(f"{subdomain} | {service} | {status}\n")

# Main function with fingerprints support
def main(subdomains_file, fingerprints_file=None, cloud_services_file=None, output_file=None):
    fingerprints = None
    cloud_services = None
    
    # Load fingerprints if provided
    if fingerprints_file:
        try:
            fingerprints = load_fingerprints(fingerprints_file)
            print(f"{Fore.GREEN}[+] Loaded fingerprints database: {fingerprints_file}{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] Fingerprints file not found: {fingerprints_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading fingerprints: {e}{Style.RESET_ALL}")
    
    # Load cloud services if provided (for backward compatibility)
    if cloud_services_file:
        try:
            cloud_services = load_cloud_services(cloud_services_file)
            print(f"{Fore.GREEN}[+] Loaded cloud services database: {cloud_services_file}{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] Cloud services file not found: {cloud_services_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading cloud services: {e}{Style.RESET_ALL}")
    
    if not fingerprints and not cloud_services:
        print(f"{Fore.RED}[!] No fingerprint or cloud service database loaded!{Style.RESET_ALL}")
        return 1
    
    vulnerable_count = 0
    total_checked = 0
    results = []
    
    # Process each subdomain
    try:
        subdomain_lines = open(subdomains_file, 'r', encoding='utf-8')
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Subdomain file not found: {subdomains_file}{Style.RESET_ALL}")
        return 1

    with subdomain_lines as file:
        for subdomain in file:
            subdomain = subdomain.strip()
            if not subdomain:
                continue
            
            total_checked += 1
            findings = []
            
            # Step 1: Find all CNAME records
            cnames = get_cnames(subdomain)
            if cnames:
                print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Checking: {subdomain}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                print(f"CNAMEs found for {subdomain}:")
                for cname in cnames:
                    print(f"  {Fore.YELLOW}[+] {cname}{Style.RESET_ALL}")
                
                # Step 2: Check CNAMEs against fingerprints database (preferred method)
                if fingerprints:
                    fingerprint_matches = check_cnames_against_fingerprints(cnames, fingerprints)
                    if fingerprint_matches:
                        print(f"\n{Fore.LIGHTMAGENTA_EX}Cloud service matches (with vulnerability status):{Style.RESET_ALL}")
                        for match in fingerprint_matches:
                            service_name = match['service']
                            is_vulnerable = match['vulnerable']
                            status = match['status']
                            cicd_pass = match['cicd_pass']
                            
                            # Color code based on vulnerability status
                            if is_vulnerable:
                                status_color = Fore.LIGHTRED_EX
                            elif status == "Edge case":
                                status_color = Fore.YELLOW
                            else:
                                status_color = Fore.GREEN
                            
                            print(f"\n  {Fore.YELLOW}[+] CNAME: {match['cname']}{Style.RESET_ALL}")
                            print(f"     Service: {Fore.LIGHTMAGENTA_EX}{service_name}{Style.RESET_ALL}")
                            print(f"     Status: {status_color}{status}{Style.RESET_ALL}")
                            if cicd_pass:
                                print(f"     CI/CD Verified: {Fore.GREEN}Pass{Style.RESET_ALL}")
                            else:
                                print(f"     CI/CD Verified: {Fore.YELLOW}Not verified{Style.RESET_ALL}")
                            
                            # Only check fingerprints for vulnerable services
                            if is_vulnerable:
                                print(f"     {Fore.CYAN}[*] Verifying vulnerability fingerprint...{Style.RESET_ALL}")
                                fingerprint_result = check_fingerprint(subdomain, match)
                                is_confirmed, response_info, status_code = fingerprint_result
                                
                                if is_confirmed:
                                    vulnerable_count += 1
                                    findings.append((service_name, STATUS_VULNERABLE))
                                    print(f"     {Fore.LIGHTRED_EX}VULNERABLE: {subdomain} is confirmed vulnerable!{Style.RESET_ALL}")
                                    print(f"     {Fore.LIGHTRED_EX}   Fingerprint matched: {match['fingerprint'][:50]}...{Style.RESET_ALL}")
                                    if status_code:
                                        print(f"     {Fore.LIGHTRED_EX}   HTTP Status: {status_code}{Style.RESET_ALL}")
                                    if match['discussion']:
                                        print(f"     {Fore.CYAN}   Discussion: {match['discussion']}{Style.RESET_ALL}")
                                    if match['documentation']:
                                        print(f"     {Fore.CYAN}   Documentation: {match['documentation']}{Style.RESET_ALL}")
                                elif is_confirmed is False:
                                    findings.append((service_name, STATUS_NOT_VULNERABLE))
                                    print(f"     {Fore.GREEN}Not vulnerable: Fingerprint not matched{Style.RESET_ALL}")
                                else:
                                    findings.append((service_name, STATUS_POTENTIALLY_VULNERABLE))
                                    print(f"     {Fore.YELLOW}Could not verify: {response_info}{Style.RESET_ALL}")
                            elif status == "Edge case":
                                findings.append((service_name, STATUS_POTENTIALLY_VULNERABLE))
                                print(f"     {Fore.YELLOW}Edge case: Requires manual verification{Style.RESET_ALL}")
                            else:
                                findings.append((service_name, STATUS_NOT_VULNERABLE))
                                print(f"     {Fore.GREEN}Not vulnerable: Service has been patched{Style.RESET_ALL}")
                    
                    # Fallback to cloud_services if no fingerprint matches
                    if not fingerprint_matches and cloud_services:
                        old_matches = check_cnames_against_cloud_services(cnames, cloud_services)
                        if old_matches:
                            print(f"\n{Fore.YELLOW}Cloud service matches (legacy format - no vulnerability status):{Style.RESET_ALL}")
                            for cname, service in old_matches:
                                findings.append((service, STATUS_POTENTIALLY_VULNERABLE))
                                print(f"  {Fore.YELLOW}[+] {cname}{Style.RESET_ALL} Uses Cloud Service: {Fore.LIGHTRED_EX}{service}{Style.RESET_ALL}")
                                print(f"     {Fore.YELLOW}No vulnerability status available - using legacy database{Style.RESET_ALL}")
                
                # Step 3: Fallback to cloud_services if fingerprints not available
                elif cloud_services:
                    matches = check_cnames_against_cloud_services(cnames, cloud_services)
                    if matches:
                        print(f"\n{Fore.YELLOW}Cloud service matches (legacy format):{Style.RESET_ALL}")
                        for cname, service in matches:
                            findings.append((service, STATUS_POTENTIALLY_VULNERABLE))
                            print(f"  {Fore.YELLOW}[+] {cname}{Style.RESET_ALL} Uses Cloud Service: {Fore.LIGHTRED_EX}{service}{Style.RESET_ALL}")
                            print(f"     {Fore.YELLOW}No vulnerability status available - using legacy database{Style.RESET_ALL}")
            
            # No CNAME found - skip silently or show if verbose
            # (Keeping silent for cleaner output)
            if findings:
                service, status = summarize_findings(findings)
                results.append((subdomain, service, status))
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
    print(f"  Total subdomains checked: {total_checked}")
    if fingerprints:
        print(f"  {Fore.LIGHTRED_EX}Confirmed vulnerable: {vulnerable_count}{Style.RESET_ALL}")
    if output_file:
        try:
            write_results(output_file, results)
            print(f"  {Fore.GREEN}Results written to {output_file}{Style.RESET_ALL}")
        except OSError as e:
            print(f"  {Fore.RED}Could not write results to {output_file}: {e}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
            return 1
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    return 0

# Example usage
if __name__ == "__main__":
    print(f"{Fore.GREEN}{ascii_banner}{Style.RESET_ALL}")
    
    # Parse command line arguments
    args = parse_args()

    # Run main function
    exit_code = main(
        subdomains_file=args.subdomains_file,
        fingerprints_file=args.fingerprints_file,
        cloud_services_file=args.cloud_services_file,
        output_file=args.output_file
    )

    print(f"{Fore.CYAN}Refer: https://github.com/EdOverflow/can-i-take-over-xyz/tree/master{Style.RESET_ALL}")
    print()
    raise SystemExit(exit_code)



