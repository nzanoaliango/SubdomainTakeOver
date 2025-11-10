#!/usr/bin/env python3
import dns.resolver
import json
import requests
import sys
import argparse
import re
import urllib3
from urllib.parse import urlparse

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
# Function to define all arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description='Subdomain Takeover Scanner - Detects potential subdomain takeover vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Use fingerprints database (recommended)
  python subdomain_takeover.py -f subdomains.txt -p fingerprints.json
  
  # Use legacy cloud services database
  python subdomain_takeover.py -f subdomains.txt -s cloud_services.json
  
  # Use both (fingerprints preferred, cloud_services as fallback)
  python subdomain_takeover.py -f subdomains.txt -p fingerprints.json -s cloud_services.json
        """
    )
    parser.add_argument('-f', '--file', '--filename', dest='subdomains_file', required=True,
                       help='Text file containing list of subdomains (one per line)')
    parser.add_argument('-p', '--fingerprints', dest='fingerprints_file',
                       help='JSON file containing fingerprints database (recommended)')
    parser.add_argument('-s', '--service', '--services', dest='cloud_services_file',
                       help='JSON file containing cloud services (legacy format)')
    return parser.parse_args()

# Function to load cloud services from a JSON file
def load_cloud_services(filename):
    with open(filename, 'r') as file:
        return json.load(file)

# Function to load fingerprints from a JSON file
def load_fingerprints(filename):
    with open(filename, 'r') as file:
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

# Function to check if any CNAME matches cloud services
# def check_cnames_against_cloud_services(cnames, cloud_services):
#     matches = []
#     for cname in cnames:
#         for service, domain in cloud_services.items():
#             if domain in cname:
#                 matches.append((cname, service))
#     return matches

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

# Function to send an HTTP request to the subdomain
def check_http(cname):
    try:
        response = requests.get(f"https://{cname}", timeout=9)
        return response.status_code == 200
    except requests.RequestException:
        return False

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

# Function to send an HTTP request to the CNAME
# def check_http(cname, subdomain):
#     try:
#         response = requests.get(f"http://{cname}", timeout=5)
#         if response.status_code == 200:
#             print(f"{Fore.LIGHTRED_EX}[+] {subdomain} is Vulnerable{Style.RESET_ALL}")
#             return True
#         else:
#             print(f"{Fore.RED}We got this for {cname} - Response Code: {response.status_code}{Style.RESET_ALL}")
#             return False
#     except requests.RequestException:
#         print(f"{Fore.RED}We got this for {cname} - Request failed{Style.RESET_ALL}")
#         return False

# Main function with fingerprints support
def main(subdomains_file, fingerprints_file=None, cloud_services_file=None):
    fingerprints = None
    cloud_services = None
    
    # Load fingerprints if provided
    if fingerprints_file:
        try:
            fingerprints = load_fingerprints(fingerprints_file)
            print(f"{Fore.GREEN}[+] Loaded fingerprints database{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] Fingerprints file not found: {fingerprints_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading fingerprints: {e}{Style.RESET_ALL}")
    
    # Load cloud services if provided (for backward compatibility)
    if cloud_services_file:
        try:
            cloud_services = load_cloud_services(cloud_services_file)
            print(f"{Fore.GREEN}[+] Loaded cloud services database{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] Cloud services file not found: {cloud_services_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading cloud services: {e}{Style.RESET_ALL}")
    
    if not fingerprints and not cloud_services:
        print(f"{Fore.RED}[!] No fingerprint or cloud service database loaded!{Style.RESET_ALL}")
        return
    
    vulnerable_count = 0
    total_checked = 0
    
    # Process each subdomain
    with open(subdomains_file, 'r') as file:
        for subdomain in file:
            subdomain = subdomain.strip()
            if not subdomain:
                continue
            
            total_checked += 1
            
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
                                status_icon = "🔴"
                            elif status == "Edge case":
                                status_color = Fore.YELLOW
                                status_icon = "🟡"
                            else:
                                status_color = Fore.GREEN
                                status_icon = "🟢"
                            
                            print(f"\n  {Fore.YELLOW}[+] CNAME: {match['cname']}{Style.RESET_ALL}")
                            print(f"     Service: {Fore.LIGHTMAGENTA_EX}{service_name}{Style.RESET_ALL}")
                            print(f"     Status: {status_color}{status_icon} {status}{Style.RESET_ALL}")
                            if cicd_pass:
                                print(f"     CI/CD Verified: {Fore.GREEN}✓ Pass{Style.RESET_ALL}")
                            else:
                                print(f"     CI/CD Verified: {Fore.YELLOW}✗ Not verified{Style.RESET_ALL}")
                            
                            # Only check fingerprints for vulnerable services
                            if is_vulnerable:
                                print(f"     {Fore.CYAN}[*] Verifying vulnerability fingerprint...{Style.RESET_ALL}")
                                fingerprint_result = check_fingerprint(subdomain, match)
                                is_confirmed, response_info, status_code = fingerprint_result
                                
                                if is_confirmed:
                                    vulnerable_count += 1
                                    print(f"     {Fore.LIGHTRED_EX}🚨 VULNERABLE: {subdomain} is confirmed vulnerable!{Style.RESET_ALL}")
                                    print(f"     {Fore.LIGHTRED_EX}   Fingerprint matched: {match['fingerprint'][:50]}...{Style.RESET_ALL}")
                                    if status_code:
                                        print(f"     {Fore.LIGHTRED_EX}   HTTP Status: {status_code}{Style.RESET_ALL}")
                                    if match['discussion']:
                                        print(f"     {Fore.CYAN}   Discussion: {match['discussion']}{Style.RESET_ALL}")
                                    if match['documentation']:
                                        print(f"     {Fore.CYAN}   Documentation: {match['documentation']}{Style.RESET_ALL}")
                                elif is_confirmed is False:
                                    print(f"     {Fore.GREEN}✓ Not vulnerable: Fingerprint not matched{Style.RESET_ALL}")
                                else:
                                    print(f"     {Fore.YELLOW}⚠ Could not verify: {response_info}{Style.RESET_ALL}")
                            elif status == "Edge case":
                                print(f"     {Fore.YELLOW}⚠ Edge case: Requires manual verification{Style.RESET_ALL}")
                            else:
                                print(f"     {Fore.GREEN}✓ Not vulnerable: Service has been patched{Style.RESET_ALL}")
                    
                    # Fallback to cloud_services if no fingerprint matches
                    if not fingerprint_matches and cloud_services:
                        old_matches = check_cnames_against_cloud_services(cnames, cloud_services)
                        if old_matches:
                            print(f"\n{Fore.YELLOW}Cloud service matches (legacy format - no vulnerability status):{Style.RESET_ALL}")
                            for cname, service in old_matches:
                                print(f"  {Fore.YELLOW}[+] {cname}{Style.RESET_ALL} Uses Cloud Service: {Fore.LIGHTRED_EX}{service}{Style.RESET_ALL}")
                                print(f"     {Fore.YELLOW}⚠ No vulnerability status available - using legacy database{Style.RESET_ALL}")
                
                # Step 3: Fallback to cloud_services if fingerprints not available
                elif cloud_services:
                    matches = check_cnames_against_cloud_services(cnames, cloud_services)
                    if matches:
                        print(f"\n{Fore.YELLOW}Cloud service matches (legacy format):{Style.RESET_ALL}")
                        for cname, service in matches:
                            print(f"  {Fore.YELLOW}[+] {cname}{Style.RESET_ALL} Uses Cloud Service: {Fore.LIGHTRED_EX}{service}{Style.RESET_ALL}")
                            print(f"     {Fore.YELLOW}⚠ No vulnerability status available - using legacy database{Style.RESET_ALL}")
            
            # No CNAME found - skip silently or show if verbose
            # (Keeping silent for cleaner output)
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
    print(f"  Total subdomains checked: {total_checked}")
    if fingerprints:
        print(f"  {Fore.LIGHTRED_EX}Confirmed vulnerable: {vulnerable_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

# Example usage
if __name__ == "__main__":
    print(f"{Fore.GREEN}{ascii_banner}{Style.RESET_ALL}")
    
    # Parse command line arguments
    args = parse_args()
    
    # Check if at least one database is provided
    if not args.fingerprints_file and not args.cloud_services_file:
        print(f"{Fore.YELLOW}[!] Warning: No fingerprints or cloud services file provided{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[-] Usage: python subdomain_takeover.py -f <subdomains_file> [-p <fingerprints_file>] [-s <cloud_services_file>]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[-] Use -h or --help for more information{Style.RESET_ALL}")
        print()
        sys.exit(1)
    
    # Run main function
    main(
        subdomains_file=args.subdomains_file,
        fingerprints_file=args.fingerprints_file,
        cloud_services_file=args.cloud_services_file
    )
    
    print(f"{Fore.CYAN}Refer: https://github.com/EdOverflow/can-i-take-over-xyz/tree/master{Style.RESET_ALL}")
    print()



