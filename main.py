"""
Domain Analysis Tool

This script analyzes domain names associated with IP addresses from various blocklists
and data center IP ranges. It checks for expired domains and their prices, generating
a comprehensive analysis report.

The script performs the following main functions:
1. Fetches IP addresses from multiple sources
2. Resolves domains from IP addresses
3. Checks domain expiration status
4. Retrieves domain pricing information
5. Exports results to a text file

Requirements:
    - socket
    - whois
    - requests
    - datetime
    - logging
    - ipaddress

Author: Unknown
Version: 1.0
"""

import socket
import whois
import requests
import logging
import ipaddress
from datetime import datetime
from exceptions.error_handling import WhoisError, DomainResolutionError, ValidationError, FetchError

logging.basicConfig(level=logging.INFO)


def get_domain(ip):
    """
    Resolves domain name from an IP address or IP network.

    Args:
        ip (str): IP address or CIDR notation network

    Returns:
        str or list: Domain name(s) associated with the IP(s)

    Raises:
        ValidationError: If an IP format is invalid
        DomainResolutionError: If domain resolution fails
    """
    if not ip:
        raise ValidationError(message="IP address cannot be empty", error_code="INVALID_IP")

    try:
        if '/' in ip:
            network = ipaddress.ip_network(ip)
            return [str(ip) for ip in network.hosts()]

        domain = socket.gethostbyaddr(ip)[0]
        return domain

    except ValueError as e:
        logging.error("Invalid IP format: %s", ip)
        raise ValidationError(message=f"Invalid IP format: {ip}", error_code="INVALID_IP") from e

    except socket.herror as e:
        logging.error("Domain resolution failed for IP %s: %s", ip, str(e))
        raise DomainResolutionError(message=f"Could not resolve domain for IP: {ip}",
                                    error_code="IP_FAILED_RESOLUTION") from e


def get_domain_info(domain):
    """
    Retrieves WHOIS information for a domain.

    Args:
        domain (str): Domain name to query

    Returns:
        datetime: Domain expiration date
        None: If WHOIS query fails
    """
    try:
        w = whois.whois(domain)
        if isinstance(w.expiration_date, list):
            return w.expiration_date[0]
        return w.expiration_date
    except WhoisError as e:
        logging.error("Failed to get WHOIS info for domain %s: %s", domain, str(e))
        return None


def get_domain_price(domain):
    """
    Retrieves price information for a domain using Namecheap API.

    Args:
        domain (str): Domain name to check

    Returns:
        str: Price information
        None: If API call fails
    """
    api_url = (f"https://api.namecheap.com/xml.response?"
               f"command=namecheap.domains.check&DomainList={domain}")
    try:
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            return response.text
        logging.error("API call failed for domain %s: %s}", domain, response.text)
        return None
    except DomainResolutionError as e:
        logging.error("Failed to get price for domain %s: $%s", domain, e)
        return None


def check_domains(ip_list):
    """
    Processes a list of IPs to check their associated domains.

    Args:
        ip_list (list): List of IP addresses to check

    Returns:
        list: List of tuples containing (domain, price) for available domains
    """
    available_domains = []
    for ip in ip_list:
        domain_result = get_domain(ip)
        if isinstance(domain_result, list):
            for single_ip in domain_result:
                domain = get_domain(single_ip)
                if domain:
                    process_domain(str(domain), available_domains)
        elif domain_result:
            process_domain(str(domain_result), available_domains)
    return available_domains


def process_domain(domain, available_domains):
    """
    Processes a single domain to check expiration and price.

    Args:
        domain (str): Domain name to a process
        available_domains (list): List to store results
    """
    expiration = get_domain_info(domain)
    if expiration and expiration < datetime.now():
        price = get_domain_price(domain)
        if price:
            available_domains.append((domain, price))
            logging.info("Expired: %s -> Price: %s", domain, price)


def fetch_target_ips():
    """
    Fetches IP addresses from various blocklist and datacenter sources.

    Returns:
        list: List of unique IP addresses
    """
    sources = [
        "52.250.42.157"
    ]
    ip_list = set()

    for source in sources:
        try:
            response = requests.get(source, timeout=10)
            for line in response.text.splitlines():
                if line and not line.startswith('#'):
                    ip = line.split()[0]
                    ip_list.add(ip)
        except FetchError as e:
            logging.error("Failed to fetch IPs from %s: %s", source, str(e))

    return list(ip_list)


def export_analysis(available_domains):
    """
    Exports analysis results to a text file.

    Args:
        available_domains (list): List of tuples containing (domain, price)
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"domain_analysis_{timestamp}.txt"

    with open(filename, 'w', encoding="UTF-8") as f:
        f.write("Domain Analysis Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Generated on: {datetime.now()}\n\n")

        for domain, price in available_domains:
            f.write(f"Domain: {domain}\n")
            f.write(f"Price: {price}\n")
            f.write("-" * 30 + "\n")


def main():
    """
    Main function to orchestrate the domain analysis process.
    """
    logging.info("Starting domain analysis...")
    ip_list = fetch_target_ips()
    logging.info("Found %s potential targets", len(ip_list))

    expired_domains = check_domains(ip_list)
    export_analysis(expired_domains)
    logging.info("Analysis complete. Results exported to file.")


if __name__ == "__main__":
    main()
