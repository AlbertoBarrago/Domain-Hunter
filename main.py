"""
Domain Analysis Tool

This script analyzes domain names associated with IP addresses from various blocklists
and data center IP ranges. It checks for expired domains and their prices, generating
a comprehensive analysis report.

Author: alBz <albertobarrago@gmail.com>
Version: 0.0.1
"""
import os
import re
import socket
import json
import xml.etree.ElementTree as ET
import requests.exceptions as req_exc
from dotenv import load_dotenv

import logging
import ipaddress
from datetime import datetime, timezone

import whois
import requests

from exceptions.error_handling import DomainResolutionError, ValidationError, WhoisError

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')


def get_user_addresses():
    logging.info("\n--- User Input Mode ---")
    raw_input = input("➡ Enter a single address, or a JSON list/dict of addresses, then press Enter: ")

    raw_input = raw_input.strip()
    if not raw_input:
        return []

    try:
        processed_input = raw_input.replace("'", '"')
        data = json.loads(processed_input)
        addresses = []

        if isinstance(data, list):
            addresses.extend(data)
        elif isinstance(data, dict):
            addresses.extend(data.values())
        else:
            addresses.append(data)

        logging.info("Successfully parsed structured input.")
        return [str(addr).strip() for addr in addresses if str(addr).strip()]

    except json.JSONDecodeError:
        logging.info("Input not recognized as JSON. Treating as a single address.")
        return [raw_input]

    except Exception as e:
        logging.error("Error processing user input: %s", str(e))
        return []


def get_domain(target):
    """
    Resolves domain name from an IP address (Reverse DNS) OR
    verifies a domain name (Forward DNS).
    """
    if not target:
        raise ValidationError(message="Target cannot be empty", error_code="INVALID_TARGET")

    try:
        if '/' in target:
            network = ipaddress.ip_network(target)
            return [str(ip) for ip in network.hosts()]

        ipaddress.ip_address(target)

        try:
            domain = socket.gethostbyaddr(target)[0]
            return domain
        except socket.herror as e:
            logging.error("Domain resolution failed for IP %s: %s", target, str(e))
            raise DomainResolutionError(message=f"Could not resolve domain for IP: {target}",
                                        error_code="IP_FAILED_RESOLUTION") from e

    except ValueError:
        try:
            socket.gethostbyname(target)
            return target
        except socket.gaierror as e:
            logging.error("Forward DNS resolution failed for domain %s: %s", target, str(e))
            raise DomainResolutionError(message=f"Could not resolve domain: {target}",
                                        error_code="DOMAIN_FAILED_RESOLUTION") from e

    except Exception as e:
        logging.error("Unexpected error in get_domain for %s: %s", target, str(e))
        raise


def get_domain_info(domain):
    """
    Retrieves WHOIS information for a domain.
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
    Retrieves price information (availability check) for a domain using Namecheap API.
    """
    params = {
        "ApiUser": os.getenv("API_USER"),
        "ApiKey": os.getenv("API_KEY"),
        "UserName": os.getenv("USER_NAME"),
        "Command": "namecheap.domains.check",
        "ClientIp": os.getenv("CLIENT_IP")
    }
    api_url = "https://api.namecheap.com/xml.response"

    try:
        response = requests.get(api_url, params=params, timeout=5)
        response.raise_for_status()

        root = ET.fromstring(response.content)

        errors = root.find(".//Error")
        if errors is not None:
            logging.error("Namecheap API Error for %s: %s", domain, errors.text)
            return "API_ERROR"

        domain_check = root.find(".//DomainCheckResult")

        if domain_check is not None:
            is_available = domain_check.attrib.get('IsAvailable')
            return "Available" if is_available == 'true' else "Unavailable (In Use)"

        return "Unknown Status"

    except req_exc.RequestException as e:
        logging.error("Network failed to get price for domain %s: %s", domain, str(e))
        return None
    except ET.ParseError:
        logging.error("Failed to parse XML response for domain %s. Check API credentials.", domain)
        return None


def process_domain(domain, available_domains, active_domains):
    """
    Processes a single domain to check expiration and price, returning the status string.
    """
    expiration = get_domain_info(domain)

    status_string = f"Domain: {domain} | Expired: False | Expires (UTC): N/A (WHOIS FAILED)"

    if expiration and isinstance(expiration, datetime):
        if expiration.tzinfo is None or expiration.tzinfo.utcoffset(expiration) is None:
            expiration_aware = expiration.replace(tzinfo=timezone.utc)
        else:
            expiration_aware = expiration.astimezone(timezone.utc)

        now_utc = datetime.now(timezone.utc)
        is_expired = expiration_aware < now_utc

        status_string = (
            f"Domain: {domain} | Expired: {is_expired} | "
            f"Expires (UTC): {expiration_aware.strftime('%Y-%m-%d %H:%M')}"
        )
        logging.info(status_string)

        if is_expired:
            price_status = get_domain_price(domain)
            if price_status and price_status != "API_ERROR":
                available_domains.append((domain, price_status))
                logging.info("Expired: %s -> Status: %s", domain, price_status)

        else:
            active_domains.append(domain)
            logging.info("Active Domain recorded: %s", domain)

        return status_string

    elif expiration:
        logging.warning("WHOIS data for %s returned unexpected format: %s", domain, str(expiration))

    return status_string


def fetch_target_ips():
    """
    Fetches IP addresses using Regex to extract actual IPs from HTML/Text.
    """
    sources = [
        "http://52.250.42.157"
    ]
    ip_list = set()
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    for source in sources:
        try:
            response = requests.get(source, timeout=10)
            found_ips = ip_pattern.findall(response.text)
            for ip in found_ips:
                try:
                    ipaddress.ip_address(ip)
                    ip_list.add(ip)
                except ValueError:
                    continue
        except requests.RequestException as e:
            logging.error("Failed to fetch IPs from %s: %s", source, str(e))

    return list(ip_list)


def check_domains(ip_list):
    """
    Processes a list of IPs to check their associated domains.
    Returns: available_domains (expired), active_domains (not expired), domain_status_log (all results).
    """
    available_domains = []
    active_domains = []
    domain_status_log = []

    try:
        for ip in ip_list:
            try:
                domain_result = get_domain(ip)

                if isinstance(domain_result, list):
                    for single_ip in domain_result:
                        try:
                            domain = get_domain(single_ip)
                            if domain and not isinstance(domain, list):
                                status = process_domain(str(domain), available_domains, active_domains)
                                if status:
                                    domain_status_log.append(status)
                        except (DomainResolutionError, ValidationError):
                            continue

                elif domain_result:
                    status = process_domain(str(domain_result), available_domains, active_domains)
                    if status:
                        domain_status_log.append(status)

            except (DomainResolutionError, ValidationError):
                continue

    except Exception as e:
        logging.error("CRITICAL ERROR: Unhandled exception in check_domains. "
                      "Returning partial results. %s", str(e))

    return available_domains, active_domains, domain_status_log


def export_analysis(available_domains, active_domains, domain_status_log):
    """
    Exports analysis results to a text file within a dedicated folder.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"domain_analysis_{timestamp}.txt"

    # --- Gestione della Cartella ---
    report_dir = "analysis_reports"

    # Crea la directory se non esiste
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
        logging.info("Created report directory: %s", report_dir)

    # Costruisci il percorso completo del file
    full_path = os.path.join(report_dir, filename)
    # --------------------------------

    with open(full_path, 'w', encoding="UTF-8") as f:  # <--- USA full_path
        f.write("Domain Analysis Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Generated on: {datetime.now()}\n\n")

        # 1. Status Log (All Targets)
        f.write("## 📝 Domain Status Log (All Targets)\n")
        f.write("=" * 50 + "\n")
        for status in domain_status_log:
            f.write(status + "\n")
        f.write("\n")

        # 2. Expired Report
        f.write("## ⚠️ Expired Domains Report\n")
        f.write("=" * 50 + "\n")

        if not available_domains:
            f.write("No expired domains found with successful price check.\n")
        else:
            for domain, price_status in available_domains:
                f.write(f"Domain: {domain}\n")
                f.write(f"Status/Price: {price_status}\n")
                f.write("-" * 30 + "\n")

        # 3. Active Domains Report
        f.write("\n## ✅ Active Domains Report\n")
        f.write("=" * 50 + "\n")

        if not active_domains:
            f.write("No active domains found in WHOIS checks.\n")
        else:
            for domain in active_domains:
                f.write(f"Domain: {domain}\n")
            f.write("-" * 30 + "\n")


def main():
    """
    Main function to orchestrate the domain analysis process.
    """
    load_dotenv()

    logging.info("Starting domain analysis...")

    ip_list = fetch_target_ips()
    user_targets = get_user_addresses()
    ip_list.extend(user_targets)

    logging.info("Found %s potential targets (including user input)", len(ip_list))

    expired_domains, active_domains, domain_status_log = check_domains(ip_list)

    export_analysis(expired_domains, active_domains, domain_status_log)

    logging.info("Analysis complete. Results exported to file.")


if __name__ == "__main__":
    main()
