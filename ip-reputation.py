from typing import Callable
import requests
import re
import os
import json
import argparse

from dotenv import load_dotenv

load_dotenv()

# Get the API keys from env file
VT_API = os.getenv('VT_API')
NEUTRINO_API = os.getenv('NEUTRINO_API')

# Configure the regex validation
ip_regex = re.compile('^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$')


# Get details from VT and calculate normalized score
def get_data_from_vt(ip: str, add_info: bool) -> int:
    headers = {
        "x-apikey": VT_API
    }

    response = requests.get(url=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)

    if response.status_code == 200:
        data = json.loads(response.text)['data']

        # Retrieve raw data
        scanners_harmless = int(data['attributes']['last_analysis_stats']['harmless'])
        scanners_malicious = int(data['attributes']['last_analysis_stats']['malicious'])
        scanners_suspicious = int(data['attributes']['last_analysis_stats']['suspicious'])
        votes_harmless = int(data['attributes']['total_votes']['harmless'])
        votes_malicious = int(data['attributes']['total_votes']['malicious'])

        # Calculate score by weight: malicious = 1, suspicious = 0.5, harmless = 0, Divide by total.
        single_score = ((scanners_malicious+votes_malicious) + scanners_suspicious*0.5) / (scanners_harmless+scanners_malicious+scanners_suspicious+votes_harmless+votes_malicious)
        single_score = round(single_score*10)

        # Print additional information for --verbose
        if add_info:
            prPurple("VirusTotal Details:")
            print(f"scanners_harmless: {scanners_harmless}")
            print(f"scanners_malicious: {scanners_malicious}")
            print(f"scanners_suspicious: {scanners_suspicious}")
            print(f"votes_harmless: {votes_harmless}")
            print(f"votes_malicious: {votes_malicious}")
            print(f"Total sources: {(scanners_harmless+scanners_malicious+scanners_suspicious+votes_harmless+votes_malicious)}")
            prLightPurple(f"VirusTotal single score: {single_score}")
        return single_score
    else:
        raise Exception(f"VirusTotal Error {response.status_code}: {response.text}")


def get_data_from_neutrino(ip: str, add_info: bool) -> int:
    headers = {
        "user-id": "or_api",
        "api-key": NEUTRINO_API
    }

    params = {
        'host': ip
    }

    response = requests.get(url="https://neutrinoapi.net/host-reputation", headers=headers, params=params)

    if response.status_code == 200:
        data = json.loads(response.text)

        # Retrieve raw data
        listed = int(data['list-count'])
        total_lists = len(data['lists'])

        # Calculate normalized score - number of malicious divided by total
        single_score = round((listed / total_lists)*10)

        # Print additional information for --verbose
        if add_info:
            prPurple("Neutrino Details:")
            print(f"Listed in blacklists: {listed}")
            print(f"Total sources: {total_lists}")
            prLightPurple(f"Neutrino single score: {single_score}")
        return single_score
    else:
        raise Exception(f"VirusTotal Error {response.status_code}: {response.text}")


# Execute functions in a given list and return a normalized score
def normalize_score(ip: str, funcs_list: list[Callable], add_info: bool) -> int:
    sum_of_score = 0
    for func in funcs_list:
        sum_of_score += func(ip, add_info)
    return round(sum_of_score/len(funcs_list))


# Coloured printing configuration
def prRed(text): print("\033[91m{}\033[00m" .format(text))
def prGreen(text): print("\033[92m{}\033[00m" .format(text))
def prYellow(text): print("\033[93m{}\033[00m" .format(text))
def prLightPurple(text): print("\033[94m{}\033[00m" .format(text))
def prPurple(text): print("\033[95m{}\033[00m" .format(text))
def prCyan(text): print("\033[96m{}\033[00m" .format(text))
def prLightGray(text): print("\033[97m{}\033[00m" .format(text))


if __name__ == '__main__':
    try:
        # Define arguments for CLI
        parser = argparse.ArgumentParser(prog="IP Malicious Reputation", description='Returns the normalized reputation score for given IPs.')
        parser.add_argument('--ips', metavar='List of IPs', type=str, help='Provide a list of IPs separated by a comma. (i.e. "0.0.0.0, 1.2.3.4, 5.6.7.8")')
        parser.add_argument('--verbose', help='Returns more details per each given IP.', action='store_true', default=False)
        args = parser.parse_args()

        if args.ips:
            for ip in args.ips.replace(" ", "").split(","):
                if ip_regex.match(ip):
                    prCyan(f"\nChecking {ip} score...")
                    normalized_score = normalize_score(ip, funcs_list=[get_data_from_vt, get_data_from_neutrino], add_info=args.verbose)
                    print(f"Normalized score: {normalized_score}")

                    # Explain the IP score
                    if normalized_score <= 4:
                        prGreen(f"IP {ip} is clean.")
                    elif normalized_score <= 7:
                        prYellow(f"IP {ip} is suspicious.")
                    else:
                        prRed(f"IP {ip} is malicious.")
                else:
                    if len(ip) > 0:
                        prLightGray(f"{ip} is not a valid IP address.")
        else:
            parser.print_help()
    except Exception as e:
        print(f"Failed! \n {e}")
