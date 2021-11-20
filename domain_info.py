"""
NAME: Domain Info
VERISON: 1.0
AUTHOR: Adam Sneed
DESCRIPTION:
TO-DO:
    - Query subdomains without using API

"""
import sys
import ssl
import random
from getpass import getpass
import colorama
import requests
import argparse
from urllib import request, error, response
import urllib3
import logging
import threading
from functools import  lru_cache

urllib3.disable_warnings()




try:
    from colorama import init, Fore, Back, Style
    init()

except ImportError:
    print("[-] ERROR: 'colorama' is a required package")
    sys.exit(1)

__author__ = "Adam Sneed"
__copyright__ = "Copyright (C) 2021 Adam Sneed"
__license__ = "MIT License"
__version__ = "1.0"


def display_banner():
    banner = (f'''
  ____                        _           ___        __       
 |  _ \  ___  _ __ ___   __ _(_)_ __     |_ _|_ __  / _| ___  
 | | | |/ _ \| '_ ` _ \ / _` | | '_ \     | || '_ \| |_ / _ \ 
 | |_| | (_) | | | | | | (_| | | | | |    | || | | |  _| (_) |
 |____/ \___/|_| |_| |_|\__,_|_|_| |_|___|___|_| |_|_|  \___/ 
                                    |_____|                   
Ver:{__version__}
''')
    return f"{Fore.YELLOW}{banner}{Fore.RESET}"


logging.basicConfig(filename='app.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%y%b%d %H:%M:%S')


def get_apikey()->str:
    """Gets api key from Users input if not provided"""
    print(f"{Fore.GREEN}[+] TASK: Copy and paste yoru API key")
    return getpass.getpass("\t[>] API_KEY: ")

def check_subdomain(subdomain, domain) -> None:
    url = f"https://{subdomain}.{domain}"
    try:
        response = requests.get(url, verify=False)
        print(url, response.status_code)
    except Exception as err:
        logging.error(err)
        
def write_to_file(domain, output_file):
    '''Write found subdomains to file.'''
    try:
        with open(output_file, 'a') as f:
            f.write(f"{domain}\n")
    except Exception as err:
        logging.error(err)

class DomainFinder(object):
    """Finder object to find all subdomains for an URL"""
    def __init__(self, domain:str=None, api_key:str=None) ->None:
        self.domain = domain
        self.apikey = api_key
        self.url = "https://api.securitytrails.com/v1/"
        self.cert_context = ssl.create_default_context()
        self.cert_context.check_hostname = False
        self.cert_context.verify_mode = ssl.CERT_NONE
        self.headers = {"Accept":"application/json", "APIKEY" : self.apikey}
        self.subdomains = None
        self.dns = []

    def test_connection(self):
        """Test Connection API before Query"""
        try :
            with request.urlopen(self.url) as status_code:
                successful_connect = status_code.getcode() == 200
                if successful_connect is True:
                    return f"{Fore.GREEN}[+] TASK: API is online!"
                print(f"{Fore.RED}[-] ERROR (HTML:{status_code.getcode()}): Unable to access API. ")
                sys.exit(1)
        except error.HTTPError as httperr:
            response_data = httperr.read().decode("utf-8", "ignore")
            print(f"{Fore.RED}[-] ERROR (HTTP Error): {response_data}")
            sys.exit(1)
        except error.URLError:
            print(f"{Fore.RED}[-] ERROR (WIN: 10061): Target actively refused connection.")
            sys.exit(1)
    @lru_cache(maxsize=400)
    def get_info(self):
        url = f"{self.url}v1/domain/{self.domain}"
        response = requests.request("GET", url, headers=self.headers, verify=False)
        self.info = response.json()
        
    @lru_cache(maxsize=400)    
    def get_dns_history(self):
        url = f"{self.url}history/{self.domain}/dns/a"
        response = requests.request("GET", url, headers=self.headers, verify=False)
        self.dns = response.json()
        
    @lru_cache(maxsize=400)
    def get_subdomains(self):
        url = f"{self.url}domain/{self.domain}/subdomains"
        response = requests.request("GET", url, headers=self.headers, verify=False)
        subdomains = response.json()["subdomains"]
        self.subdomains = subdomains
        
    @lru_cache(maxsize=400)
    def get_associated_domains(self):
        """Get associated domains. This function requires a full subscription"""
        url = f"{self.url}domain/{self.domain}/associated"
        response = requests.request("GET", url, headers=self.headers, verify=False)
        associated = response.json()
        self.associated_domains = associated      

def main():
    print(display_banner())
    parser = argparse.ArgumentParser(prog="domain_info", usage="%(prog)s [options]", description=f"Query information on a given domain")
    parser.add_argument('-a', '--apikey', help="Enter API Key")
    parser.add_argument('-d', '--domain', help="Domain to query", required=True)
    parser.add_argument('-o','--out', help="File to write output")
    parser.add_argument('-c', '--check', help='Check if found subdomains can be reached', action='store_true')
    args = parser.parse_args()
    if not args.apikey:
        apikey = get_apikey()
    else:
        apikey = args.apikey

    d = DomainFinder(args.domain, apikey)
    #d.test_connection()
    d.get_subdomains()
    print(f"{Fore.GREEN}{'-' * 50}\n[+] TASK: Finding Subdomains\n{'-' * 50 }")
    for subdomain in d.subdomains:
        sys.stdout.write(f"{Fore.YELLOW}{subdomain}.{d.domain}{Fore.RESET}\n")
    subdomains_list = [f"{subdomain}.{d.domain}" for subdomain in d.subdomains]
    output = "\n".join(subdomains_list)
    if args.out:
        write_to_file(output, args.out)

    if args.check:
        threads = list()
        for sub in d.subdomains:
            x = threading.Thread(target=check_subdomain, args=(sub.strip(), d.domain))
            threads.append(x)
            x.start()
        print(f"{Fore.GREEN} {'-' * 50 }\n[+] TASK: Checking status of subdomains...\n{'-' * 50 }")
        for thread in threads:
            thread.join()


if __name__ == '__main__':
    main() 