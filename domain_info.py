"""
NAME: Domain Info
VERISON: 1.0
AUTHOR: Adam Sneed
DESCRIPTION:
TO-DO:

"""
import sys
import ssl
import random
import getpass
import colorama
import requests
import argparse
from urllib import request, error, response

from requests import api


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
    colors = list(vars(colorama.Fore).values())
    banner = ('''
  ____                        _           ___        __       
 |  _ \  ___  _ __ ___   __ _(_)_ __     |_ _|_ __  / _| ___  
 | | | |/ _ \| '_ ` _ \ / _` | | '_ \     | || '_ \| |_ / _ \ 
 | |_| | (_) | | | | | | (_| | | | | |    | || | | |  _| (_) |
 |____/ \___/|_| |_| |_|\__,_|_|_| |_|___|___|_| |_|_|  \___/ 
                                    |_____|                   
''')
    return f"{random.choice(colors)}{banner}{Fore.RESET}"



def get_apikey()->str:
    """Gets api key from Users input if not provided"""
    print(f"{Fore.GREEN}[+] TASK: Copy and paste yoru API key")
    return getpass.getpass("\t[>] API_KEY: ")

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

    def test_connection(self):
        """Test Connection API before Querying"""
        try :
            with request.urlopen(self.url) as status_code:
                successful_connect = status_code.getcode() == 200
                if successful_connect is True:
                    return f"{Fore.GREEN}[+] TASK: API is online! Proceeding..."
                print(f"{Fore.RED}[-] ERROR (HTML:{status_code.getcode()}): Unable to access API. ")
                sys.exit(1)
        except error.HTTPError as httperr:
            response_data = httperr.read().decode("utf-8", "ignore")
            print(f"{Fore.RED}[-] ERROR (HTTP Error): {response_data}")
            sys.exit(1)
        except error.URLError:
            print(f"{Fore.RED}[-] ERROR (WIN: 10061): Target actively refused connection.")
            sys.exit(1)

    def get_subdomains(self):
        url = f"{self.url}domain/{self.domain}/subdomains"
        response = requests.request("GET", url, headers=self.headers, verify=False)
        subdomains = response.json()["subdomains"]
        self.subdomains = subdomains


def main():
    print(display_banner())
    parser = argparse.ArgumentParser(prog="domain_info", usage="%(prog)s [options]", description=f"Queiries information on a given domain")
    parser.add_argument('-a', '--apikey', help="Enter API Key")
    parser.add_argument('-d', '--domain', help="Domain to query", required=True)
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
        print(f"{Fore.YELLOW}{subdomain}{Fore.RESET}")


if __name__ == '__main__':
    main() 