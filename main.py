import os
import json
import mmap
import requests
from urllib.parse import urlparse
import string
import requests
import argparse
import random
import threading

cwd = os.getcwd()

if os.name == "nt":
    os.system("cls")
else:
    os.system("clear")
    
print("""

▄██   ▄      ▄████████             ▄████████  ▄██████▄     ▄████████    ▄████████ 
███   ██▄   ███    ███            ███    ███ ███    ███   ███    ███   ███    ███ 
███▄▄▄███   ███    ███            ███    █▀  ███    ███   ███    ███   ███    █▀  
▀▀▀▀▀▀███   ███    ███   ██████   ███        ███    ███  ▄███▄▄▄▄██▀   ███        
▄██   ███ ▀███████████   ██████   ███        ███    ███ ▀▀███▀▀▀▀▀   ▀███████████ 
███   ███   ███    ███            ███    █▄  ███    ███ ▀███████████          ███ 
███   ███   ███    ███            ███    ███ ███    ███   ███    ███    ▄█    ███ 
 ▀█████▀    ███    █▀             ████████▀   ▀██████▀    ███    ███  ▄████████▀               


Made by: Apollyon    
Do python main.py -h for help                   
""")
parse = argparse.ArgumentParser()
parse.add_argument('-u','--url',help="Target URL",required=False)
parse.add_argument('-ulist','--url_list',help="Target multiple URLs from a file",required=False)
parse.add_argument('-to','--timeout',help="Set timeout for requests [10 seconds by default]", default=10,required=False)
parse.add_argument('-wiz','--wizard',help="Run the wizard, for beginner and first time users",required=False,default=False, action = "store_true")
parse.add_argument('-t','--threads',help="Threads [1 by default]",default=1,required=False)
parse.add_argument('-pr','--proxy',help="Add a list of proxies to use [HTTP, HTTPS, SOCKS]",required=False)
parse.add_argument('-auth','--authentication',help="Load headers and/or cookies and/or URL schema from a file to run a scan while authenticated",required=False,default="auth.json")
parse.add_argument('-save','--save_to_file',help="Save vulnerablities and vulnerable URLs to a file on disk",required=False,default="CORS_scanner_saves.txt")
parse = parse.parse_args()

def save_file_writer(save_file , msg):
    if save_file:
        with open(save_file , "a") as f:
            f.write(msg)
            f.write("\n")

def make_request_finally(url , headers , cookies , proxies ,  timeout):
    if proxies:
        if cookies:
            response = requests.get(url, headers=headers , cookies = cookies , proxies=random.choice(proxies) , timeout = timeout_time)
        else:
            response = requests.get(url, headers=headers , proxies=random.choice(proxies) , timeout = timeout_time)
    else:
        if cookies:
            response = requests.get(url, headers=headers , cookies = cookies  , timeout = timeout_time)
        else:
            response = requests.get(url, headers=headers  , timeout = timeout_time)
    return response

def scan_single_url(url , proxies , auth_stuff , timeout_time , save_file , url_clean):

    
    #structure of auth stuff
    #headers , cookies
    headers = auth_stuff[0]
    cookies = auth_stuff[1]
    domain = url_clean[1]

    print("="*20)
    print(f"[*] TESTING URL: {url}")
    issue_found = False
    domain = urlparse(url).netloc

    response = make_request_finally(url , headers , cookies , proxies ,  timeout_time)

    response_headers = response.headers
    if "access-control-allow-origin" in response_headers.keys():
        pass
    else:
        print("[*] No issues found")
        print("="*20)
        return
    #if there is no cors policy then theres no point to check for other


    headers["Origin"] = url_clean[0]
    response = make_request_finally(url , headers , cookies , proxies ,  timeout_time)
    response_headers = response.headers
        
    if "access-control-allow-credentials" in response_headers.keys():
        print("[!] Access Control Allow Credentials enabled.")
        save_file_writer(save_file , f"{url_clean[0]} | [!] Access Control Allow Credentials enabled.")
        issue_found = True

    if "access-control-allow-origin" in response_headers.keys():
        if response_headers["access-control-allow-origin"] == "*":
            print("[!] Wildcard Access Control Allow Origin header found")
            save_file_writer(save_file , f"{url_clean[0]} | [!] Wildcard Access Control Allow Origin header found")
            print("="*20)
            return #if acao is wildcard then no point of checking others


    headers["Origin"] = "null"
    response = make_request_finally(url , headers , cookies , proxies ,  timeout_time)
    response_headers = response.headers
    if "access-control-allow-origin" in response_headers.keys():
        print("[!] NULL origin vulnerability")
        save_file_writer(save_file , f"{url_clean[0]} | [!] NULL origin vulnerability")
        issue_found = True

        
    headers["Origin"] = f"https://ya_cors_test-{domain}"
    response = make_request_finally(url , headers , cookies , proxies ,  timeout_time)
    response_headers = response.headers
    if "access-control-allow-origin" in response_headers.keys():
        print("[!] Pre domain wildcard vulnerability")
        save_file_writer(save_file , f"{url_clean[0]} | [!] Pre domain wildcard vulnerability")
        issue_found = True
            
    domain_name = domain.split(".")[0].strip()
    domain_tld = domain.split(".")[1].strip()
    headers["Origin"] = f"https://{domain_name}ya_cors_test.{domain_tld}"
    response = make_request_finally(url , headers , cookies , proxies ,  timeout_time)
    response_headers = response.headers
    if "access-control-allow-origin" in response_headers.keys():
        print("[!] Post domain wildcard vulnerability")
        save_file_writer(save_file , f"{url_clean[0]} | [!] Post domain wildcard vulnerability")
        issue_found = True

    headers["Origin"] = f"http://ya_broken_parser%60%60.com"
    response = make_request_finally(url , headers , cookies , proxies ,  timeout_time)
    response_headers = response.headers
    if "access-control-allow-origin" in response_headers.keys():
        print("[!] CORS parser might be broken")
        save_file_writer(save_file , f"{url_clean[0]} | [!] CORS parser might be broken")
        issue_found = True

    if not issue_found:
        print("[*] No issues found")
    print("="*20)


def basic_url_parsing(url):
    if r"https://" in url or r"http://" in url:
        url = url
    else:
        url = r"https://" + url
    return url

def advance_url_parsing(url):
    domain = urlparse(url).netloc
    protocol = urlparse(url).scheme
    path = urlparse(url).path
    return (domain , protocol , path)

def url_scanner(url_or_file , proxies , auth_stuff , timeout_time , save_file , scan_mode , x , urls_per_thread , carry_over):
    #structure of auth stuff here is
    #(headers,cookies,url_schema_logins,special_cookies,special_headers,special_url_schema_logins)
    headers = auth_stuff[0]
    
    cookies = auth_stuff[1]
    url_schema_login = auth_stuff[2]

    special_cookies = auth_stuff[3]
    special_headers = auth_stuff[4]
    special_url_schema_logins = auth_stuff[5]

    if scan_mode == "multi":
        if os.path.isfile(url_or_file):
            file_pointer = 0
            current_range_start = x*urls_per_thread
            current_range_end = (x+1)*urls_per_thread
            if carry_over:
                current_range_end = current_range_end + carry_over
            with open(url_or_file , "r") as f:
                for line in f:
                    if file_pointer >= current_range_start and file_pointer <= current_range_end:
                        current_attack_url = basic_url_parsing(line.strip())

                        domain , protocol , path = advance_url_parsing(current_attack_url)
                        something_raw = r"://"

                        url_clean = (current_attack_url , domain)

                        if domain in special_url_schema_logins:
                            username = special_url_schema_logins[domain][0]
                            password = special_url_schema_logins[domain][1]
                            current_attack_url = f"{protocol}{something_raw}{username}:{password}@{domain}{path}"
                        else:
                            if url_schema_login:
                                username = url_schema_login[domain][0]
                                password = url_schema_login[domain][1]
                                current_attack_url = f"{protocol}{something_raw}{username}:{password}@{domain}{path}"
                        
                        if domain in special_headers:
                            headers = special_headers[domain]

                        if domain in special_cookies:
                            cookies = special_cookies

                        auth_stuff = (headers , cookies)
                        scan_single_url(current_attack_url , proxies , auth_stuff , timeout_time , save_file , url_clean)
                    file_pointer = file_pointer + 1 
        else:
            print("[X] URL FILE SPECIFIED DOES NOT EXIST")
            quit()
    else:
        current_attack_url = url_or_file
        domain , protocol , path = advance_url_parsing(current_attack_url)
        something_raw = r"://"

        url_clean = (current_attack_url , domain)

        if domain in special_url_schema_logins:
            username = special_url_schema_logins[domain][0]
            password = special_url_schema_logins[domain][1]
            current_attack_url = f"{protocol}{something_raw}{username}:{password}@{domain}{path}"
        else:
            if url_schema_login:
                username = url_schema_login[domain][0]
                password = url_schema_login[domain][1]
                current_attack_url = f"{protocol}{something_raw}{username}:{password}@{domain}{path}"
                        
        if domain in special_headers:
            headers = special_headers[domain]

        if domain in special_cookies:
            cookies = special_cookies

        auth_stuff = (headers , cookies)
        scan_single_url(current_attack_url , proxies , auth_stuff , timeout_time , save_file , url_clean)


def load_authentication(auth_path):

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0',
        "Accept-Language": "en-US,en;q=0.6",
        "Accept-Encoding": "gzip, deflate, br, zstd"
    }
    cookies = {}
    url_schema_login = ()

    special_cookies = {}
    special_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0',
        "Accept-Language": "en-US,en;q=0.6",
        "Accept-Encoding": "gzip, deflate, br, zstd"
    }
    special_url_schema_logins = {}

    if os.path.isfile(auth_path):
        with open(auth_path , "r") as auth_file:
            auth_data = auth_file.read()
        auth_data = json.loads(auth_data)
        #loading headers
        if auth_data["auth_headers"]:
            for header in auth_data["auth_headers"]:
                headers[header] = auth_data["auth_headers"][header]

        if auth_data["cookies"]:
            cookies = auth_data["cookies"]

        url_schema_logins = False
        if auth_data["url_schema_login"]:
            url_schema_logins = (auth_data["url_schema_login"][0] , auth_data["url_schema_login"][1],)

        
        if auth_data["special_cookies"]:
            special_cookies = auth_data["special_cookies"]

        if auth_data["special_auth_headers"]:
            special_headers = auth_data["special_auth_headers"]
            for domain in auth_data["special_auth_headers"]:
                for header in headers:
                    if header not in auth_data["special_auth_headers"][domain]:
                        auth_data["special_auth_headers"][domain][header] = headers[header]

        if auth_data["special_url_schema_login"]:
            special_url_schema_logins = auth_data["special_url_schema_login"]
        
    else:
        print("[X] AUTH FILE DOES NOT EXIST")
    
    return (headers,cookies,url_schema_logins,special_cookies,special_headers,special_url_schema_logins)

def load_proxies(proxy_path):
    proxies_but_dict = []

    if os.path.isfile(proxy_path):
        with open(proxy_path , "r") as proxy_file:
            proxies = proxy_file.readlines()
        proxies = list(filter(None, proxies)) #remove emptiness
        for proxy in proxies:
            proxy = proxy.strip()
            if proxy:
                try:
                    proxy_split = proxy.split(r"://")
                    proxy_ip , proxy_scheme = proxy_split[1] , proxy_split[0]
                    proxy_dict = {proxy_scheme:proxy}
                    proxies_but_dict.append(proxy_dict)
                except:
                    print(f"[!] ERROR WHILE LOADING PROXY {proxy}, USING REST OF THE PROXIES")
        if len(proxies_but_dict) == 0:
            print(f"[!] NO VALID PROXIES, RUNNING WITHOUT PROXIES")
            return proxies_but_dict
        else:
            print(f"[*] RUNNING USING PROXIES GIVEN")
    else:
        print("[X] PROXY FILE PATH DOES NOT EXIST")
        quit()
    return proxies_but_dict

if not parse.wizard:
    proxies = []
    auth = (
        {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0',
        "Accept-Language": "en-US,en;q=0.6",
        "Accept-Encoding": "gzip, deflate, br, zstd"
    } ,
    {} , () , {} , {} , {}
    )
    timeout_time = 10

    if parse.proxy:
        proxies = load_proxies(parse.proxy)

    if parse.authentication:
        auth = load_authentication(parse.authentication)

    if parse.timeout:
        timeout_time = int(parse.timeout) #in seconds
    else:
        timeout_time = 10

    if parse.save_to_file:
        save_file = parse.save_to_file
    else:
        save_file = ""

    if parse.url:

        current_target = basic_url_parsing(parse.url)
            
        url_scanner(current_target , proxies , auth , timeout_time , save_file , "single" , 0 , 0 , 0)
        #ignore multithreading for single urls because it doesnt make a lot of sense

    else:
        if parse.url_list:
            urls_file_path = parse.url_list
            if os.path.isfile(urls_file_path):

                with open(urls_file_path, 'rb+') as f:
                    mm = mmap.mmap(f.fileno(), 0)
                    lines = 0
                    while mm.readline():
                        lines += 1
                    mm.close()

                if parse.threads:
                    threads = int(parse.threads)
                else:
                    threads = 2

                urls_per_thread = lines//threads
                carry_over = lines%threads

                x = 0
                for x in range(threads-1):
                    threading.Thread(target=url_scanner, args=(urls_file_path , proxies , auth , timeout_time , save_file , "multi" , x , urls_per_thread , 0)).start()    
                else:
                    threading.Thread(target=url_scanner, args=(urls_file_path , proxies , auth , timeout_time , save_file , "multi" , x , urls_per_thread , carry_over)).start()    
            
            else:
                print("[X] GIVEN URL FILE NOT FOUND")
                quit()

        else:
            print("[X] NO TARGET URL OR TARGET FILE FOUND. QUITTING PROGRAM.")
            quit()
else:
    target_mode = input("YA-CORS Wizard | Do you want to check a [1]single URL or a [2]multiple URLs :").strip().lower()
    proxies = []
    auth = (
        {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0',
        "Accept-Language": "en-US,en;q=0.6",
        "Accept-Encoding": "gzip, deflate, br, zstd"
    } ,
    {} , () , {} , {} , {}
    )
    timeout_time = 10
    match target_mode:
        case "1" | "single" | "single url":

            current_target = input("YA-CORS Wizard | Enter the URL you want to test :").strip().lower()
            if current_target:
                current_target = basic_url_parsing(current_target)
            else:
                print("[X] NO TARGET URL SPECIFIED")
                quit()

            proxy_file = input("YA-CORS Wizard | Enter the path for the proxy file if you want to use them, leave blank or enter no if you dont want to use proxies :").strip().lower()

            if proxy_file:
                proxies = load_proxies(proxy_file)

            req_timeout = input("YA-CORS Wizard | Enter the timeout value for each request in seconds :").strip().lower()
            if req_timeout:
                try:
                    timeout_time = int(req_timeout)
                except:
                    print("[X] REQUEST TIMEOUT VALUE MUST BE INTEGER")
            else:
                timeout_time = 10

            auth_file = input("YA-CORS Wizard | Enter the path for auth headers and cookies if you want to use them, leave blank or enter no if you dont want to scan without auth :").strip().lower()

            if auth_file:
                auth = load_authentication(auth_file)

            save_file_path = input("YA-CORS Wizard | Enter the path for file where to save results, leave blank or enter no if you dont want to scan without auth :").strip().lower()

            if save_file_path:
                save_file = save_file_path
            else:
                save_file = ""

            url_scanner(current_target , proxies , auth , timeout_time , save_file , "single" , 0 , 0 , 0)

        case "2" | "multiple" | "multiple url" | "multiple urls" | "multi":

            url_file = input("YA-CORS Wizard | Enter the URL file you want to test :").strip().lower()
            
            if url_file:
                if os.path.isfile(url_file):
                    with open(url_file, 'rb+') as f:
                        mm = mmap.mmap(f.fileno(), 0)
                        lines = 0
                        while mm.readline():
                            lines += 1
                        mm.close()
                    threads_count = input("YA-CORS Wizard | How many threads do you want to use :").strip()
                    try:
                        if threads_count > 0:
                            threads = int(threads_count)
                        else:
                            print("[X] NUMBER OF THREADS CANT BE LESS THAN ZERO")
                            quit()
                    except:
                        threads = 1

                    urls_per_thread = lines//threads
                    carry_over = lines%threads
            else:
                print("[X] NO TARGET URL FILE SPECIFIED")
                quit()

            proxy_file = input("YA-CORS Wizard | Enter the path for the proxy file if you want to use them, leave blank or enter no if you dont want to use proxies :").strip().lower()

            if proxy_file:
                proxies = load_proxies(proxy_file)

            req_timeout = input("YA-CORS Wizard | Enter the timeout value for each request in seconds :").strip().lower()
            if req_timeout:
                try:
                    timeout_time = int(req_timeout)
                except:
                    print("[X] REQUEST TIMEOUT VALUE MUST BE INTEGER")
            else:
                timeout_time = 10

            auth_file = input("YA-CORS Wizard | Enter the path for auth headers and cookies if you want to use them, leave blank or enter no if you dont want to scan without auth :").strip().lower()

            if auth_file:
                auth = load_authentication(auth_file)

            save_file_path = input("YA-CORS Wizard | Enter the path for file where to save results, leave blank or enter no if you dont want to scan without auth :").strip().lower()

            if save_file_path:
                save_file = save_file_path
            else:
                save_file = ""

            x = 0
            for x in range(threads-1):
                threading.Thread(target=url_scanner, args=(url_file , proxies , auth , timeout_time , save_file , "multi" , x , urls_per_thread , 0)).start()    
            else:
                threading.Thread(target=url_scanner, args=(url_file , proxies , auth , timeout_time , save_file , "multi" , x , urls_per_thread , carry_over)).start() 

        case _:
            print("[X] NOT A VALID OPTION")
            quit()  


    



