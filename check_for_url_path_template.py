#!/usr/bin/env python3


__author__ = "StrikeFLow"
__date__ = "4/21/2023"
__version__ = "0.01"
__description__ = """A template script to look for specifc URL paths at scale"""


import argparse
import sys
import time
import os
import re
import csv
import threading
from queue import Queue

# Third party modules
missing_modules = []
try:
    import requests
except ImportError as error:
    missing_module = str(error).split(' ')[-1]
    missing_modules.append(missing_module)

if missing_modules:
    for m in missing_modules:
        print('[-] Missing module: {}'.format(m))
        print('[*] Try running "pip3 install {}", or do an Internet search for installation instructions.\n'.format(m.strip("'")))
    exit()
from requests.packages.urllib3.exceptions import InsecureRequestWarning


def parse_to_csv(data, csv_name=None):
    """Takes a list of lists and outputs to a csv file."""
    csv_name = 'new_scan_data.csv' if not csv_name else csv_name
    if not os.path.isfile(csv_name):
        if sys.version.startswith('3'):
            csv_file = open(csv_name, 'w', newline='')
        else:
            csv_file = open(csv_name, 'wb')
        csv_writer = csv.writer(csv_file)
        top_row = ['Requested URL, URL, Text']
        csv_writer.writerow(top_row)
        print('[+] The file {} does not exist. New file created!'.format(csv_name))
    else:
        try:
            if sys.version.startswith('3'):
                csv_file = open(csv_name, 'a', newline='')
            else:
                csv_file = open(csv_name, 'ab')
        except PermissionError:
            print("[-] Permission denied to open the file {}. Check if the file is open and try again.".format(csv_name))
            exit()
        csv_writer = csv.writer(csv_file)
        print('\n[+]  {} exists. Appending to file!\n'.format(csv_name))
    for line in data:
        csv_writer.writerow(line)
    csv_file.close()


def build_request() -> requests.sessions.Session:
    """Initializes a Session object, adds some headers
    and returns the Session object.
    """
    s = requests.Session()
    if args.proxy:
        s.proxies['http'] = args.proxy
        s.proxies['https'] = args.proxy
    return s


def manage_queue():
    """Manages the queue and calls the get_customer_messages() function"""
    while True:
        current_url = url_queue.get()
        do_scan(current_url)
        url_queue.task_done()


def do_scan(url):
    """Sends a request to a specified url.
    """
    s = build_request()
    try:
        resp = s.get(url, verify=False, timeout=int(args.timeout))
    except Exception as e:
        if args.debug:
            with print_lock:
                print('[-] Unable to connect to site: {}'.format(url))
        return
    
    # Here is where you would write some logic depending on what you expect in the response
    if resp.status_code == 200:
        
        if "/secrets.json" in resp.url:
            if 'someSpecifcThing' in resp.text:
                all_data.append((url,resp.url,resp.text[:300]))
                print(resp.url)


def main():
    for i in range(args.threads):
        t = threading.Thread(target=manage_queue)
        t.daemon = True
        t.start()

    for current_url in urls:
        url_queue.put(current_url)

    url_queue.join()

    #print(all_data)
    parse_to_csv(all_data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-d", "--debug",
                        help="displays error messages",
                        action="store_true")
    parser.add_argument(
        "-pr", "--proxy", 
        help="Specify a proxy to use (-pr 127.0.0.1:8080)"
    )
    parser.add_argument(
        "-t", "--threads",
        nargs="?",
        type=int,
        const=30,
        default=30,
        help="Specify number of threads (default=30)"
    )
    parser.add_argument(
        "-f", "--filename",
        help="Specify a file containing hostnames or IP addresses."
    )
    parser.add_argument("-to", "--timeout",
                        nargs="?", 
                        type=int, 
                        default=10, 
                        help="Specify number of seconds until a connection timeout (default=10)")
    args = parser.parse_args()

    if not args.filename:
        parser.print_help()
        print("[-] Please specify an input file listing IP addresses "
              "and/or hostnames (-f) or a range of IP address (-r). "
              "or a single url (-u)")
        exit()

    # Initialize input data
    input_data = []

    if args.filename:
        filename = args.filename
        if not os.path.exists(filename):
            parser.print_help()
            print(f"[-] The file {filename} cannot be found or you do not have "
                   "permission to open the file.")
            exit()
        with open(filename) as f:
            input_data = f.read().splitlines()


    # Suppress SSL warnings in the terminal
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    # Print banner
    print()
    word_banner = '{} version: {}. Coded by: {}'.format(sys.argv[0].title()[:-3], __version__, __author__)
    print('=' * len(word_banner))
    print(word_banner)
    print('=' * len(word_banner))
    print()
    time.sleep(1)

    # Remove duplicates from the list
    input_data = list(set(input_data))

    temp_urls = [i for i in input_data]
    
    # Here is where you would add the endpoints you want to look at:
    endpoints = [
        "/secrets.json",
    ]
    urls = []
    for i in temp_urls:
        for j in endpoints:
            urls.append(i + j)
    
    print(f"[+] Loaded {len(urls)} URLs")
            
    # Threading lock and queue initialization
    print_lock = threading.Lock()
    url_queue = Queue()

    all_data = []
    main()

