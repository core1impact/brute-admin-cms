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

logpath = "./fusion.txt"
ch = logging.FileHandler(logpath)
logger = logging.getLogger('log')
logger.setLevel(logging.INFO)
logger.addHandler(ch)

THREADS_COUNT = 15

def get_user_agent():
    user_agent = {
        'User-agent': '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15'}
    return user_agent


def main():
    setdefaulttimeout(15)
    q = Queue(maxsize=0)
    with open("./rest.txt") as ip:
        target = [line.rstrip('\n') for line in ip]

        for i in range(len(target)):
            q.put_nowait((i, target[i]))

            #with open("./best.txt") as txtpass:
            #    password = [line.rstrip('\n') for line in txtpass]
            #   for x in range(len(password)):
            #        q.put_nowait((i, target[i], password[x]))
    start_thread(q)

def start_thread(q):
    for i in range(THREADS_COUNT):
        worker = Thread(target=processor, args=(q,))
        worker.setDaemon(True)
        worker.start()
    q.join()


def processor(q, ):
    while not q.empty():
        item = q.get_nowait()
        apply_payload(q, item[1])
        q.task_done()
    return True


def apply_payload(q, session_url):
    try:
        response = requests.get(session_url + "/login.php", verify=False, headers=get_user_agent(), timeout=15)

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        session = requests.Session()
        session.headers.update(get_user_agent())

        if response.status_code == 200:
            print("[+] {}".format(session_url))
            logger.info("{}".format(session_url))
        #try:
        #    response = session.post(session_url + "/core/user_settings/user_dashboard.php", headers=headers, proxies=proxies, allow_redirects=True, verify=False)
        #    if response.status_code == 200:
        #        print("[+] {}".format(session_url))
        #        logger.info("{}".format(session_url))
    except:
        pass

# username: superadmin: admin fusionpbx

if __name__ == '__main__':
    urllib3.disable_warnings()
    sys.exit(main())

