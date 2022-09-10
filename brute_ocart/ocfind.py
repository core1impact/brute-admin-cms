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

logpath = "./ctalive.txt"
ch = logging.FileHandler(logpath)
logger = logging.getLogger('log')
logger.setLevel(logging.INFO)
logger.addHandler(ch)

THREADS_COUNT = 15

proxies = {'http': '192.168.0.180:8080', 'https': '192.168.0.180:8080'}


def get_user_agent():
    user_agent = {
        'User-agent': '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15'}
    return user_agent


def main():
    setdefaulttimeout(15)
    q = Queue(maxsize=0)

    with open("./ctcms.txt") as ip:
        target = [line.rstrip('\n') for line in ip]

        for i in range(len(target)):
            q.put_nowait((i, target[i]))

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
    session = requests.Session()
    session.headers.update(get_user_agent())

    try:
        r = session.get(session_url + "/admin.php/caiji/index", timeout=8, allow_redirects=False, verify=False)
    except:
        pass
    else:
        if r.status_code == 200:
            logger.info("{}".format(r.url))


if __name__ == '__main__':
    urllib3.disable_warnings()
    sys.exit(main())
