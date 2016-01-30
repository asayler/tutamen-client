#!/usr/bin/env python3

import time
import uuid
import functools
import threading
import statistics
import requests
import sys
from concurrent import futures

def get_auth(path_crt, path_key, obj_perm, obj_type, obj_uid=None):

    url = "https://ac.tutamen-test.bdr1.volaticus.net/api/v1/authorizations/"

    json = {'objperm': obj_perm,
            'objtype': obj_type,
            'objuid': str(obj_uid) if obj_uid else ""}

    res = requests.post(url=url, json=json, cert=(path_crt, path_key))
    res.raise_for_status()
    uid = res.json()['authorizations'][0]
    return uid

def get_token(path_crt, path_key, uid):

    url = "https://ac.tutamen-test.bdr1.volaticus.net/api/v1/authorizations/"
    url += str(uid) + "/"

    res = requests.get(url=url, cert=(path_crt, path_key))
    res.raise_for_status()
    authz = res.json()
    return authz['token']

def get_ac_null_cert(path_crt, path_key):

    url = "https://ac.tutamen-test.bdr1.volaticus.net/api/v1/"
    res = requests.get(url=url, cert=(path_crt, path_key))
    res.raise_for_status()

def get_ac_null():

    url = "https://ac.tutamen-test.bdr1.volaticus.net/api/v1/"
    res = requests.get(url=url)
    res.raise_for_status()

def res_time():

    def _decorator(func):

        @functools.wraps(func)
        def _wrapper(*args, **kwargs):

            start = time.time()
            func(*args, **kwargs)
            dur = time.time() - start
            return dur

        return _wrapper

    return _decorator

def min_time(sec):

    def _decorator(func):

        @functools.wraps(func)
        def _wrapper(*args, **kwargs):

            start = time.time()
            ret = func(*args, **kwargs)
            dur = time.time() - start
            if dur < sec:
                time.sleep(sec-dur)
            return ret

        return _wrapper

    return _decorator

if __name__ == "__main__":

    path_crt = sys.argv[1]
    path_key = sys.argv[2]
    iops_s = int(sys.argv[3])
    iops_f = int(sys.argv[4])
    step = int(sys.argv[5])
    duration = int(sys.argv[6])
    min_t = float(sys.argv[7])

    @min_time(min_t)
    @res_time()
    def min_get_auth(path_crt, path_key, obj_perm, obj_type, obj_uid=None):

        try:
            get_auth(path_crt, path_key, obj_perm, obj_type, obj_uid=obj_uid)
        except Exception as error:
            print(error)

    @min_time(min_t)
    @res_time()
    def min_get_ac_null_cert(path_crt, path_key):

        try:
            get_ac_null_cert(path_crt, path_key)
        except Exception as error:
            print(error)

    @min_time(min_t)
    @res_time()
    def min_get_ac_null():

        try:
            get_ac_null()
        except Exception as error:
            print(error)    

    for iops_t in range(iops_s, iops_f, step):

        threads = iops_t * min_t
        launch = iops_t * duration


        futs = []
        times = []
        start = time.time()
        with futures.ThreadPoolExecutor(max_workers=threads) as e:
#            print("LAUNCHING")
            for i in range(0, launch):
                futs.append(e.submit(min_get_ac_null))
#                futs.append(e.submit(min_get_ac_null_cert, path_crt, path_key))
#                futs.append(e.submit(min_get_auth, path_crt, path_key, "create", "acserver"))
#            print("WAITING")
            for f in futs:
                times.append(f.result())
#            print("COMPLETE")
        length = time.time() - start

        cnt = len(times)
        avg = statistics.mean(times)
        std = statistics.stdev(times)
        iops = (float(cnt) / float(length))
        print("{}, {:.1f}, {:.3f}, {:.3f}".format(cnt, iops, avg, std))

        # print("Requests         = {}".format(cnt))
        # print("Response Mean    = {}".format(avg))
        # print("Response Std Dev = {}".format(std))
        # print("IOPS Mean        = {}".format(iops))
