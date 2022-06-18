#!/usr/bin/env python
# -*- coding: utf-8 -*-

import redis


REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
RC = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)


def redis_sadd():
    pass
