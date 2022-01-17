#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hashlib import md5
from pathlib import Path
from PwnT00ls.lib.config import PT_PATH
import json


CACHE_DIR = Path(json.load(open(PT_PATH / "conf/pt.json"))["cache"]["save_dir"])

if not CACHE_DIR.is_dir():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


class Cache(object):
    def __init__(self):
        self.cache_dir = CACHE_DIR
        self.cache_file = None
        self.info = dict()
        self.info_str = str()
        self.hash = str()
        self.handler = None
        self.result = str()

    def _hash(self, text):
        h = md5()
        h.update(text)
        return h.hexdigest()

    def calc(self):
        pass

    def save(self):
        pass

    def search(self):
        pass


class CmdCache(Cache):
    def __init__(self, cmd: list, handler, **kwargs):
        super(CmdCache, self).__init__()

        self.cmd = list()
        self.handler = handler

        self._parse_cmd(cmd, **kwargs)
        self._dump_info()

    def _parse_cmd(self, cmd, **kwargs):
        """
        kwargs:
            $filename?: like filename1, filename2 ...
        """

        # ban same arg
        _args = [x for x in cmd if x.startswith("$")]
        assert len(_args) == len(set(_args))

        # parse args start with "$"
        for i in range(len(cmd)):
            c = cmd[i]
            if c.startswith("$"):
                arg = c[1:]
                cmd[i] = kwargs[arg]
                self.info[arg] = kwargs[arg]

        self.cmd = cmd

    def _dump_info(self):
        res = list()

        for k, v in self.info.items():
            if k.startswith("filename"):
                # calc file hash
                h = self._hash(open(v, "rb").read())
                res.append(f"{k}={h}")
            else:
                res.append(f"{k}={v}")

        res.sort()
        res = "\n".join(res)

        self.info_str = res
        return res

    def calc(self):
        # hash(cmd + info_str)
        text = " ".join(self.cmd) + "\n" + self.info_str
        self.hash = self._hash(text.encode())
        return self.hash

    def run(self):  # handler wrapper
        self.result = self.handler(self.cmd)
        return self.result

    def save(self):  # save result to file
        self.calc()
        self.cache_file = self.cache_dir / self.hash

        J = dict()
        J["result"] = self.result
        J["cmd"] = self.cmd
        J["info"] = self.info
        J["info_str"] = self.info_str

        json.dump(J, open(self.cache_file, "w"))

    def search(self):
        self.calc()
        self.cache_file = self.cache_dir / self.hash

        try:
            J = json.load(open(self.cache_file, "r"))
            self.result = J["result"]
            return self.result
        except:
            return None
