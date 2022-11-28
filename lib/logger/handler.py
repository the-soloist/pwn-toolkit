#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging


__all__ = [
    "TqdmLoggingHandler"
]


class TqdmLoggingHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except Exception:
            self.handleError(record)
