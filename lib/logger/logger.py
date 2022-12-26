#!/usr/bin/env python
# -*- coding: utf-8 -*-
# edit from https://github.com/shmilylty/OneForAll/blob/master/config/log.py

import json
import sys
from loguru import logger
from pathlib import Path
from pwnutils.lib.config import SETTING


__all__ = [
    "logger"
]


log_dir = Path(SETTING["log"]["dir"])
log_path = log_dir / "pwn-utils.log"

if not log_path.is_file():
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch()


# 终端日志输出格式
stdout_fmt = (
    "<cyan>{time:HH:mm:ss}</cyan> "
    "[<level>{level: >8}</level>] "
    "<blue>{module}</blue>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)

# 日志文件记录格式
logfile_fmt = (
    "<light-green>{time:YYYY-MM-DD HH:mm:ss.SSS}</light-green> "
    "[<level>{level: >8}</level>] "
    "<blue>{module}</blue>.<blue>{function}</blue>:"
    "<blue>{line}</blue> - <level>{message}</level>"
)

logger.remove()

# logger.remove(handler_id=None)  # 控制台静默运行
logger.add(sys.stderr, level="INFO", format=stdout_fmt, enqueue=True)  # 命令终端日志级别默认为 INFO
logger.add(log_path, level="TRACE", format=logfile_fmt, enqueue=True, encoding="utf-8")  # 日志文件默认为级别为 TRACE


if __name__ == "__main__":
    logger.trace("test trace")
    logger.debug("test debug")
    logger.info("test info")
    logger.success("test success")
    logger.warning("test warning")
    logger.error("test error")
    logger.critical("test critical")
