#!/usr/bin/env python
# -*- coding: utf-8 -*-
# edit from https://github.com/shmilylty/OneForAll/blob/master/config/log.py

from loguru import logger
from pathlib import Path
from PwnT00ls.lib.config import PT_PATH
import json
import sys


log_dir = json.load(open(PT_PATH / "conf/pt.json"))["log"]["save_dir"]
log_path = Path(log_dir) / "pt.log"

if not log_path.is_file():
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch()

# 终端日志输出格式
stdout_fmt = (
    "<cyan>{time:HH:mm:ss}</cyan> "
    "[<level>{level: <8}</level>] "
    "<blue>{module}</blue>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)

# 日志文件记录格式
logfile_fmt = (
    "<light-green>{time:YYYY-MM-DD HH:mm:ss.SSS}</light-green> "
    "[<level>{level: <8}</level>] "
    "<blue>{module}</blue>.<blue>{function}</blue>:"
    "<blue>{line}</blue> - <level>{message}</level>"
)

logger.remove()

# 如果你想在命令终端静默运行，可以将以下一行中的 level 设置为 QUITE
logger.add(sys.stderr, level="INFO", format=stdout_fmt, enqueue=True)  # 命令终端日志级别默认为INFOR
logger.add(log_path, level="TRACE", format=logfile_fmt, enqueue=True, encoding="utf-8")  # 日志文件默认为级别为DEBUG


if __name__ == "__main__":
    logger.trace("test trace")
    logger.debug("test debug")
    logger.info("test info")
    logger.success("test success")
    logger.warning("test warning")
    logger.error("test error")
    logger.critical("test critical")
