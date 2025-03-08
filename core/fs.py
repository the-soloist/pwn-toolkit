#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path
from typing import Union
import shutil
import os
# from pwnkit.core.log import ulog

__all__ = [
    "mkdir_s",
    "touch_s",
    "rm_s",
    "cp_s",
    "mv_s",
    "is_empty_dir",
]


def mkdir_s(path: Union[str, Path]) -> Path:
    """Safely create a directory, including parent directories if needed.

    Args:
        path: Path to create (can be string or Path object)

    Returns:
        Path object of the created directory

    Raises:
        OSError: If directory creation fails
    """
    path = Path(path)
    try:
        path.mkdir(parents=True, exist_ok=True)
        # ulog.debug(f"Created directory: {path}")
        return path
    except OSError as e:
        # ulog.error(f"Failed to create directory {path}: {str(e)}")
        raise


def touch_s(path: Union[str, Path]) -> Path:
    """Safely create an empty file, creating parent directories if needed.

    Args:
        path: Path to create (can be string or Path object)

    Returns:
        Path object of the created file

    Raises:
        OSError: If file creation fails
    """
    path = Path(path)
    try:
        mkdir_s(path.parent)
        path.touch(exist_ok=True)
        # ulog.debug(f"Created file: {path}")
        return path
    except OSError as e:
        # ulog.error(f"Failed to create file {path}: {str(e)}")
        raise


def rm_s(path: Union[str, Path]) -> None:
    """Safely remove a file or directory.

    Args:
        path: Path to remove (can be string or Path object)

    Raises:
        OSError: If removal fails
    """
    path = Path(path)
    try:
        if path.is_file() or path.is_symlink():
            path.unlink()
            # ulog.debug(f"Removed file: {path}")
        elif path.is_dir():
            shutil.rmtree(path)
            # ulog.debug(f"Removed directory: {path}")
    except OSError as e:
        # ulog.error(f"Failed to remove {path}: {str(e)}")
        raise


def cp_s(src: Union[str, Path], dst: Union[str, Path]) -> Path:
    """Safely copy a file or directory.

    Args:
        src: Source path (can be string or Path object)
        dst: Destination path (can be string or Path object)

    Returns:
        Path object of the copied file/directory

    Raises:
        OSError: If copy operation fails
    """
    src, dst = Path(src), Path(dst)
    try:
        if src.is_file():
            shutil.copy2(src, dst)
            # ulog.debug(f"Copied file from {src} to {dst}")
        elif src.is_dir():
            shutil.copytree(src, dst)
            # ulog.debug(f"Copied directory from {src} to {dst}")
        return dst
    except OSError as e:
        # ulog.error(f"Failed to copy from {src} to {dst}: {str(e)}")
        raise


def mv_s(src: Union[str, Path], dst: Union[str, Path]) -> Path:
    """Safely move a file or directory.

    Args:
        src: Source path (can be string or Path object)
        dst: Destination path (can be string or Path object)

    Returns:
        Path object of the moved file/directory

    Raises:
        OSError: If move operation fails
    """
    src, dst = Path(src), Path(dst)
    try:
        shutil.move(str(src), str(dst))
        # ulog.debug(f"Moved from {src} to {dst}")
        return dst
    except OSError as e:
        # ulog.error(f"Failed to move from {src} to {dst}: {str(e)}")
        raise


def is_empty_dir(path: Union[str, Path]) -> bool:
    """Check if a directory is empty.

    Args:
        path: Path to check (can be string or Path object)

    Returns:
        bool: True if directory exists and is empty, False otherwise
    """
    path = Path(path)
    try:
        if not path.is_dir():
            return False
        return not any(path.iterdir())
    except OSError as e:
        # ulog.error(f"Failed to check directory {path}: {str(e)}")
        return False
