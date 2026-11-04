"""Race-resistant reading of regular files across supported platforms."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path


def _open_windows_file(path: Path) -> int:
    """Open a Windows file handle without following its final reparse point."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE

    get_info = kernel32.GetFileInformationByHandleEx
    get_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    get_info.restype = wintypes.BOOL

    get_file_type = kernel32.GetFileType
    get_file_type.argtypes = [wintypes.HANDLE]
    get_file_type.restype = wintypes.DWORD

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    invalid_handle = ctypes.c_void_p(-1).value
    handle = create_file(
        os.fsdecode(os.fspath(path)),
        0x80000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00200000 | 0x08000000 | 0x02000000 | 0x00000080,
        None,
    )

    if handle == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        info = FileAttributeTagInfo()

        if not get_info(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())

        if info.FileAttributes & 0x00000400:
            raise OSError(
                errno.ELOOP,
                "Reparse-point files are not permitted",
                str(path),
            )

        if get_file_type(handle) != 1:
            raise OSError(
                errno.EINVAL,
                "Input must be a regular disk file",
                str(path),
            )

        fd = msvcrt.open_osfhandle(
            int(handle),
            os.O_RDONLY | os.O_BINARY,
        )
        handle = None
        return fd
    finally:
        if handle is not None:
            close_handle(handle)


def _open_regular_file(path: Path) -> int:
    if os.name == "nt":
        return _open_windows_file(path)

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise OSError(
            errno.ENOTSUP,
            "Safe no-follow file opening is unavailable",
            str(path),
        )

    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    return os.open(path, flags)


def read_regular_file(
    path: Path,
    *,
    limit: int,
    label: str = "Input",
) -> tuple[bytes, os.stat_result]:
    """Read a bounded regular file without following its final link."""
    path = Path(path)

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError("File size limit must be a non-negative integer")

    fd = _open_regular_file(path)

    try:
        info = os.fstat(fd)

        if not stat.S_ISREG(info.st_mode):
            raise OSError(
                errno.EINVAL,
                f"{label} must be a regular file",
                str(path),
            )

        if info.st_size > limit:
            raise OSError(
                errno.EFBIG,
                f"{label} exceeds the size limit",
                str(path),
            )

        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)

        if len(data) > limit:
            raise OSError(
                errno.EFBIG,
                f"{label} exceeds the size limit",
                str(path),
            )

        return data, info
    finally:
        os.close(fd)
