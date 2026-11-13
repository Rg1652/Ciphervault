"""
Native Windows Drag and Drop Integration for Tkinter / CustomTkinter
Enables dragging files directly from Windows File Explorer onto the app window.
"""

import sys
import os
import ctypes
from ctypes import wintypes
from typing import Callable, List, Optional

WM_DROPFILES = 0x0233
GWLP_WNDPROC = -4

# Windows API signatures
user32 = ctypes.windll.user32
shell32 = ctypes.windll.shell32

WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_longlong, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
user32.SetWindowLongPtrW.restype = ctypes.c_void_p

user32.CallWindowProcW.argtypes = [ctypes.c_void_p, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.CallWindowProcW.restype = ctypes.c_longlong

shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
shell32.DragAcceptFiles.restype = None

shell32.DragQueryFileW.argtypes = [wintypes.WPARAM, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
shell32.DragQueryFileW.restype = wintypes.UINT

shell32.DragFinish.argtypes = [wintypes.WPARAM]
shell32.DragFinish.restype = None


class WindowsDragDropHandler:
    def __init__(self, hwnd: int, callback: Callable[[List[str]], None]):
        self.hwnd = hwnd
        self.callback = callback
        self.old_wndproc = None
        self._c_wndproc = None
        self._active = False
        self._setup()

    def _setup(self):
        try:
            def py_wndproc(hwnd, msg, wparam, lparam):
                if msg == WM_DROPFILES:
                    hdrop = wparam
                    count = shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)
                    dropped_files = []
                    for i in range(count):
                        length = shell32.DragQueryFileW(hdrop, i, None, 0)
                        buf = ctypes.create_unicode_buffer(length + 1)
                        shell32.DragQueryFileW(hdrop, i, buf, length + 1)
                        dropped_files.append(buf.value)
                    shell32.DragFinish(hdrop)

                    if self.callback and dropped_files:
                        try:
                            self.callback(dropped_files)
                        except Exception as e:
                            print(f"[DragDrop] Error in drop callback: {e}", file=sys.stderr)
                    return 0

                return user32.CallWindowProcW(self.old_wndproc, hwnd, msg, wparam, lparam)

            self._c_wndproc = WNDPROC(py_wndproc)
            self.old_wndproc = user32.SetWindowLongPtrW(
                self.hwnd,
                GWLP_WNDPROC,
                ctypes.cast(self._c_wndproc, ctypes.c_void_p)
            )
            shell32.DragAcceptFiles(self.hwnd, True)
            self._active = True
        except Exception as e:
            print(f"[DragDrop] Warning: Could not initialize native drag & drop: {e}", file=sys.stderr)

    def teardown(self):
        if self._active and self.old_wndproc:
            try:
                shell32.DragAcceptFiles(self.hwnd, False)
                user32.SetWindowLongPtrW(self.hwnd, GWLP_WNDPROC, self.old_wndproc)
                self._active = False
            except Exception:
                pass
