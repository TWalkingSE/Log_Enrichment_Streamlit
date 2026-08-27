"""
Cooperative job cancellation for long enrichment runs.
Works across Streamlit sessions via a flag file (open another tab and cancel).
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FLAG = ROOT / "data" / "jobs" / "cancel.flag"


class JobCancelled(Exception):
    """Raised when a cooperative cancel is requested."""


class CancelToken:
    def __init__(self, flag_path: Optional[Path] = None):
        self.flag_path = Path(flag_path) if flag_path else DEFAULT_FLAG
        self._local = threading.Event()

    def request_cancel(self) -> None:
        self._local.set()
        try:
            self.flag_path.parent.mkdir(parents=True, exist_ok=True)
            self.flag_path.write_text("1", encoding="utf-8")
        except OSError:
            pass

    def clear(self) -> None:
        self._local.clear()
        try:
            if self.flag_path.exists():
                self.flag_path.unlink()
        except OSError:
            pass

    def is_cancelled(self) -> bool:
        if self._local.is_set():
            return True
        try:
            return self.flag_path.exists()
        except OSError:
            return False

    def check(self) -> None:
        if self.is_cancelled():
            raise JobCancelled("Processamento cancelado pelo usuário")


_default_token: Optional[CancelToken] = None


def get_cancel_token() -> CancelToken:
    global _default_token
    if _default_token is None:
        _default_token = CancelToken()
    return _default_token


def request_cancel() -> None:
    get_cancel_token().request_cancel()


def clear_cancel() -> None:
    get_cancel_token().clear()


def check_cancel() -> None:
    get_cancel_token().check()
