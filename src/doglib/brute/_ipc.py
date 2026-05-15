"""Small message helpers for `dog brute` worker IPC."""

import os
import time
from multiprocessing.connection import Connection


ENV_IPC = "_DOG_BRUTE_IPC"
ENV_ATTEMPT = "DOG_BRUTE_ATTEMPT"
ENV_WORKER_ID = "DOG_BRUTE_WORKER_ID"
ENV_WORKERS = "DOG_BRUTE_WORKERS"

MSG_LOG = "LOG"
MSG_FAIL = "FAIL"
MSG_WON = "WON"
MSG_GO_AHEAD = "GO_AHEAD"


def parse_ipc_env(value: str | None = None) -> tuple[int, int] | None:
    """Return (fd, worker_id) from the brute IPC environment variable."""
    if value is None:
        value = os.environ.get(ENV_IPC)
    if not value:
        return None

    try:
        fd_text, worker_text = value.split(":", 1)
        return int(fd_text), int(worker_text)
    except ValueError:
        return None


def make_message(kind: str, **fields) -> dict:
    return {
        "type": kind,
        "time": time.monotonic(),
        **fields,
    }


def send_message(conn: Connection, kind: str, **fields) -> None:
    conn.send(make_message(kind, **fields))


def recv_message(conn: Connection) -> dict:
    return conn.recv()


__all__ = [
    "ENV_IPC",
    "ENV_ATTEMPT",
    "ENV_WORKER_ID",
    "ENV_WORKERS",
    "MSG_FAIL",
    "MSG_GO_AHEAD",
    "MSG_LOG",
    "MSG_WON",
    "make_message",
    "parse_ipc_env",
    "recv_message",
    "send_message",
]
