"""Bruteforce orchestration helpers for the `dog brute` CLI."""

import os
import sys
from collections.abc import Callable
from multiprocessing.connection import Connection

from doglib.brute._ipc import (
    ENV_ATTEMPT,
    ENV_IPC,
    ENV_WORKER_ID,
    ENV_WORKERS,
    MSG_GO_AHEAD,
    MSG_WON,
    parse_ipc_env,
    recv_message,
    send_message,
)


_conn: Connection | None = None
_worker_id: int | None = None
_finish_sent = False
_go_ahead_callback: Callable[[], None] | None = None


def _env_int(name: str) -> int | None:
    value = os.environ.get(name)
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


brute_id = _env_int(ENV_WORKER_ID)
brute_attempt = _env_int(ENV_ATTEMPT)
brute_workers = _env_int(ENV_WORKERS)


def _set_worker_connection(conn: Connection, worker_id: int) -> None:
    global _conn, _worker_id, _finish_sent
    _conn = conn
    _worker_id = worker_id
    _finish_sent = False


def _set_go_ahead_callback(callback: Callable[[], None] | None) -> None:
    global _go_ahead_callback
    _go_ahead_callback = callback


def _finish_called() -> bool:
    return _finish_sent


def _ensure_worker_connection() -> tuple[Connection, int]:
    global _conn, _worker_id

    if _conn is not None and _worker_id is not None:
        return _conn, _worker_id

    ipc_info = parse_ipc_env()
    if ipc_info is None:
        raise RuntimeError("dog brute IPC is not configured")

    fd, worker_id = ipc_info
    _conn = Connection(fd)
    _worker_id = worker_id
    return _conn, _worker_id


def finish(reason: str = "finished") -> None:
    """Signal success to `dog brute`, or no-op with a notice outside it."""
    global _finish_sent

    if not os.environ.get(ENV_IPC):
        print("dog.finish() called outside dog brute, no-op", file=sys.stderr)
        return

    if _finish_sent:
        return

    conn, worker_id = _ensure_worker_connection()
    send_message(conn, MSG_WON, worker_id=worker_id, reason=str(reason))
    _finish_sent = True

    while True:
        msg = recv_message(conn)
        if msg.get("type") == MSG_GO_AHEAD:
            if _go_ahead_callback is not None:
                _go_ahead_callback()
            return


__all__ = ["brute_attempt", "brute_id", "brute_workers", "finish"]
