"""Worker bootstrap for `python -m doglib.brute._worker`."""

import logging
import os
import runpy
import sys
import traceback
from multiprocessing.connection import Connection

import doglib.brute as brute
from doglib.brute._ipc import (
    ENV_DEBUG,
    MSG_FAIL,
    MSG_LOG,
    parse_ipc_env,
    send_message,
)


class _PwnlibForwardHandler(logging.Handler):
    def __init__(self, conn: Connection, worker_id: int) -> None:
        super().__init__()
        self.conn = conn
        self.worker_id = worker_id

    def emit(self, record: logging.LogRecord) -> None:
        try:
            send_message(
                self.conn,
                MSG_LOG,
                worker_id=self.worker_id,
                level=record.levelno,
                levelname=record.levelname,
                msg=record.getMessage(),
                pwnlib_msgtype=getattr(record, "pwnlib_msgtype", None),
            )
        except Exception:
            self.handleError(record)


def _open_devnull_stdin() -> None:
    fd = os.open(os.devnull, os.O_RDONLY)
    try:
        os.dup2(fd, 0)
    finally:
        if fd > 2:
            os.close(fd)


def _reopen_tty_stdio() -> None:
    try:
        tty = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        return

    try:
        os.dup2(tty, 0)
        os.dup2(tty, 1)
        os.dup2(tty, 2)
    finally:
        if tty > 2:
            os.close(tty)


def _restore_pwnlib_terminal() -> None:
    try:
        from pwnlib import term
        from pwnlib.term import text
    except Exception:
        return

    try:
        text.when = "auto"
    except Exception:
        pass

    try:
        term.init()
    except Exception:
        pass


def _configure_pwnlib_logging(conn: Connection, worker_id: int, debug: bool):
    if debug:
        try:
            from pwnlib.context import context
            context.defaults['log_level'] = logging.DEBUG
        except Exception:
            pass

    logger = logging.getLogger("pwnlib")
    handler = _PwnlibForwardHandler(conn, worker_id)
    handler.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    return logger, handler


def _system_exit_code(code) -> int:
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    return 1


def _send_failure(conn: Connection, worker_id: int, text: str) -> None:
    send_message(conn, MSG_FAIL, worker_id=worker_id, traceback=text)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        print("usage: python -m doglib.brute._worker <solve.py> [args...]", file=sys.stderr)
        return 2

    ipc_info = parse_ipc_env()
    if ipc_info is None:
        print("dog brute worker started without IPC", file=sys.stderr)
        return 2

    fd, worker_id = ipc_info
    conn = Connection(fd)
    brute._set_worker_connection(conn, worker_id)

    debug = os.environ.get(ENV_DEBUG) == "1"
    logger, handler = _configure_pwnlib_logging(conn, worker_id, debug)

    def go_ahead() -> None:
        logger.removeHandler(handler)
        _reopen_tty_stdio()
        _restore_pwnlib_terminal()

    brute._set_go_ahead_callback(go_ahead)

    solve_path = argv[0]
    script_args = argv[1:]
    sys.argv = [solve_path, *script_args]
    _open_devnull_stdin()

    try:
        runpy.run_path(solve_path, run_name="__main__")
    except SystemExit as exc:
        if brute._finish_called():
            return _system_exit_code(exc.code)

        code = _system_exit_code(exc.code)
        if code == 0:
            _send_failure(conn, worker_id, "script finished without dog.finish()")
            return 1

        _send_failure(conn, worker_id, f"script exited with status {code}")
        return code
    except BaseException:
        if brute._finish_called():
            raise

        _send_failure(conn, worker_id, traceback.format_exc())
        return 1
    finally:
        if not brute._finish_called():
            logger.removeHandler(handler)
            brute._set_go_ahead_callback(None)

    if not brute._finish_called():
        _send_failure(conn, worker_id, "script finished without dog.finish()")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
