"""Parent orchestrator for the `dog brute` CLI."""

import curses
import logging
import os
import selectors
import signal
import subprocess
import sys
import time
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from multiprocessing import Pipe
from multiprocessing.connection import Connection

from doglib.brute import _tui
from doglib.brute._ipc import (
    ENV_ATTEMPT,
    ENV_IPC,
    ENV_WORKER_ID,
    ENV_WORKERS,
    MSG_FAIL,
    MSG_GO_AHEAD,
    MSG_LOG,
    MSG_WON,
    recv_message,
    send_message,
)


CAPTURE_LIMIT = 128 * 1024
RATE_WINDOW = 5.0
TIMEOUT_NOTICE_SECONDS = 2.0
SOFT_WORKER_CAP = 64
DEFAULT_EXPECTED_LOGS = 20
LOG_COUNT_HISTORY = 128


@dataclass
class WorkerSlot:
    id: int
    proc: subprocess.Popen | None = None
    conn: Connection | None = None
    stdout_fd: int | None = None
    attempt: int = 0
    started_at: float = 0.0
    log_count: int = 0
    message: str = "starting"
    status: str = _tui.STATUS_RUNNING
    won: bool = False
    win_reason: str = ""
    timed_out: bool = False
    timeout_kill_at: float = 0.0
    respawn_at: float = 0.0
    captured: bytearray = field(default_factory=bytearray)
    fail_text: str | None = None


class BruteOrchestrator:
    def __init__(
        self,
        solve_path: str,
        script_args: Sequence[str],
        workers: int,
        timeout: float,
        delay: float = 0.0,
        instant: bool = False,
    ) -> None:
        self.solve_path = os.path.abspath(solve_path)
        self.script_args = list(script_args)
        self.target_workers = max(1, workers)
        self.timeout = timeout
        self.delay = max(0.0, delay)
        self.instant = instant

        self.selector = selectors.DefaultSelector()
        self.slots: dict[int, WorkerSlot] = {}
        self.selected_id: int | None = None
        self.monitor_id: int | None = None
        self.monitor_scroll = 0
        self.failure_overlay = False
        self.paused = False
        self.total_attempts = 0
        self.next_attempt = 1
        self.timeout_attempts = 0
        self.attempt_times: deque[float] = deque()
        self.attempt_log_counts: deque[int] = deque(maxlen=LOG_COUNT_HISTORY)
        self.last_failure = "No failures yet."
        self.failure_overlay_text = ""
        self.failure_overlay_scroll = 0
        self.start_time = time.monotonic()
        self.winner: WorkerSlot | None = None
        self._handoff_requested = False
        self.show_help = False
        self.quit_confirm_until = 0.0
        self.over_cap_confirm_until = 0.0
        self.dirty = True
        self._last_draw = 0.0
        self._curses_shutdown = False

    def run(self) -> int:
        if not os.path.isfile(self.solve_path):
            print(f"error: solve script not found: {self.solve_path}", file=sys.stderr)
            return 2

        stdscr = curses.initscr()
        try:
            curses.noecho()
            curses.cbreak()
            _set_escdelay()
            stdscr.keypad(True)
            stdscr.nodelay(True)
            _tui.init_colors()

            self._ensure_target_workers()
            code = self._loop(stdscr)
            return code
        except KeyboardInterrupt:
            self._kill_all()
            return 130
        except Exception:
            self._kill_all()
            raise
        finally:
            self._kill_all()
            self._shutdown_curses(stdscr)

    def _loop(self, stdscr) -> int:
        while True:
            now = time.monotonic()
            self._handle_keys(stdscr, now)
            if self._handoff_requested:
                code = self._handoff_winner(stdscr)
                if code is None:
                    self._handoff_requested = False
                    continue
                return code

            self._handle_events()
            if self._handoff_requested:
                code = self._handoff_winner(stdscr)
                if code is None:
                    self._handoff_requested = False
                    continue
                return code

            self._check_timeouts()
            self._reap_workers()
            self._spawn_delayed_workers()
            if not self.paused:
                self._ensure_target_workers()

            if self.dirty or now - self._last_draw > 0.25:
                self._draw(stdscr)
                self._last_draw = now
                self.dirty = False

            time.sleep(0.03)

    def _spawn_slot(self, slot: WorkerSlot) -> None:
        parent_conn, child_conn = Pipe(duplex=True)
        child_fd = child_conn.fileno()
        os.set_inheritable(child_fd, True)

        env = os.environ.copy()
        env[ENV_IPC] = f"{child_fd}:{slot.id}"
        env[ENV_ATTEMPT] = str(self.next_attempt)
        env[ENV_WORKER_ID] = str(slot.id)
        env[ENV_WORKERS] = str(self.target_workers)
        env["PYTHONUNBUFFERED"] = "1"

        cmd = [
            sys.executable,
            "-m",
            "doglib.brute._worker",
            self.solve_path,
            *self.script_args,
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            pass_fds=(child_fd,),
            preexec_fn=os.setpgrp,
        )
        child_conn.close()

        slot.proc = proc
        slot.conn = parent_conn
        slot.stdout_fd = proc.stdout.fileno() if proc.stdout is not None else None
        slot.attempt = self.next_attempt
        self.next_attempt += 1
        slot.started_at = time.monotonic()
        slot.log_count = 0
        slot.message = "starting"
        slot.status = _tui.STATUS_RUNNING
        slot.won = False
        slot.win_reason = ""
        slot.timed_out = False
        slot.timeout_kill_at = 0.0
        slot.respawn_at = 0.0
        slot.captured.clear()
        slot.fail_text = None

        self.selector.register(parent_conn.fileno(), selectors.EVENT_READ, (slot.id, "ipc"))
        if slot.stdout_fd is not None:
            os.set_blocking(slot.stdout_fd, False)
            self.selector.register(slot.stdout_fd, selectors.EVENT_READ, (slot.id, "stdout"))
        self.dirty = True

    def _ensure_target_workers(self) -> None:
        while len(self.slots) < self.target_workers:
            slot = WorkerSlot(self._next_slot_id())
            self.slots[slot.id] = slot

        for slot in self.slots.values():
            if slot.proc is None and not slot.respawn_at and not self.paused:
                self._spawn_slot(slot)
        self._ensure_selection()

    def _next_slot_id(self) -> int:
        slot_id = 1
        while slot_id in self.slots:
            slot_id += 1
        return slot_id

    def _handle_events(self) -> None:
        for key, _ in self.selector.select(timeout=0):
            slot_id, kind = key.data
            slot = self.slots.get(slot_id)
            if slot is None:
                continue

            if kind == "ipc":
                self._handle_ipc(slot)
            elif kind == "stdout":
                self._handle_stdout(slot)

    def _handle_ipc(self, slot: WorkerSlot) -> bool:
        if slot.conn is None:
            return False

        try:
            msg = recv_message(slot.conn)
        except (EOFError, OSError):
            self._close_conn(slot)
            return False

        kind = msg.get("type")
        if kind == MSG_LOG:
            level = int(msg.get("level", 0))
            msgtype = msg.get("pwnlib_msgtype")
            slot.log_count += 1
            slot.message = str(msg.get("msg", "")).replace("\n", " ")
            slot.status = _status_for_log(level, msgtype)
            self.dirty = True
        elif kind == MSG_FAIL:
            text = str(msg.get("traceback", "worker failed"))
            slot.fail_text = text
            slot.message = _failure_summary(text)
            slot.status = _tui.STATUS_FAIL
            self.last_failure = self._failure_text(slot, text)
            self.dirty = True
        elif kind == MSG_WON:
            reason = str(msg.get("reason") or "finished")
            slot.message = reason
            slot.status = _tui.STATUS_WON
            slot.won = True
            slot.win_reason = reason
            self.winner = slot
            if self.instant:
                self._handoff_requested = True
            self.dirty = True
        return True

    def _handle_stdout(self, slot: WorkerSlot) -> bool:
        if slot.stdout_fd is None:
            return False
        try:
            data = os.read(slot.stdout_fd, 4096)
        except BlockingIOError:
            return False
        except OSError:
            self._close_stdout(slot)
            return False

        if not data:
            self._close_stdout(slot)
            return False

        slot.captured.extend(data)
        if len(slot.captured) > CAPTURE_LIMIT:
            del slot.captured[: len(slot.captured) - CAPTURE_LIMIT]
        return True

    def _check_timeouts(self) -> None:
        now = time.monotonic()
        for slot in self.slots.values():
            if slot.proc is None or slot.proc.poll() is not None:
                continue
            if slot.won:
                continue
            if slot.timed_out:
                if now >= slot.timeout_kill_at:
                    self._kill_slot(slot)
                continue
            if now - slot.started_at >= self.timeout:
                slot.timed_out = True
                slot.timeout_kill_at = now + TIMEOUT_NOTICE_SECONDS
                slot.message = f"script took longer than {self.timeout:g}s, restarting"
                slot.status = _tui.STATUS_TIMEOUT
                self.last_failure = self._failure_text(slot, slot.message)
                self.dirty = True

    def _reap_workers(self) -> None:
        for slot in list(self.slots.values()):
            if slot.proc is None:
                continue
            code = slot.proc.poll()
            if code is None:
                continue
            if self.winner is slot:
                continue

            self._drain_ipc(slot)
            self._drain_stdout(slot)
            if self.winner is slot:
                continue

            self._record_attempt()
            self._record_attempt_log_count(slot.log_count)
            if slot.timed_out:
                self.timeout_attempts += 1
            if slot.fail_text is None:
                if slot.timed_out:
                    slot.fail_text = slot.message
                else:
                    slot.fail_text = f"worker exited with status {code}"
                    slot.message = slot.fail_text
                    slot.status = _tui.STATUS_FAIL
                self.last_failure = self._failure_text(slot, slot.fail_text)

            self._cleanup_process(slot)
            if self.paused:
                slot.message = "paused"
                slot.status = _tui.STATUS_PAUSED
            elif self.delay:
                slot.respawn_at = time.monotonic() + self.delay
            else:
                self._spawn_slot(slot)
            self.dirty = True

    def _spawn_delayed_workers(self) -> None:
        now = time.monotonic()
        for slot in self.slots.values():
            if slot.proc is None and slot.respawn_at and now >= slot.respawn_at and not self.paused:
                self._spawn_slot(slot)

    def _drain_ipc(self, slot: WorkerSlot) -> None:
        while slot.conn is not None:
            try:
                if not slot.conn.poll():
                    return
            except (EOFError, OSError):
                self._close_conn(slot)
                return
            if not self._handle_ipc(slot):
                return

    def _drain_stdout(self, slot: WorkerSlot) -> None:
        while slot.stdout_fd is not None:
            if not self._handle_stdout(slot):
                return

    def _record_attempt(self) -> None:
        now = time.monotonic()
        self.total_attempts += 1
        self.attempt_times.append(now)
        while self.attempt_times and now - self.attempt_times[0] > RATE_WINDOW:
            self.attempt_times.popleft()

    def _record_attempt_log_count(self, log_count: int) -> None:
        self.attempt_log_counts.append(log_count)

    def _expected_logs(self) -> int:
        if not self.attempt_log_counts:
            return DEFAULT_EXPECTED_LOGS
        return max(1, max(self.attempt_log_counts))

    def _handle_keys(self, stdscr, now: float) -> None:
        while True:
            ch = stdscr.getch()
            if ch == -1:
                return

            if self.failure_overlay:
                if ch in (27, ord("q")):
                    self.failure_overlay = False
                    self.failure_overlay_text = ""
                    self.failure_overlay_scroll = 0
                    self.dirty = True
                elif ch == curses.KEY_UP:
                    self._scroll_failure_overlay(stdscr, -1)
                elif ch == curses.KEY_DOWN:
                    self._scroll_failure_overlay(stdscr, 1)
                elif ch == curses.KEY_PPAGE:
                    self._scroll_failure_overlay(stdscr, -10)
                elif ch == curses.KEY_NPAGE:
                    self._scroll_failure_overlay(stdscr, 10)
                elif ch == curses.KEY_HOME:
                    self.failure_overlay_scroll = 0
                    self.dirty = True
                elif ch == curses.KEY_END:
                    self.failure_overlay_scroll = _tui.overlay_scroll_limit(stdscr, self.failure_overlay_text)
                    self.dirty = True
                elif ch == curses.KEY_RESIZE:
                    self._scroll_failure_overlay(stdscr, 0)
                    self.dirty = True
                continue

            if self.monitor_id is not None:
                slot = self.slots.get(self.monitor_id)
                if ch in (27, ord("q")):
                    self.monitor_id = None
                    self.monitor_scroll = 0
                    self.dirty = True
                elif ch in (ord("i"), ord("I")):
                    self._request_first_winner()
                elif ch in (10, 13, curses.KEY_ENTER) and slot is not None and slot.won:
                    self._request_handoff(slot)
                elif ch == curses.KEY_UP and slot is not None:
                    self._scroll_monitor(stdscr, slot, -1)
                elif ch == curses.KEY_DOWN and slot is not None:
                    self._scroll_monitor(stdscr, slot, 1)
                elif ch == curses.KEY_PPAGE and slot is not None:
                    self._scroll_monitor(stdscr, slot, -10)
                elif ch == curses.KEY_NPAGE and slot is not None:
                    self._scroll_monitor(stdscr, slot, 10)
                elif ch == curses.KEY_HOME:
                    self.monitor_scroll = 0
                    self.dirty = True
                elif ch == curses.KEY_END and slot is not None:
                    self.monitor_scroll = _tui.overlay_scroll_limit(stdscr, self._monitor_text(slot))
                    self.dirty = True
                elif ch == curses.KEY_RESIZE:
                    if slot is not None:
                        self._scroll_monitor(stdscr, slot, 0)
                    self.dirty = True
                continue

            if ch == curses.KEY_UP:
                self._select_delta(-1)
            elif ch == curses.KEY_DOWN:
                self._select_delta(1)
            elif ch in (10, 13, curses.KEY_ENTER):
                slot = self._selected_slot()
                if slot is None:
                    continue
                if slot.won:
                    self._request_handoff(slot)
                else:
                    self.monitor_id = slot.id
                    self.monitor_scroll = 0
                    self.dirty = True
            elif ch in (ord("r"), ord("R")):
                self._restart_selected()
            elif ch in (ord("+"), ord("=")):
                self._increase_workers(now)
            elif ch in (ord("-"), ord("_")):
                self._decrease_workers()
            elif ch == ord(" "):
                self.paused = not self.paused
                if not self.paused:
                    self._ensure_target_workers()
                self.dirty = True
            elif ch == ord("f"):
                self.failure_overlay_text = self.last_failure
                self.failure_overlay = True
                self.failure_overlay_scroll = 0
                self.dirty = True
            elif ch in (ord("h"), ord("H")):
                self.show_help = not self.show_help
                self.dirty = True
            elif ch in (ord("i"), ord("I")):
                self._request_first_winner()
            elif ch == ord("q"):
                if now <= self.quit_confirm_until:
                    self._kill_all()
                    self._shutdown_curses(stdscr)
                    raise SystemExit(130)
                self.quit_confirm_until = now + 3.0
                self.dirty = True
            elif ch == curses.KEY_RESIZE:
                self.dirty = True

    def _increase_workers(self, now: float) -> None:
        if self.target_workers >= SOFT_WORKER_CAP and now > self.over_cap_confirm_until:
            self.over_cap_confirm_until = now + 3.0
            self.dirty = True
            return
        self.target_workers += 1
        self._ensure_target_workers()
        self.dirty = True

    def _decrease_workers(self) -> None:
        if self.target_workers <= 1:
            return
        if not self.slots:
            return
        self.target_workers -= 1
        slot = self._selected_slot()
        if slot is None:
            slot = self.slots[max(self.slots)]
        if self.winner is slot:
            self.winner = None
            self._handoff_requested = False
        self.slots.pop(slot.id, None)
        self._kill_slot(slot)
        if slot.proc is not None:
            try:
                slot.proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        self._cleanup_process(slot)
        self._ensure_selection()
        self.dirty = True

    def _restart_selected(self) -> None:
        slot = self._selected_slot()
        if slot is None:
            return
        if self.winner is slot:
            self.winner = None
            self._handoff_requested = False
        self._kill_slot(slot)
        if slot.proc is not None:
            try:
                slot.proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        self._cleanup_process(slot)
        slot.won = False
        slot.win_reason = ""
        slot.respawn_at = 0.0
        if self.paused:
            slot.message = "paused"
            slot.status = _tui.STATUS_PAUSED
        else:
            self._spawn_slot(slot)
        self.dirty = True

    def _request_handoff(self, slot: WorkerSlot) -> None:
        self.winner = slot
        self.monitor_id = None
        self._handoff_requested = True
        self.dirty = True

    def _request_first_winner(self) -> None:
        won = [slot for slot in self.slots.values() if slot.won]
        if not won:
            return
        self._request_handoff(sorted(won, key=lambda s: s.id)[0])

    def _sorted_ids(self) -> list[int]:
        return sorted(self.slots)

    def _ensure_selection(self) -> None:
        ids = self._sorted_ids()
        if not ids:
            self.selected_id = None
        elif self.selected_id not in self.slots:
            self.selected_id = ids[0]

    def _selected_slot(self) -> WorkerSlot | None:
        self._ensure_selection()
        if self.selected_id is None:
            return None
        return self.slots.get(self.selected_id)

    def _select_delta(self, delta: int) -> None:
        ids = self._sorted_ids()
        if not ids:
            self.selected_id = None
            return
        self._ensure_selection()
        idx = ids.index(self.selected_id) if self.selected_id in ids else 0
        self.selected_id = ids[(idx + delta) % len(ids)]
        self.dirty = True

    def _draw(self, stdscr, overlay: str | None = None, overlay_hint: str = "press any key to close") -> None:
        now = time.monotonic()
        title = (
            f"dog brute  {os.path.basename(self.solve_path)}  -  "
            f"{self.target_workers} workers  -  elapsed {_format_elapsed(now - self.start_time)}"
        )
        self._ensure_selection()
        rows = [
            {
                "id": slot.id,
                "age": _format_age(now - slot.started_at) if slot.proc is not None else "0:00",
                "log_count": slot.log_count,
                "message": slot.message,
                "selected": slot.id == self.selected_id,
                "status": slot.status,
            }
            for slot in sorted(self.slots.values(), key=lambda s: s.id)
        ]
        overlay_title = "last failure"
        if overlay is None and self.monitor_id is not None:
            slot = self.slots.get(self.monitor_id)
            if slot is not None:
                overlay = self._monitor_text(slot)
                overlay_title = self._monitor_title(slot)
                overlay_hint = "up/down scroll, esc/q close"
                if slot.won:
                    overlay_hint = "enter interactive, up/down scroll, esc/q close"
        elif overlay is None and self.failure_overlay:
            overlay = self.failure_overlay_text
            overlay_title = "last failure"
            overlay_hint = "up/down scroll, esc/q close"
        _tui.draw(
            stdscr,
            title,
            rows,
            {
                "expected_logs": self._expected_logs(),
                "footer": self._footer(),
                "winner": self._winner_notice(),
            },
            overlay=overlay,
            overlay_title=overlay_title,
            overlay_hint=overlay_hint,
            overlay_scroll=self._overlay_scroll(),
        )

    def _overlay_scroll(self) -> int:
        if self.failure_overlay:
            return self.failure_overlay_scroll
        if self.monitor_id is not None:
            return self.monitor_scroll
        return 0

    def _scroll_failure_overlay(self, stdscr, delta: int) -> None:
        max_scroll = _tui.overlay_scroll_limit(stdscr, self.failure_overlay_text)
        self.failure_overlay_scroll = max(0, min(max_scroll, self.failure_overlay_scroll + delta))
        self.dirty = True

    def _scroll_monitor(self, stdscr, slot: WorkerSlot, delta: int) -> None:
        max_scroll = _tui.overlay_scroll_limit(stdscr, self._monitor_text(slot))
        self.monitor_scroll = max(0, min(max_scroll, self.monitor_scroll + delta))
        self.dirty = True

    def _footer(self) -> str:
        now = time.monotonic()
        while self.attempt_times and now - self.attempt_times[0] > RATE_WINDOW:
            self.attempt_times.popleft()
        rate = len(self.attempt_times) / RATE_WINDOW
        total = f"total: {self.total_attempts}"
        if self.timeout_attempts:
            label = "timeout" if self.timeout_attempts == 1 else "timeouts"
            total += f" ({self.timeout_attempts} {label})"
        if self.show_help:
            parts = [
                "[up/down/enter] monitor",
                "[r] restart",
                "[+/-] add/remove",
                "[space] stop/start",
                "[f] last failure",
                "[q] quit",
                "[h] hide",
            ]
        else:
            parts = [
                f"{rate:.1f} iter/s",
                total,
                "h=help",
                "q=quit",
            ]
        if now <= self.quit_confirm_until:
            parts.append("press q again to quit")
        if now <= self.over_cap_confirm_until:
            parts.append(f"press + again to exceed {SOFT_WORKER_CAP} workers")
        return "  ·  ".join(parts)

    def _winner_notice(self) -> str:
        won = [slot for slot in self.slots.values() if slot.won]
        if not won:
            return ""
        slot = sorted(won, key=lambda s: s.id)[0]
        return f"WINNER #{slot.id}: {slot.win_reason or 'finished'}  ·  press 'i' to enter"

    def _monitor_title(self, slot: WorkerSlot) -> str:
        return f"worker #{slot.id} output"

    def _monitor_text(self, slot: WorkerSlot) -> str:
        text = bytes(slot.captured).decode(errors="replace")
        if not text:
            text = "No output yet."
        if slot.won:
            text += f"\n\n[dog brute] worker #{slot.id} finished: {slot.win_reason or 'finished'}"
            text += "\n[dog brute] press Enter to hand off, Esc/q to keep watching."
        return text

    def _handoff_winner(self, stdscr) -> int | None:
        winner = self.winner
        if winner is None or winner.proc is None or winner.conn is None:
            return 1
        if winner.proc.poll() is not None:
            self._cleanup_process(winner)
            self.winner = None
            return 1

        self._kill_losers(winner)
        self._shutdown_curses(stdscr)
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

        parent_pgid = os.getpgrp()
        try:
            winner_pgid = os.getpgid(winner.proc.pid)
        except ProcessLookupError:
            self._cleanup_process(winner)
            self.winner = None
            return 1
        tty_fd = _open_tty_fd()
        if tty_fd is not None:
            _tcsetpgrp(tty_fd, winner_pgid)

        send_message(winner.conn, MSG_GO_AHEAD)
        try:
            code = winner.proc.wait()
        finally:
            if tty_fd is not None:
                _tcsetpgrp(tty_fd, parent_pgid)
                os.close(tty_fd)

        self._cleanup_process(winner)
        return code

    def _kill_losers(self, winner: WorkerSlot) -> None:
        for slot_id, slot in list(self.slots.items()):
            if slot is winner:
                continue
            self._kill_slot(slot)
            self._cleanup_process(slot)
            self.slots.pop(slot_id, None)

    def _kill_all(self) -> None:
        for slot in list(self.slots.values()):
            self._kill_slot(slot)
        for slot in list(self.slots.values()):
            self._cleanup_process(slot)

    def _kill_slot(self, slot: WorkerSlot) -> None:
        if slot.proc is None or slot.proc.poll() is not None:
            return
        try:
            os.killpg(slot.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _cleanup_process(self, slot: WorkerSlot) -> None:
        proc = slot.proc
        self._close_conn(slot)
        self._close_stdout(slot)
        if proc is not None and proc.poll() is None:
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        if proc is not None and proc.stdout is not None:
            proc.stdout.close()
        slot.proc = None

    def _close_conn(self, slot: WorkerSlot) -> None:
        if slot.conn is None:
            return
        self._safe_unregister(slot.conn.fileno())
        slot.conn.close()
        slot.conn = None

    def _close_stdout(self, slot: WorkerSlot) -> None:
        if slot.stdout_fd is None:
            return
        self._safe_unregister(slot.stdout_fd)
        slot.stdout_fd = None

    def _safe_unregister(self, fd: int) -> None:
        try:
            self.selector.unregister(fd)
        except Exception:
            pass

    def _shutdown_curses(self, stdscr) -> None:
        if self._curses_shutdown:
            return
        self._curses_shutdown = True
        try:
            curses.nocbreak()
        except curses.error:
            pass
        try:
            stdscr.keypad(False)
        except curses.error:
            pass
        try:
            curses.echo()
        except curses.error:
            pass
        try:
            curses.endwin()
        except curses.error:
            pass

    def _failure_text(self, slot: WorkerSlot, text: str) -> str:
        captured = bytes(slot.captured).decode(errors="replace").strip()
        header = f"worker #{slot.id}: {text}"
        if not captured:
            return header
        return f"{header}\n\n--- captured stdout/stderr ---\n{captured}"


def run(
    solve_path: str,
    script_args: Sequence[str],
    workers: int,
    timeout: float,
    delay: float = 0.0,
    instant: bool = False,
) -> int:
    return BruteOrchestrator(solve_path, script_args, workers, timeout, delay, instant).run()


def _status_for_log(level: int, msgtype: str | None) -> str:
    if level >= logging.ERROR:
        return _tui.STATUS_FAIL
    if msgtype in ("info", "info_once"):
        return _tui.STATUS_INFO
    return _tui.STATUS_RUNNING


def _failure_summary(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return text.replace("\n", " ")
    if lines[0] == "Traceback (most recent call last):" and len(lines) > 1:
        location = _traceback_location(lines)
        if location is not None:
            return f"{location}: {lines[-1]}"
        return lines[-1]
    return lines[0]


def _traceback_location(lines: list[str]) -> str | None:
    for line in reversed(lines):
        if not line.startswith("File "):
            continue
        parts = line.split('"')
        if len(parts) < 3:
            continue
        path = os.path.basename(parts[1])
        marker = ", line "
        if marker not in line:
            return path
        line_no = line.split(marker, 1)[1].split(",", 1)[0]
        return f"{path}:{line_no}"
    return None


def _format_elapsed(seconds: float) -> str:
    seconds_i = int(seconds)
    minutes, seconds_i = divmod(seconds_i, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds_i:02d}"
    return f"{minutes:02d}:{seconds_i:02d}"


def _format_age(seconds: float) -> str:
    seconds_i = max(0, int(seconds))
    minutes, seconds_i = divmod(seconds_i, 60)
    return f"{minutes}:{seconds_i:02d}"


def _set_escdelay() -> None:
    try:
        curses.set_escdelay(25)
    except (AttributeError, curses.error):
        pass


def _open_tty_fd() -> int | None:
    try:
        return os.open("/dev/tty", os.O_RDWR)
    except OSError:
        return None


def _tcsetpgrp(fd: int, pgid: int) -> None:
    old_ttou = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    try:
        os.tcsetpgrp(fd, pgid)
    except OSError:
        pass
    finally:
        signal.signal(signal.SIGTTOU, old_ttou)


__all__ = ["BruteOrchestrator", "run"]
