import argparse
import os
import subprocess
import sys
import time
from multiprocessing import Pipe
from pathlib import Path

from doglib.brute import finish
from doglib.brute import _tui
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
from doglib.brute._orchestrator import BruteOrchestrator, WorkerSlot, _failure_summary, _format_age
from doglib.commandline import brute as brute_cli


def _build_parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    brute_cli.register(sub)
    return parser


def _src_path() -> str:
    return str(Path(__file__).parents[2] / "src")


def test_parser_keeps_script_args_without_separator():
    parser = _build_parser()
    args = parser.parse_args(["brute", "-n", "8", "--delay", "0.5", "solve.py", "1.2.3.4", "1337"])

    assert args.workers == 8
    assert args.delay == 0.5
    assert args.solve_path == "solve.py"
    assert args.script_args == ["1.2.3.4", "1337"]


def test_main_keeps_all_caps_script_args():
    code = """
import sys
import types

sys.argv = ["dog", "brute", "/tmp/solve.py", "ASDJIIJOASD"]

fake = types.ModuleType("doglib.brute._orchestrator")
def run(solve_path, script_args, workers, timeout, delay=0.0, debug=False, instant=False):
    print(repr(script_args))
    return 0
fake.run = run
sys.modules["doglib.brute._orchestrator"] = fake

from doglib.commandline.main import main
main()
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = _src_path() + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )

    assert result.stdout.strip() == "['ASDJIIJOASD']"


def test_finish_outside_brute_is_noop(monkeypatch, capsys):
    monkeypatch.delenv(ENV_IPC, raising=False)

    finish()

    captured = capsys.readouterr()
    assert "dog.finish() called outside dog brute, no-op" in captured.err


def test_worker_finish_blocks_until_go_ahead(tmp_path):
    marker = tmp_path / "after_finish"
    solve = tmp_path / "solve.py"
    solve.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "import dog\n"
        "dog.finish('got shell')\n"
        "Path(os.environ['MARKER']).write_text('continued')\n"
    )

    parent_conn, child_conn = Pipe(duplex=True)
    child_fd = child_conn.fileno()
    os.set_inheritable(child_fd, True)

    env = os.environ.copy()
    env[ENV_IPC] = f"{child_fd}:7"
    env["MARKER"] = str(marker)
    env["PYTHONPATH"] = _src_path() + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.Popen(
        [sys.executable, "-m", "doglib.brute._worker", str(solve)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        pass_fds=(child_fd,),
    )
    child_conn.close()

    try:
        assert parent_conn.poll(5)
        msg = recv_message(parent_conn)
        assert msg["type"] == MSG_WON
        assert msg["worker_id"] == 7
        assert msg["reason"] == "got shell"

        time.sleep(0.1)
        assert not marker.exists()

        send_message(parent_conn, MSG_GO_AHEAD)
        out, _ = proc.communicate(timeout=5)
        assert proc.returncode == 0, out.decode(errors="replace")
        assert marker.read_text() == "continued"
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        parent_conn.close()


def test_worker_matches_pwntools_all_caps_arg_parsing(tmp_path):
    marker = tmp_path / "argv"
    solve = tmp_path / "solve.py"
    solve.write_text(
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n"
        "from dog import *\n"
        "Path(os.environ['MARKER']).write_text(repr(sys.argv))\n"
        "finish()\n"
    )

    parent_conn, child_conn = Pipe(duplex=True)
    child_fd = child_conn.fileno()
    os.set_inheritable(child_fd, True)

    env = os.environ.copy()
    env[ENV_IPC] = f"{child_fd}:9"
    env["MARKER"] = str(marker)
    env["PYTHONPATH"] = _src_path() + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.Popen(
        [sys.executable, "-m", "doglib.brute._worker", str(solve), "ASDJIIJOASD"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        pass_fds=(child_fd,),
    )
    child_conn.close()

    try:
        assert parent_conn.poll(5)
        msg = recv_message(parent_conn)
        assert msg["type"] == MSG_WON
        assert marker.read_text() == f"[{str(solve)!r}]"
        send_message(parent_conn, MSG_GO_AHEAD)
        proc.wait(timeout=5)
        assert proc.returncode == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        parent_conn.close()


def test_worker_reports_traceback(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("raise RuntimeError('boom')\n")

    parent_conn, child_conn = Pipe(duplex=True)
    child_fd = child_conn.fileno()
    os.set_inheritable(child_fd, True)

    env = os.environ.copy()
    env[ENV_IPC] = f"{child_fd}:3"
    env["PYTHONPATH"] = _src_path() + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.Popen(
        [sys.executable, "-m", "doglib.brute._worker", str(solve)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        pass_fds=(child_fd,),
    )
    child_conn.close()

    try:
        assert parent_conn.poll(5)
        msg = recv_message(parent_conn)
        assert msg["type"] == "FAIL"
        assert "RuntimeError: boom" in msg["traceback"]
        proc.wait(timeout=5)
        assert proc.returncode != 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        parent_conn.close()


def test_worker_exposes_brute_vars(tmp_path):
    marker = tmp_path / "brute_vars"
    solve = tmp_path / "solve.py"
    solve.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "import dog\n"
        "Path(os.environ['MARKER']).write_text(f'{dog.brute_id}:{dog.brute_attempt}:{dog.brute_workers}')\n"
        "dog.finish()\n"
    )

    parent_conn, child_conn = Pipe(duplex=True)
    child_fd = child_conn.fileno()
    os.set_inheritable(child_fd, True)

    env = os.environ.copy()
    env[ENV_IPC] = f"{child_fd}:4"
    env[ENV_ATTEMPT] = "37"
    env[ENV_WORKER_ID] = "4"
    env[ENV_WORKERS] = "8"
    env["MARKER"] = str(marker)
    env["PYTHONPATH"] = _src_path() + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.Popen(
        [sys.executable, "-m", "doglib.brute._worker", str(solve)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        pass_fds=(child_fd,),
    )
    child_conn.close()

    try:
        assert parent_conn.poll(5)
        msg = recv_message(parent_conn)
        assert msg["type"] == MSG_WON
        assert marker.read_text() == "4:37:8"
        send_message(parent_conn, MSG_GO_AHEAD)
        proc.wait(timeout=5)
        assert proc.returncode == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        parent_conn.close()


def test_orchestrator_respawns_after_failed_attempt(tmp_path, monkeypatch):
    counter = tmp_path / "counter"
    solve = tmp_path / "solve.py"
    solve.write_text(
        "import os\n"
        "import sys\n"
        "import time\n"
        "from pathlib import Path\n"
        "counter = Path(os.environ['BRUTE_TEST_COUNTER'])\n"
        "attempt = int(counter.read_text()) if counter.exists() else 0\n"
        "counter.write_text(str(attempt + 1))\n"
        "if attempt == 0:\n"
        "    sys.exit(1)\n"
        "time.sleep(30)\n"
    )
    monkeypatch.setenv("BRUTE_TEST_COUNTER", str(counter))

    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    orch._ensure_target_workers()
    slot = next(iter(orch.slots.values()))
    first_pid = slot.proc.pid

    try:
        slot.proc.wait(timeout=5)
        orch._reap_workers()

        assert orch.total_attempts == 1
        assert slot.proc is not None
        assert slot.proc.pid != first_pid
        assert slot.proc.poll() is None
        assert slot.attempt == 2
    finally:
        orch._kill_all()


def test_delay_holds_failed_row_before_respawn(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5, delay=30)

    class ExitedProcess:
        stdout = None

        def poll(self):
            return 1

    slot = WorkerSlot(1, proc=ExitedProcess())
    orch.slots = {1: slot}
    spawned = []
    orch._spawn_slot = lambda slot: spawned.append(slot.id)

    orch._reap_workers()
    assert slot.proc is None
    assert slot.respawn_at > time.monotonic()

    orch._ensure_target_workers()
    orch._spawn_delayed_workers()
    assert spawned == []

    slot.respawn_at = time.monotonic() - 1
    orch._spawn_delayed_workers()
    assert spawned == [1]


def test_expected_logs_learns_from_completed_attempts(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)

    assert orch._expected_logs() == 20

    orch._record_attempt_log_count(3)
    assert orch._expected_logs() == 3

    orch._record_attempt_log_count(50)
    assert orch._expected_logs() == 50


def test_bar_fill_clamps_instead_of_wrapping():
    assert _tui._bar_fill(0, expected_logs=3, bar_width=10) == 0
    assert _tui._bar_fill(1, expected_logs=3, bar_width=10) == 4
    assert _tui._bar_fill(3, expected_logs=3, bar_width=10) == 10
    assert _tui._bar_fill(30, expected_logs=3, bar_width=10) == 10


def test_failure_summary_prefers_exception_line():
    text = (
        "Traceback (most recent call last):\n"
        '  File "/tmp/solve.py", line 3, in <module>\n'
        '    raise Exception("balls")\n'
        "Exception: balls\n"
    )
    assert _failure_summary(text) == "solve.py:3: Exception: balls"
    assert _failure_summary("script exited with status 1") == "script exited with status 1"
    assert _failure_summary("first line\nsecond line") == "first line"


def test_decrease_removes_selected_worker(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=3, timeout=5)
    orch.slots = {1: WorkerSlot(1), 2: WorkerSlot(2), 3: WorkerSlot(3)}
    orch.selected_id = 2

    orch._decrease_workers()

    assert orch.target_workers == 2
    assert sorted(orch.slots) == [1, 3]
    assert orch.selected_id == 1


def test_decrease_workers_ignores_empty_slots(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=2, timeout=5)
    orch.slots = {}

    orch._decrease_workers()

    assert orch.target_workers == 2


def test_footer_only_mentions_timeouts_after_one_occurs(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    orch.total_attempts = 48

    assert "total: 48" in orch._footer()
    assert "timeout" not in orch._footer()

    orch.timeout_attempts = 1
    assert "total: 48 (1 timeout)" in orch._footer()


def test_over_cap_footer_uses_constant(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    orch.over_cap_confirm_until = time.monotonic() + 1

    assert "press + again to exceed 64 workers" in orch._footer()


def test_footer_compact_and_help_modes(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)

    compact = orch._footer()
    assert "h=help" in compact
    assert "+/- add/remove" not in compact
    assert "up/down select" not in compact

    orch.show_help = True
    help_text = orch._footer()
    assert "[up/down/enter] monitor" in help_text
    assert "[h] hide" in help_text


def test_failure_overlay_uses_nonblocking_state(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)

    assert not orch.failure_overlay
    orch.failure_overlay = True
    assert orch.failure_overlay


def test_failure_overlay_hint_matches_monitor(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    orch.failure_overlay = True
    captured = {}

    def fake_draw(stdscr, title, rows, stats, overlay=None, overlay_title="last failure", overlay_hint="", overlay_scroll=0):
        captured["overlay_hint"] = overlay_hint

    old_draw = _tui.draw
    _tui.draw = fake_draw
    try:
        orch._draw(None)
    finally:
        _tui.draw = old_draw

    assert captured["overlay_hint"] == "up/down scroll, esc/q close"


def test_failure_overlay_uses_snapshot_text(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    orch.failure_overlay = True
    orch.failure_overlay_text = "old failure"
    orch.last_failure = "new failure"
    captured = {}

    def fake_draw(stdscr, title, rows, stats, overlay=None, overlay_title="last failure", overlay_hint="", overlay_scroll=0):
        captured["overlay"] = overlay

    old_draw = _tui.draw
    _tui.draw = fake_draw
    try:
        orch._draw(None)
    finally:
        _tui.draw = old_draw

    assert captured["overlay"] == "old failure"


def test_failure_overlay_passes_scroll_offset(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    orch.failure_overlay = True
    orch.failure_overlay_scroll = 3
    captured = {}

    def fake_draw(stdscr, title, rows, stats, overlay=None, overlay_title="last failure", overlay_hint="", overlay_scroll=0):
        captured["overlay_scroll"] = overlay_scroll

    old_draw = _tui.draw
    _tui.draw = fake_draw
    try:
        orch._draw(None)
    finally:
        _tui.draw = old_draw

    assert captured["overlay_scroll"] == 3


def test_failure_overlay_arrow_keys_scroll(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    orch.failure_overlay = True
    orch.failure_overlay_text = "\n".join(f"line {idx}" for idx in range(40))

    class FakeScreen:
        def __init__(self, keys):
            self.keys = list(keys)

        def getch(self):
            if not self.keys:
                return -1
            return self.keys.pop(0)

        def getmaxyx(self):
            return 20, 80

    orch._handle_keys(FakeScreen([_tui.curses.KEY_DOWN, _tui.curses.KEY_NPAGE, _tui.curses.KEY_UP]), time.monotonic())

    assert orch.failure_overlay_scroll == 10


def test_monitor_overlay_passes_scroll_offset(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    orch.monitor_id = 1
    orch.monitor_scroll = 4
    orch.slots = {1: WorkerSlot(1)}
    captured = {}

    def fake_draw(stdscr, title, rows, stats, overlay=None, overlay_title="last failure", overlay_hint="", overlay_scroll=0):
        captured["overlay_hint"] = overlay_hint
        captured["overlay_scroll"] = overlay_scroll

    old_draw = _tui.draw
    _tui.draw = fake_draw
    try:
        orch._draw(None)
    finally:
        _tui.draw = old_draw

    assert captured["overlay_hint"] == "up/down scroll, esc/q close"
    assert captured["overlay_scroll"] == 4


def test_monitor_overlay_arrow_keys_scroll(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    slot = WorkerSlot(1, captured=bytearray("\n".join(f"line {idx}" for idx in range(40)), "utf-8"))
    orch.slots = {1: slot}
    orch.monitor_id = 1

    class FakeScreen:
        def __init__(self, keys):
            self.keys = list(keys)

        def getch(self):
            if not self.keys:
                return -1
            return self.keys.pop(0)

        def getmaxyx(self):
            return 20, 80

    orch._handle_keys(FakeScreen([_tui.curses.KEY_DOWN, _tui.curses.KEY_NPAGE, _tui.curses.KEY_UP]), time.monotonic())

    assert orch.monitor_scroll == 10


def test_monitor_overlay_close_resets_scroll(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    orch.monitor_id = 1
    orch.monitor_scroll = 5
    orch.slots = {1: WorkerSlot(1)}

    class FakeScreen:
        def __init__(self):
            self.keys = [ord("q")]

        def getch(self):
            if not self.keys:
                return -1
            return self.keys.pop(0)

        def getmaxyx(self):
            return 20, 80

    orch._handle_keys(FakeScreen(), time.monotonic())

    assert orch.monitor_id is None
    assert orch.monitor_scroll == 0


def test_winner_notice_uses_finished_reason(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)
    orch.slots = {2: WorkerSlot(2, won=True, win_reason="got shell")}

    assert orch._winner_notice() == "WINNER #2: got shell  ·  press 'i' to enter"


def test_won_worker_is_not_timed_out(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=1, timeout=5)

    class RunningProcess:
        def poll(self):
            return None

    slot = WorkerSlot(1, proc=RunningProcess(), started_at=0.0, won=True)
    orch.slots = {1: slot}

    orch._check_timeouts()

    assert not slot.timed_out
    assert slot.status == _tui.STATUS_RUNNING


def test_parse_ipc_env_rejects_malformed_values():
    assert parse_ipc_env("") is None
    assert parse_ipc_env("not-a-pipe") is None
    assert parse_ipc_env("fd:worker") is None


def test_handoff_kills_losers_and_guards_dead_winner(tmp_path):
    solve = tmp_path / "solve.py"
    solve.write_text("pass\n")
    orch = BruteOrchestrator(str(solve), [], workers=2, timeout=5)

    class ExitedProcess:
        def poll(self):
            return 1

    winner = WorkerSlot(1, proc=ExitedProcess(), conn=object())
    loser = WorkerSlot(2)
    orch.slots = {1: winner, 2: loser}
    orch.winner = winner
    cleaned = []
    orch._cleanup_process = lambda slot: cleaned.append(slot)

    assert orch._handoff_winner(None) == 1
    assert cleaned == [winner]

    class RunningProcess:
        pid = 123456

        def poll(self):
            return None

    winner.proc = RunningProcess()
    orch.winner = winner
    cleaned.clear()
    killed_losers = []
    orch._kill_losers = lambda slot: killed_losers.append(slot)
    orch._shutdown_curses = lambda stdscr: None
    old_getpgid = os.getpgid
    os.getpgid = lambda pid: (_ for _ in ()).throw(ProcessLookupError())
    try:
        assert orch._handoff_winner(None) == 1
    finally:
        os.getpgid = old_getpgid
    assert killed_losers == [winner]
    assert cleaned == [winner]


def test_format_age_uses_minutes_seconds():
    assert _format_age(0) == "0:00"
    assert _format_age(7.9) == "0:07"
    assert _format_age(74) == "1:14"
