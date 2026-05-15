"""Curses drawing helpers for `dog brute`."""

import curses
import textwrap


DEFAULT_BAR_WIDTH = 20
MAX_BAR_WIDTH = 30
MIN_BAR_WIDTH = 8
MIN_MESSAGE_WIDTH = 24
STATUS_RUNNING = "running"
STATUS_INFO = "info"
STATUS_FAIL = "fail"
STATUS_TIMEOUT = "timeout"
STATUS_WON = "won"
STATUS_PAUSED = "paused"

PAIR_CYAN = 1
PAIR_RED = 2
PAIR_GREEN = 3
PAIR_DIM = 4
PAIR_SELECTED = 5
PAIR_BLUE = 6


def init_colors() -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    try:
        curses.use_default_colors()
    except curses.error:
        pass
    curses.init_pair(PAIR_CYAN, curses.COLOR_CYAN, -1)
    curses.init_pair(PAIR_RED, curses.COLOR_RED, -1)
    curses.init_pair(PAIR_GREEN, curses.COLOR_GREEN, -1)
    curses.init_pair(PAIR_DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(PAIR_SELECTED, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(PAIR_BLUE, curses.COLOR_BLUE, -1)


def draw(
    stdscr,
    title: str,
    rows: list[dict],
    stats: dict,
    overlay: str | None = None,
    overlay_title: str = "last failure",
    overlay_hint: str = "press any key to close",
    overlay_scroll: int = 0,
) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    if height <= 0 or width <= 0:
        return

    _addnstr(stdscr, 0, 0, title, width, curses.A_BOLD)

    box_top = 1
    box_bottom = max(box_top + 2, height - 3)
    if height >= 5 and width >= 4:
        _draw_box(stdscr, box_top, 0, box_bottom, width - 1)

    expected_logs = max(1, int(stats.get("expected_logs", DEFAULT_BAR_WIDTH)))
    visible_rows = rows[: max(0, box_bottom - box_top - 1)]
    max_log_count = max((int(row.get("log_count", 0)) for row in visible_rows), default=0)
    count_width = max(1, len(str(max_log_count)))

    usable_rows = max(0, box_bottom - box_top - 1)
    for idx, row in enumerate(rows[:usable_rows]):
        _draw_worker_row(
            stdscr,
            box_top + 1 + idx,
            2,
            width - 4,
            row,
            expected_logs,
            count_width,
        )

    footer = stats.get("footer", "")
    winner = stats.get("winner", "")
    if winner and height >= 3:
        _addnstr(stdscr, height - 2, 1, winner, max(0, width - 2), _color(PAIR_GREEN) | curses.A_BOLD | curses.A_REVERSE)
    if height >= 2:
        _addnstr(stdscr, height - 1, 1, footer, max(0, width - 2), _color(PAIR_DIM))

    if overlay is not None:
        _draw_overlay(stdscr, overlay, overlay_title, overlay_hint, overlay_scroll)

    stdscr.refresh()


def _draw_worker_row(
    stdscr,
    y: int,
    x: int,
    width: int,
    row: dict,
    expected_logs: int,
    count_width: int,
) -> None:
    worker = f"#{row['id']:<2}"
    log_count = int(row.get("log_count", 0))
    msg = str(row.get("message", ""))
    status = row.get("status", STATUS_RUNNING)

    attr = _status_attr(status)
    selected_attr = _color(PAIR_SELECTED) if row.get("selected") else attr
    bar_attr = (_color(PAIR_SELECTED) if row.get("selected") else _color(PAIR_CYAN))
    age = str(row.get("age", "0:00"))
    prefix = f"{worker}  {age:>5}  "
    bar_width = _bar_width(width, len(prefix), count_width)
    fill = _bar_fill(log_count, expected_logs, bar_width)
    bar = "█" * fill + "░" * (bar_width - fill)
    count = str(log_count).rjust(count_width)

    _addnstr(stdscr, y, x, prefix, width, selected_attr)
    _addnstr(stdscr, y, x + len(prefix), bar, max(0, width - len(prefix)), bar_attr)
    count_x = x + len(prefix) + bar_width + 2
    _addnstr(stdscr, y, count_x, count, max(0, width - (count_x - x)), selected_attr)
    msg_x = count_x + count_width + 2
    _addnstr(stdscr, y, msg_x, msg, max(0, width - (msg_x - x)), selected_attr)


def _bar_width(row_width: int, prefix_width: int, count_width: int) -> int:
    max_with_message = row_width - prefix_width - count_width - 4 - MIN_MESSAGE_WIDTH
    if max_with_message < MIN_BAR_WIDTH:
        max_with_message = row_width - prefix_width - count_width - 4
    return max(1, min(MAX_BAR_WIDTH, max_with_message))


def _bar_fill(log_count: int, expected_logs: int, bar_width: int) -> int:
    if log_count <= 0:
        return 0
    expected_logs = max(1, expected_logs)
    return min(bar_width, max(1, (log_count * bar_width + expected_logs - 1) // expected_logs))


def _draw_box(stdscr, top: int, left: int, bottom: int, right: int) -> None:
    if right <= left or bottom <= top:
        return

    _addnstr(stdscr, top, left, "┌" + "─" * (right - left - 1) + "┐", right - left + 1)
    for y in range(top + 1, bottom):
        _addnstr(stdscr, y, left, "│", 1)
        _addnstr(stdscr, y, right, "│", 1)
    _addnstr(stdscr, bottom, left, "└" + "─" * (right - left - 1) + "┘", right - left + 1)


def _draw_overlay(stdscr, text: str, title: str, hint: str, scroll: int = 0) -> None:
    height, width = stdscr.getmaxyx()
    overlay_h, overlay_w = _overlay_size(height, width)
    top = max(0, (height - overlay_h) // 2)
    left = max(0, (width - overlay_w) // 2)
    bottom = top + overlay_h - 1
    right = left + overlay_w - 1

    attr = curses.A_BOLD
    _draw_box(stdscr, top, left, bottom, right)
    _addnstr(stdscr, top, left + 2, f" {title} ", max(0, overlay_w - 4), attr)

    lines = _overlay_lines(text, overlay_w)
    body_h = max(0, overlay_h - 3)
    scroll = max(0, min(scroll, max(0, len(lines) - body_h)))
    for idx, line in enumerate(lines[scroll: scroll + body_h]):
        _addnstr(stdscr, top + 1 + idx, left + 2, line, max(0, overlay_w - 4))

    _addnstr(stdscr, bottom, max(left + 2, right - len(hint) - 1), hint, len(hint), _color(PAIR_DIM))


def overlay_scroll_limit(stdscr, text: str) -> int:
    height, width = stdscr.getmaxyx()
    overlay_h, overlay_w = _overlay_size(height, width)
    body_h = max(0, overlay_h - 3)
    return max(0, len(_overlay_lines(text, overlay_w)) - body_h)


def _overlay_size(height: int, width: int) -> tuple[int, int]:
    overlay_h = max(5, min(height - 2, height * 3 // 4))
    overlay_w = max(20, min(width - 4, width * 4 // 5))
    return overlay_h, overlay_w


def _overlay_lines(text: str, overlay_w: int) -> list[str]:
    lines: list[str] = []
    for line in text.splitlines() or ["No failures yet."]:
        wrapped = textwrap.wrap(line, width=max(1, overlay_w - 4)) or [""]
        lines.extend(wrapped)
    return lines


def _status_attr(status: str) -> int:
    if status == STATUS_FAIL:
        return _color(PAIR_RED)
    if status == STATUS_TIMEOUT:
        return _color(PAIR_RED) | curses.A_BOLD
    if status == STATUS_WON:
        return _color(PAIR_GREEN) | curses.A_BOLD
    if status == STATUS_INFO:
        return _color(PAIR_BLUE) | curses.A_BOLD
    if status == STATUS_PAUSED:
        return _color(PAIR_DIM)
    return 0


def _color(pair: int) -> int:
    if not curses.has_colors():
        return 0
    return curses.color_pair(pair)


def _addnstr(stdscr, y: int, x: int, text: str, n: int, attr: int = 0) -> None:
    if n <= 0:
        return
    try:
        stdscr.addnstr(y, x, text, n, attr)
    except curses.error:
        pass


__all__ = [
    "DEFAULT_BAR_WIDTH",
    "STATUS_FAIL",
    "STATUS_INFO",
    "STATUS_PAUSED",
    "STATUS_RUNNING",
    "STATUS_TIMEOUT",
    "STATUS_WON",
    "draw",
    "init_colors",
]
