import argparse
import ipaddress
import logging
import win32evtlog
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Generator

# ── Configuration ─────────────────────────────────────────────────────────────
LOG_NAME        = "Security"
FAILED_LOGIN_ID = 4625
SOURCE_IP_FIELD = 19

DEFAULT_THRESHOLD  = 5
DEFAULT_WINDOW_MIN = 10

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


# ── Event reader ──────────────────────────────────────────────────────────────
def read_security_events(server: str = "localhost") -> Generator:
    handle = win32evtlog.OpenEventLog(server, LOG_NAME)
    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )
    try:
        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            yield from events
    finally:
        win32evtlog.CloseEventLog(handle)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_source_ip(inserts: list[str]) -> str:
    if inserts and len(inserts) > SOURCE_IP_FIELD:
        candidate = inserts[SOURCE_IP_FIELD].strip()
        if _is_valid_ip(candidate):
            return candidate
    for field in reversed(inserts):
        if field and _is_valid_ip(field.strip()):
            return field.strip()
    return "Unknown"


def parse_event(event) -> tuple[str, datetime] | None:
    if (event.EventID & 0xFFFF) != FAILED_LOGIN_ID:
        return None
    inserts = event.StringInserts or []
    return extract_source_ip(inserts), event.TimeGenerated


def resolve_range(
    start: datetime | None,
    end: datetime | None,
    window_minutes: int,
) -> tuple[datetime, datetime]:
    """
    Resolve the effective (start, end) window.

    Rules:
      - Both provided      → use as-is
      - Only end provided  → start = end - window
      - Only start         → end   = start + window
      - Neither provided   → end = now, start = now - window
    """
    now = datetime.now()
    if start and end:
        if start >= end:
            raise ValueError("--start must be earlier than --end")
        return start, end
    if end and not start:
        return end - timedelta(minutes=window_minutes), end
    if start and not end:
        return start, start + timedelta(minutes=window_minutes)
    # default: rolling window ending now
    return now - timedelta(minutes=window_minutes), now


# ── Detection ─────────────────────────────────────────────────────────────────
def detect(
    server: str = "localhost",
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MIN,
    start: datetime | None = None,
    end: datetime | None = None,
) -> None:
    range_start, range_end = resolve_range(start, end, window_minutes)

    print(
        f"Scanning  {range_start.strftime('%Y-%m-%d %H:%M:%S')}  →  "
        f"{range_end.strftime('%Y-%m-%d %H:%M:%S')}\n"
    )

    failed_by_ip: dict[str, list[datetime]] = defaultdict(list)

    for event in read_security_events(server):
        parsed = parse_event(event)
        if parsed is None:
            continue

        source_ip, ts = parsed

        # Since events are newest-first, stop once we're past the start of the range
        if ts < range_start:
            break

        if ts <= range_end:
            failed_by_ip[source_ip].append(ts)

    suspicious = {
        ip: times
        for ip, times in failed_by_ip.items()
        if len(times) >= threshold
    }

    if not suspicious:
        print("No suspicious IPs found.")
        return

    print(
        f"Suspicious IPs — ≥{threshold} failed logins in window:\n"
        f"{'IP':<22} {'Attempts':>8}   {'First seen':<22} {'Last seen'}"
    )
    print("-" * 75)

    for ip, times in sorted(suspicious.items(), key=lambda x: -len(x[1])):
        times_sorted = sorted(times)
        print(
            f"  {ip:<20} {len(times):>8}   "
            f"{times_sorted[0].strftime('%Y-%m-%d %H:%M:%S'):<22}"
            f"{times_sorted[-1].strftime('%Y-%m-%d %H:%M:%S')}"
        )


# ── Entry point ───────────────────────────────────────────────────────────────
def _parse_dt(value: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Unrecognised date format: '{value}'. "
        "Use YYYY-MM-DD, YYYY-MM-DD HH:MM, or YYYY-MM-DD HH:MM:SS"
    )


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Brute-force login detector (Windows Security log)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # rolling 10-minute window ending now (default)
  detector.py

  # explicit range
  detector.py --start "2025-05-30 02:00" --end "2025-05-30 03:00"

  # anchor on end time, look back 30 minutes
  detector.py --end "2025-05-30 03:00" --window 30

  # anchor on start time, look forward 30 minutes
  detector.py --start "2025-05-30 02:00" --window 30
        """,
    )
    p.add_argument("--server",    default="localhost", help="Target host")
    p.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,  help="Failed attempts before alert")
    p.add_argument("--window",    type=int, default=DEFAULT_WINDOW_MIN, help="Window size in minutes (used when only one bound is given)")
    p.add_argument("--start",     type=_parse_dt, default=None, metavar="DATETIME", help="Range start (YYYY-MM-DD [HH:MM[:SS]])")
    p.add_argument("--end",       type=_parse_dt, default=None, metavar="DATETIME", help="Range end   (YYYY-MM-DD [HH:MM[:SS]])")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    detect(
        server=args.server,
        threshold=args.threshold,
        window_minutes=args.window,
        start=args.start,
        end=args.end,
    )
