# simple_bruteforce_detect.py
import win32evtlog
from collections import defaultdict
from datetime import datetime, timedelta

# Config
LOG_NAME = "Security"
THRESHOLD = 5           # failed attempts considered suspicious
WINDOW_MINUTES = 10     # time window to count failures

def read_security_events(server="localhost"):
    hand = win32evtlog.OpenEventLog(server, LOG_NAME)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for ev in events:
            yield ev

def simple_detect():
    now = datetime.now()
    window = timedelta(minutes=WINDOW_MINUTES)
    failed_by_ip = defaultdict(list)

    for ev in read_security_events():
        ev_id = ev.EventID & 0xFFFF          # mask to get real ID
        if ev_id != 4625:                    # 4625 = failed logon
            continue

        ts = ev.TimeGenerated                # pywin32 gives a datetime-like object
        inserts = ev.StringInserts or []

        # StringInserts layout can vary by system; try to safely pull IP
        source_ip = "Unknown"
        try:
            # common place for IP is near the end; this is tolerant
            for s in reversed(inserts):
                if s and (s.count('.') == 3 or ':' in s):  # rough IPv4/IPv6 check
                    source_ip = s
                    break
        except Exception:
            pass

        failed_by_ip[source_ip].append(ts)

    # Report IPs with >= THRESHOLD failures in the time window
    print(f"Suspicious IPs (>= {THRESHOLD} failed attempts within {WINDOW_MINUTES} minutes):\n")
    for ip, times in failed_by_ip.items():
        recent = [t for t in times if now - t <= window]
        if len(recent) >= THRESHOLD:
            print(f"  {ip:20} - {len(recent)} failed attempts")

if __name__ == "__main__":
    simple_detect()