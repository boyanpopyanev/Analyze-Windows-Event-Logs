import win32evtlog
from collections import defaultdict
from datetime import datetime, timedelta

# Set Failed Attemps Counter & Set Work Window
LOG_NAME = "Security"
THRESHOLD = 5           
WINDOW_MINUTES = 10    

# Get EventLogs
def read_security_events(server="localhost"):
    hand = win32evtlog.OpenEventLog(server, LOG_NAME)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for ev in events:
            yield ev
            
# Check events for ID
def simple_detect():
    now = datetime.now()
    window = timedelta(minutes=WINDOW_MINUTES)
    failed_by_ip = defaultdict(list)

    for ev in read_security_events():
        ev_id = ev.EventID & 0xFFFF         
        if ev_id != 4625:                 
            continue

        ts = ev.TimeGenerated              
        inserts = ev.StringInserts or []
        
        source_ip = "Unknown"
        try:
    
            for s in reversed(inserts):
                if s and (s.count('.') == 3 or ':' in s):  # rough IPv4/IPv6 check
                    source_ip = s
                    break
        except Exception:
            pass

        failed_by_ip[source_ip].append(ts)

# Report IPs 
    print(f"Suspicious IPs (>= {THRESHOLD} failed attempts within {WINDOW_MINUTES} minutes):\n")
    for ip, times in failed_by_ip.items():
        recent = [t for t in times if now - t <= window]
        if len(recent) >= THRESHOLD:
            print(f"  {ip:20} - {len(recent)} failed attempts")

if __name__ == "__main__":

    simple_detect()
