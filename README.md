# Analyze Windows event logs

I have created a Python script to analyze Windows Event Logs and detect brute-force patterns based on windows alert IDs, reducing manual SOC triage time.

# Prerequesites

Works only on windows systems.
Needs to be run with administrator previleges to get access to the logs.
You need to install the pywin32 module by using: pip install pywin32

# Example output

Suspicious IPs (>= 5 failed attempts within 10 minutes):

  192.168.1.100         - 8 failed attempts
  10.0.0.15             - 12 failed attempts

# Future versions

1.I am working on adding an export to CVS file function.
2.Working on a limiter based on timestamps.
