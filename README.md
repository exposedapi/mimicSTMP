# mimicSTMP
STMP Honeypot (Python)
=============

A minimal SMTP honeypot written. The server mimics an SMTP server (EHLO/HELO, MAIL FROM, RCPT TO, DATA)
and logs connection attempts and full message bodies to a logfile. It does not deliver mail.

WARNING & LEGAL
---------------
This tool is provided for education, research and defensive training only.
Do NOT run this on networks or against systems where you do not have explicit authorization.
Collecting or storing data from third parties may be subject to privacy and law — obey all applicable laws.

Requirements
------------
- Python 3.8+
- Twisted

Installation
------------
1. Create a virtual environment (recommended)
   python3 -m venv venv
   source venv/bin/activate

2. Install requirements
   pip install -r requirements.txt

Usage
-----
1. Edit `SMTP_SERVER_NAME` in `smtp_honeypot.py` if you wish to change the fake banner hostname.
2. Choose a port:
   - Default in the script: 2525 (no root required)
   - To bind to port 25 you must run as root (NOT RECOMMENDED), or set capabilities on python binary.

Run:
   python3 smtp_honeypot.py

Test with `telnet` (example):
   telnet 127.0.0.1 2525
   EHLO example.com
   MAIL FROM:<attacker@example.org>
   RCPT TO:<victim@example.com>
   DATA
   Subject: test
   Hello honeypot
   .
   QUIT

Logs
----
All events are written to `smtp_honeypot.log` in the working directory. The log includes session IDs,
remote IPs, commands, and the full message body when DATA is sent.

Notes & Improvements
--------------------
- This honeypot intentionally accepts mail and logs contents. You may want to add throttling, connection limits,
  or automated alerting in production testing.
- Consider running inside a controlled lab / VM and ensure logs are stored securely.
- For production-grade honeypots, integrate with existing honeyfarm frameworks, add fingerprinting, or decoy addresses.

License
-------
Use under your own responsibility. Educational / research use only.
