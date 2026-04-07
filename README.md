SQL Injection Scanner

Python tool that automatically tests web inputs for SQL injection vulnerabilities.

What it does
•	Sends 30+ SQLi payloads (error-based, blind, time-based, UNION)
•	Detects vulnerabilities by analyzing HTTP responses
•	Runs parallel scans with rate limiting
•	Saves results to JSON + log file
•	Supports authenticated sessions (cookies)

 Quick start
bash
•	pip install requests
•	python sql_injection_scanner.py "http://target.com/page?id=1" --cookie "PHPSESSID=123; security=low"

