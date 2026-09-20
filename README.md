# CyberTrace — Digital Forensics MVP

A beginner-friendly Flask prototype for an authorized digital-forensics demonstration.

## Features
- Evidence upload (max 25 MB)
- File metadata extraction
- MD5 and SHA-256 hashing
- Basic text/log analysis
- IP, username and timestamp extraction
- Failed-login pattern detection
- PDF investigation report
- Responsive dashboard

## Run on Windows
1. Install Python 3.10+.
2. Open Command Prompt in this folder.
3. Create a virtual environment:
   `python -m venv venv`
4. Activate it:
   `venv\Scripts\activate`
5. Install packages:
   `pip install -r requirements.txt`
6. Start:
   `python app.py`
7. Open:
   `http://127.0.0.1:5000`

## Run on Kali/Linux
`python3 -m venv venv`
`source venv/bin/activate`
`pip install -r requirements.txt`
`python3 app.py`

Then open `http://127.0.0.1:5000`.

## Demo
Upload `sample_log.txt` and show:
- metadata
- MD5/SHA-256
- failed authentication count
- detected IP
- risk indicator
- generated PDF report

## Important
This is an MVP, not a certified forensic suite. Use only data/evidence you are authorized to examine. Risk indicators are heuristic and are not proof of malicious activity.

For a production version, add persistent case management, evidence-chain-of-custody records, access control, secure secret configuration, database storage, stronger file-type parsing, audit logs, and tests.
