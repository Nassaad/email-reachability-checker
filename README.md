# Streamlit Email Reachability Checker

## Features
- Single-address and bulk CSV/TXT checks
- Syntax validation
- DNS MX and A/AAAA fallback checks
- Optional SMTP recipient probe (no message body sent)
- Optional catch-all heuristic
- Small built-in disposable-domain list
- Progress bar, status summaries, CSV export

## Important limitations
SMTP checks are not definitive. A server may accept all recipients, conceal mailbox existence, defer rejection, or block connections. SMTP acceptance does not guarantee delivery. Port 25 may be blocked by your network or hosting provider. The app labels inconclusive results as unknown instead of invalid.

## Windows setup
1. Install Python 3.11 or newer from https://www.python.org/downloads/ . During setup, enable **Add Python to PATH**.
2. Extract this folder.
3. Open Command Prompt or PowerShell in this folder.
4. Create a virtual environment:
   ```powershell
   py -m venv .venv
   ```
5. Activate it:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks activation, use Command Prompt and run:
   ```bat
   .venv\Scripts\activate.bat
   ```
6. Install packages:
   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
7. Start Streamlit:
   ```powershell
   streamlit run app.py
   ```
8. The app should open in your browser, usually at http://localhost:8501 .

## Usage
- **Single email**: enter one address and click Check email.
- **Bulk check**: upload a CSV/TXT or paste addresses. A CSV column named `email` is preferred; otherwise cells are scanned.
- Download the report with **Download results as CSV**.

## Responsible use
Only assess addresses you have permission to process. Avoid high concurrency and do not use the tool to harvest or enumerate mailboxes. SMTP behavior can be rate-limited or blocked by remote providers.
