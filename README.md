# Cyber-Pass — Password Security & Threat Intelligence

A single security project with two related tools:
- **Password Strength & Breach Checker** — estimates strength in the browser and checks known password breach data using the Have I Been Pwned Pwned Passwords range API.
- **Threat Intelligence Lookup** — queries configured VirusTotal and AlienVault OTX APIs for IPs, domains, URLs, and file hashes. Results are provider-backed; missing keys, rate limits, errors, and unknown results are shown explicitly, never replaced with fake detections.

## Requirements
- Python 3.10+
- A modern browser
- Optional API keys for VirusTotal and AlienVault OTX. Use accounts/keys in accordance with each provider's terms and rate limits.

## Run locally (Windows PowerShell)

### 1. Set up backend
```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```
Edit `backend/.env` and add your API keys. **Do not share `.env` or commit it to GitHub.** You can run without keys, but providers will be shown as `NOT CONFIGURED` and risk will be `UNKNOWN`.

Start the backend from the `backend` folder:
```powershell
uvicorn main:app --reload --port 8000
```
Check `http://127.0.0.1:8000/api/health`.

### 2. Serve the frontend
Open a second terminal in the project root:
```powershell
cd frontend
py -m http.server 5173
```
Then open `http://127.0.0.1:5173`.

The frontend calls the backend at `http://127.0.0.1:8000`. Keep both services running locally. The backend CORS configuration allows the local frontend origin.

## How it works
- Password strength estimate runs locally.
- The browser hashes the password with SHA-1 and sends only the first five hash characters to the HIBP Pwned Passwords range endpoint; matching is performed in the browser.
- IOC lookup validates the submitted indicator and queries VirusTotal and AlienVault OTX from the Python backend so API keys are not exposed in browser code.
- The displayed risk label is a transparent, basic heuristic based on returned provider data. It is not a certified verdict or a replacement for analyst review.

## Security and privacy notes
- Never enter a password you use for a sensitive account into a checker unless you trust the implementation.
- A password not found in known breach data is not necessarily secure.
- For IOC lookup, the indicator is sent to configured third-party providers. Do not submit confidential internal indicators unless you are authorized to do so.
- API keys belong only in `backend/.env`, not in HTML/JS, screenshots, or Git commits.
- Add `.env` to `.gitignore`; never commit secrets.
- The project does not crawl or visit the submitted URL; it submits the indicator to the configured intelligence APIs.
- Provider results can be incomplete, stale, rate-limited, or unavailable. `UNKNOWN` does not mean safe.

## Suggested next improvements
- Add unit tests for indicator validation and mocked provider responses.
- Add server-side request rate limiting and a small database for persistent scan history.
- Add exportable JSON/PDF reports and provider timestamps.
