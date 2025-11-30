# IP-Reputation-Checker
A simple, secure web app to check an IP address against threat intelligence (AbuseIPDB).

Without exposing your API key in the browser. Flask handles all API calls server-side; the frontend is plain HTML/CSS/JS.

Features
Server-side API calls: Your AbuseIPDB key stays on the backend.

Clean UI: Minimal HTML/CSS for quick use.

Validation and error handling: Checks IP format, handles API failures and timeouts.

Optional rate limiting: Prevents abuse on public deployments.
