# CyberGuard Security Engine

A modular FastAPI prototype for URL phishing signals, basic image/WAV frequency analysis, and account-takeover velocity checks. All findings are heuristic indicators for triage; they are not proof that content is malicious, synthetic, or compromised. The service uses in-memory state only, so ATO history is process-local and resets on restart.

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API.

To run the container from the project root, use `docker compose -f deploy/docker-compose.yml up --build`.

## Endpoints

- `GET /healthz`, `GET /readyz`
- `POST /api/v1/scan-url` with JSON such as `{"url":"https://example.com/login"}`
- `POST /api/v1/scan-batch` with 1-50 URLs
- `POST /api/v1/phishing/scan` with JSON such as `{"url":"https://example.com/login"}`
- `POST /api/v1/deepfake/scan` with multipart field `file` (JPEG, PNG, WebP, or uncompressed WAV; at most 10 MiB by default)
- `POST /api/v1/ato/scan-log` with username, failed-attempt count, and optional IP/device/country metadata

Set `API_KEY` in `.env` to require the `X-API-Key` header on scan endpoints. With no key configured, endpoints are open for local demos. Restrict CORS origins before exposing the service.

## Checks

```powershell
pytest
```

FFT artifacts alone cannot establish deepfake authenticity. The media route intentionally returns a triage signal and should not be used for identity, hiring, credit, or access decisions. Production deployment also needs persistent per-tenant rate limits, key management, auditing, robust model validation, and operational controls.

## How scoring works

Each module returns findings with points (capped at 100). `app/shared/xai_engine.py` weights the module scores (phishing 0.40, deepfake 0.30, ATO 0.30), keeps at least 85% of the strongest signal so one hot module is not diluted, and maps the result to Safe (0-19), Low (20-39), Medium (40-59), High (60-79) or Critical (80-100). Each finding is rendered through a plain-language template. The response also carries a `decision` of `allow`, `review` or `block` for webhook use.

- **Phishing**: offline URL parsing only (the URL is never fetched). Raw/obfuscated IPs, `@` tricks, length, subdomain depth, hyphens, punycode, risky TLDs, shorteners, keywords, brand typosquatting and brand misuse against a small official-domain list, plus a lexicon check for urgency and credential-harvesting phrases in optional `text`.
- **Deepfake**: 2D FFT periodic-peak detection (with JPEG 8x8 grid harmonics masked), high-frequency energy ratio, block-gradient boundary check; for WAV, the steepest spectral step between 4 kHz and Nyquist (a sharp cutoff near 8 kHz scores highest). Thresholds are uncalibrated placeholders in `T` at the top of `engine.py`; calibrate on labelled data before relying on them. Subtle artifacts and nearest-neighbour upsampling were not detected in synthetic tests.
- **ATO**: per-account sliding window (5 minutes) of failed attempts and event rate, plus new country, device family, /24 network and ASN against a baseline. Only clean, low-risk events extend the baseline. Supply `asn` from your own IP-intelligence source.
