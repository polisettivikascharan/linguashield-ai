# LinguaShield AI

Regional-language phishing detection — Omnikon National Hackathon 2026, Team Vision Runner's.

Two parts, matching the pitch deck's planned stack:

- **`backend/`** — Python + FastAPI. The analysis engine: keyword/pattern indicators across
  English, Hindi, Telugu, Tamil, and Hinglish, plus URL-trust heuristics, screenshot OCR, and QR
  decoding.
- **`frontend/`** — React (Vite). The interface: paste a message/URL, upload a screenshot, or
  scan a QR code, and see the risk result.

## Run the backend

```bash
cd backend
python -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Backend runs at `http://localhost:8000`. Check `http://localhost:8000/docs` for interactive API docs.

**System dependencies** (needed for OCR and QR endpoints — the text endpoint works with just the
pip packages above):

- Tesseract OCR binary (for `/api/analyze/screenshot`)
  - Ubuntu/Debian: `sudo apt install tesseract-ocr tesseract-ocr-hin tesseract-ocr-tel tesseract-ocr-tam`
  - macOS: `brew install tesseract tesseract-lang`
  - Windows: install from https://github.com/UB-Mannheim/tesseract/wiki
- zbar library (for `/api/analyze/qr`)
  - Ubuntu/Debian: `sudo apt install libzbar0`
  - macOS: `brew install zbar`

If these aren't installed, the text/URL check still works fully — only the screenshot and QR
endpoints need them.

## Run the frontend

```bash
cd frontend
npm install
npm run dev
```

Opens at `http://localhost:5173`. It's already configured (see `vite.config.js`) to proxy
`/api/*` calls to the backend at `localhost:8000`, so run the backend first.

## API summary

| Endpoint                    | Method | Body                          | Returns                                   |
|------------------------------|--------|--------------------------------|--------------------------------------------|
| `/api/analyze/text`          | POST   | `{ "text": "..." }`           | risk score, level, reasons, action        |
| `/api/analyze/screenshot`    | POST   | multipart image (`file`)      | OCR'd text + risk result                  |
| `/api/analyze/qr`            | POST   | multipart image (`file`)      | decoded content + risk result             |
| `/api/health`                | GET    | —                              | `{ status: "ok" }`                        |

## Where to take this after the hackathon

- Swap the rule-based scoring in `backend/phishing_engine.py` for a MuRIL-based classifier — the
  API layer doesn't need to change, only what's inside `analyze_text` / `analyze_url`.
- Add a PostgreSQL layer if you want to log checks (the deck lists this as "if storage is
  needed") — keep it opt-in and never store OTP/PIN/passwords even if pasted by mistake.
- Deploy: frontend to Vercel/Netlify, backend to Render/Railway/Fly.io; point the frontend's API
  base URL at the deployed backend instead of the local proxy.
