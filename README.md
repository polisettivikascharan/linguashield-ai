# 🛡️ LinguaShield AI

> **Regional-language phishing detection platform**\
> **Omnikon National Hackathon 2026 --- Team Vision Runner's**

LinguaShield AI helps users identify potentially malicious **messages,
URLs, screenshots, and QR-code content** using multilingual phishing
indicators, URL-trust heuristics, OCR, QR decoding, and explainable risk
scoring.

------------------------------------------------------------------------

## ✨ Features

-   🌍 **Multilingual detection** --- English, Hindi, Telugu, Tamil, and
    Hinglish
-   💬 **Message analysis** --- paste suspicious text and receive a risk
    assessment
-   🔗 **URL analysis** --- checks suspicious URL characteristics using
    trust heuristics
-   🖼️ **Screenshot analysis** --- extracts text with OCR and analyzes
    it
-   📱 **QR-code analysis** --- decodes QR content and analyzes the
    result
-   ⚠️ **Explainable results** --- risk score, risk level, reasons, and
    recommended action

------------------------------------------------------------------------

## 🧩 How It Works

``` text
User Input
   │
   ├── Message / URL
   ├── Screenshot
   └── QR Code
          │
          ▼
   OCR / QR Decoding
          │
          ▼
   Text / URL Extraction
          │
          ▼
   Multilingual Pattern Analysis
          │
          ▼
   URL Heuristic Analysis
          │
          ▼
   Risk Signal Calculation
          │
          ▼
   Risk Classification
          │
          ▼
   Explainable Result
          │
          ▼
   Recommended Safety Action
```

------------------------------------------------------------------------

## 🏗️ Architecture

``` text
                    ┌──────────────────────┐
                    │      User Input      │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
             ▼                 ▼                 ▼
       Message / URL       Screenshot         QR Code
             │                 │                 │
             │                 ▼                 ▼
             │              OCR Engine       QR Decoder
             │                 │                 │
             └─────────────────┼─────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │   Analysis Engine    │
                    │                      │
                    │ • Language patterns  │
                    │ • Phishing signals   │
                    │ • URL heuristics     │
                    │ • Risk scoring       │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │     Risk Result      │
                    │                      │
                    │ • Score              │
                    │ • Risk level         │
                    │ • Reasons            │
                    │ • Recommended action │
                    └──────────────────────┘
```

------------------------------------------------------------------------

## 🛠️ Technology Stack

### Backend

-   Python
-   FastAPI
-   Pydantic
-   Rule-based multilingual phishing analysis engine
-   PyTesseract
-   Pillow
-   PyZBar / ZBar

### Frontend

-   React
-   Vite
-   JavaScript
-   CSS

------------------------------------------------------------------------

## 📁 Project Structure

``` text
linguashield-fullstack/
│
├── backend/
│   ├── main.py
│   ├── phishing_engine.py
│   ├── requirements.txt
│   └── ...
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── api.js
│   │   └── main.jsx
│   │
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   └── vite.config.js
│
├── README.md
├── .gitignore
└── package-lock.json
```

------------------------------------------------------------------------

# 🚀 Installation & Setup

## 1. Clone the Repository

``` bash
git clone https://github.com/polisettivikascharan/linguashield-ai.git
cd linguashield-ai
```

------------------------------------------------------------------------

## 2. Backend Setup

Open a terminal and enter the backend directory:

``` bash
cd backend
```

### Create a virtual environment

**Windows PowerShell:**

``` powershell
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux:**

``` bash
python3 -m venv venv
source venv/bin/activate
```

### Install dependencies

``` bash
pip install -r requirements.txt
```

### Start the backend

``` bash
uvicorn main:app --reload --port 8000
```

Backend:

**http://localhost:8000**

FastAPI interactive documentation:

**http://localhost:8000/docs**

------------------------------------------------------------------------

## 3. System Dependencies

The text and URL endpoint works with the Python packages from
`requirements.txt`.

**Screenshot OCR** and **QR-code decoding** require additional system
software.

### Tesseract OCR

Required for:

``` text
/api/analyze/screenshot
```

#### Windows

Install Tesseract OCR from the official Windows distribution:

https://github.com/UB-Mannheim/tesseract/wiki

#### Ubuntu / Debian

``` bash
sudo apt install tesseract-ocr
sudo apt install tesseract-ocr-hin
sudo apt install tesseract-ocr-tel
sudo apt install tesseract-ocr-tam
```

#### macOS

``` bash
brew install tesseract
brew install tesseract-lang
```

### ZBar

Required for:

``` text
/api/analyze/qr
```

#### Ubuntu / Debian

``` bash
sudo apt install libzbar0
```

#### macOS

``` bash
brew install zbar
```

> **Note:** If Tesseract or ZBar is not installed, the text/URL analysis
> still works. Only screenshot and QR endpoints require these additional
> system dependencies.

------------------------------------------------------------------------

## 4. Frontend Setup

Open a **second terminal** and enter the frontend directory:

``` bash
cd frontend
```

Install dependencies:

``` bash
npm install
```

Start the development server:

``` bash
npm run dev
```

Frontend:

**http://localhost:5173**

The Vite configuration proxies `/api/*` requests to the backend running
on:

**http://localhost:8000**

> **Important:** Start the backend before using the frontend.

------------------------------------------------------------------------

## 5. Run the Complete Application

### Terminal 1 --- Backend

``` bash
cd backend

# Activate your virtual environment first

uvicorn main:app --reload --port 8000
```

### Terminal 2 --- Frontend

``` bash
cd frontend

npm install
npm run dev
```

Then open:

**http://localhost:5173**

------------------------------------------------------------------------

# 🔌 API Reference

  ---------------------------------------------------------------------------------
  Endpoint                    Method            Body              Description
  --------------------------- ----------------- ----------------- -----------------
  `/api/analyze/text`         POST              JSON              Analyze text or
                                                                  URL

  `/api/analyze/screenshot`   POST              Multipart image   OCR + phishing
                                                                  analysis

  `/api/analyze/qr`           POST              Multipart image   QR decoding +
                                                                  phishing analysis

  `/api/health`               GET               None              Check backend
                                                                  status
  ---------------------------------------------------------------------------------

------------------------------------------------------------------------

## `POST /api/analyze/text`

Analyzes a message or URL.

### Example request

``` json
{
  "text": "Your account will be blocked. Verify now and share your OTP."
}
```

The result includes the risk assessment, including:

-   Risk score
-   Risk level
-   Reasons
-   Detected URLs
-   Recommended action

------------------------------------------------------------------------

## `POST /api/analyze/screenshot`

Accepts an image through multipart form data.

### Processing flow

1.  Read the uploaded image.
2.  Run Tesseract OCR.
3.  Extract the text.
4.  Analyze the extracted content.
5.  Return the OCR text and risk result.

Supported OCR languages currently include:

``` text
eng
hin
tel
tam
```

------------------------------------------------------------------------

## `POST /api/analyze/qr`

Accepts a QR-code image through multipart form data.

### Processing flow

1.  Read the uploaded image.
2.  Decode the QR code.
3.  Extract the embedded URL or text.
4.  Analyze the decoded content.
5.  Return the decoded content and risk result.

------------------------------------------------------------------------

## `GET /api/health`

Checks whether the backend is running.

Example:

``` json
{
  "status": "ok",
  "service": "linguashield-ai"
}
```

------------------------------------------------------------------------

# 🧪 Example Detection

### Suspicious message

``` text
Your account will be blocked.
Verify now and share your OTP.
```

Possible phishing indicators include:

-   🚨 Urgency or pressure language
-   🔐 Request for OTP/PIN/CVV
-   ⚠️ Account blocking or suspension threat

Example result:

``` text
HIGH RISK

Score: 77/100

Why we flagged this:

🧩 Urgency / pressure language
🧩 Asks you to share OTP/PIN/CVV
🧩 Account blocking / suspension threat

Recommended action:

Don't click, reply, or share any details.
```

------------------------------------------------------------------------

# 🌍 Supported Languages

The current rule-based analysis engine includes indicators for:

-   English
-   Hindi
-   Telugu
-   Tamil
-   Hinglish

The system is designed to recognize phishing patterns in regional and
mixed-language content.

------------------------------------------------------------------------

# 🔐 Security & Privacy

LinguaShield AI is intended as a phishing-awareness and detection tool.

### Never share sensitive information such as:

-   OTPs
-   PINs
-   CVVs
-   Passwords
-   Banking credentials

The current engine is heuristic/rule-based. A detection result should
not be treated as an absolute guarantee that content is safe or
malicious.

If scan-history storage is added in the future:

-   Make storage opt-in.
-   Do not store OTPs.
-   Do not store PINs.
-   Do not store passwords.
-   Avoid storing unnecessary sensitive information.

------------------------------------------------------------------------

# ⚠️ Disclaimer

LinguaShield AI currently uses rule-based multilingual indicators and
URL heuristics.

A **LOW risk** result does **not** guarantee that a message or URL is
safe.

A **HIGH risk** result means that multiple suspicious indicators were
detected.

For important requests, users should independently verify the request
through the organization's official application, official website, or
verified contact channel.

------------------------------------------------------------------------

# 🔮 Future Enhancements

## 🤖 MuRIL-Based Classifier

The current rule-based scoring engine can be replaced or enhanced with a
**MuRIL-based multilingual classifier**.

The API layer can remain unchanged. The internal implementation of
`analyze_text` / `analyze_url` can be upgraded.

## 🗄️ Optional PostgreSQL Storage

A PostgreSQL layer can be added if scan-history storage is required.

Storage should be:

-   Opt-in
-   Privacy-conscious
-   Designed to avoid storing OTPs, PINs, passwords, and other sensitive
    credentials

## ☁️ Deployment

Possible deployment architecture:

``` text
React + Vite
      │
      ▼
Vercel / Netlify
      │
      ▼
FastAPI Backend
      │
      ▼
Render / Railway / Fly.io
```

For deployment, update the frontend API configuration so it points to
the deployed backend instead of the local Vite proxy.

------------------------------------------------------------------------

# 🏆 Hackathon Information

  Field     Details
  --------- --------------------------------------
  Event     Omnikon National Hackathon 2026
  Team      Vision Runner's
  Project   LinguaShield AI
  Domain    Regional-Language Phishing Detection

------------------------------------------------------------------------

# 📄 License

This project is licensed under the **MIT License**.

------------------------------------------------------------------------

# 🎯 Project Summary

LinguaShield AI combines:

``` text
Multilingual Detection
        +
URL Trust Heuristics
        +
Screenshot OCR
        +
QR Decoding
        +
Explainable Risk Scoring
        ↓
Regional-Language Phishing Detection
```

### Goal

> **Help users understand suspicious content before they click, reply,
> or share sensitive information.**
