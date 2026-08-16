"""
LinguaShield AI — FastAPI backend.

Endpoints:
  POST /api/analyze/text        { "text": "..." }            -> risk result
  POST /api/analyze/screenshot  multipart file upload (image)  -> OCR'd text + risk result
  POST /api/analyze/qr          multipart file upload (image)  -> decoded URL + risk result
  GET  /api/health              basic liveness check

Run:
  pip install -r requirements.txt
  uvicorn main:app --reload --port 8000

System dependencies (outside pip) needed for full functionality:
  - tesseract-ocr binary (for screenshot OCR via pytesseract)
      Ubuntu/Debian: sudo apt install tesseract-ocr tesseract-ocr-hin tesseract-ocr-tel tesseract-ocr-tam
      macOS:         brew install tesseract tesseract-lang
  - libzbar0 (for QR decoding via pyzbar)
      Ubuntu/Debian: sudo apt install libzbar0
      macOS:         brew install zbar
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image
import io

from phishing_engine import analyze_text

app = FastAPI(title="LinguaShield AI", version="0.1.0")

# Local dev CORS — tighten this before any real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class TextRequest(BaseModel):
    text: str


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "linguashield-ai"}


@app.post("/api/analyze/text")
def analyze_text_endpoint(payload: TextRequest):
    if not payload.text or not payload.text.strip():
        raise HTTPException(status_code=400, detail="No text provided")
    return analyze_text(payload.text)


@app.post("/api/analyze/screenshot")
async def analyze_screenshot(file: UploadFile = File(...), lang: str = "eng"):
    """OCR the uploaded screenshot, then run the same text analysis on the extracted text.
    `lang` accepts tesseract language codes, e.g. 'eng', 'hin', 'tel', 'tam', or combined 'eng+hin'.
    """
    try:
        import pytesseract
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="pytesseract not installed. Run: pip install pytesseract, and install the "
                   "tesseract-ocr system binary (see README).",
        )

    image_bytes = await file.read()
    try:
        image = Image.open(io.BytesIO(image_bytes))
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read uploaded file as an image")

    try:
        extracted_text = pytesseract.image_to_string(image, lang=lang)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OCR failed: {e}")

    result = analyze_text(extracted_text)
    result["extracted_text"] = extracted_text.strip()
    return result


@app.post("/api/analyze/qr")
async def analyze_qr(file: UploadFile = File(...)):
    """Decode a QR code image, extract the embedded URL/text, and run the analysis on it."""
    try:
        from pyzbar.pyzbar import decode as qr_decode
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="pyzbar not installed. Run: pip install pyzbar, and install the libzbar0 "
                   "system library (see README).",
        )

    image_bytes = await file.read()
    try:
        image = Image.open(io.BytesIO(image_bytes))
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read uploaded file as an image")

    decoded = qr_decode(image)
    if not decoded:
        raise HTTPException(status_code=422, detail="No QR code detected in this image")

    qr_text = decoded[0].data.decode("utf-8", errors="replace")
    result = analyze_text(qr_text)
    result["decoded_content"] = qr_text
    return result
