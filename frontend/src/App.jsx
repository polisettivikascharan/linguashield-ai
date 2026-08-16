import { useState, useRef } from 'react'
import { analyzeText, analyzeScreenshot, analyzeQr } from './api'

const SAMPLE_MESSAGE =
  "Dear customer, aapka SBI account KYC abhi update nahi hua hai. Aapka khata 24 ghante mein " +
  "block ho jayega. Turant verify karein: sbi-kyc-update.xyz/verify — OTP share karke apna " +
  "account safe rakhein."

const RISK_LABEL = { high: '⚠ HIGH RISK', medium: '⚠ MEDIUM RISK', low: '✓ LOW RISK' }

function ResultPanel({ status, error, result }) {
  if (status === 'idle') {
    return (
      <div className="result-empty">
        <div className="re-icon">🛡️</div>
        <div className="re-text">
          Run a check on the left. The result — risk level, reasons, and a safe next step — will
          appear here.
        </div>
      </div>
    )
  }
  if (status === 'loading') {
    return (
      <div className="scanning">
        <div className="scan-ring" />
        <div className="scanning-label">SCANNING ACROSS LANGUAGES…</div>
      </div>
    )
  }
  if (status === 'error') {
    return (
      <div className="result-empty">
        <div className="re-icon">⚠️</div>
        <div className="re-text">{error || 'Something went wrong. Is the backend running on :8000?'}</div>
      </div>
    )
  }
  if (!result) return null

  return (
    <div className="result-body">
      <div className="risk-header">
        <div className={`risk-tag ${result.level}`}>{RISK_LABEL[result.level]}</div>
        <div className="risk-score">
          Signal score
          <br />
          <b>{result.score}</b>/100
        </div>
      </div>
      <div className="meter">
        <div className={`meter-fill ${result.level}`} style={{ width: `${result.score}%` }} />
      </div>

      <div className="reasons-title">Why we flagged this</div>
      <div>
        {result.reasons.map((r, i) => (
          <div className="reason" key={i}>
            <div className="r-icon">{r.icon}</div>
            <div className="r-text">{r.text}</div>
          </div>
        ))}
      </div>

      <div className={`action-box ${result.level}`}>
        <b>{result.action.title}</b>
        <span>{result.action.text}</span>
      </div>

      <div className="disclaimer">
        Rule-based demo engine — indicators + heuristics, not a guarantee. Never enter OTP, PIN,
        CVV, or passwords based on a message alone.
      </div>
    </div>
  )
}

export default function App() {
  const [tab, setTab] = useState('text')
  const [message, setMessage] = useState('')
  const [status, setStatus] = useState('idle') // idle | loading | done | error
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [ocrLang, setOcrLang] = useState('eng')
  const [imgPreview, setImgPreview] = useState(null)
  const [qrPreview, setQrPreview] = useState(null)
  const [ocrStatusMsg, setOcrStatusMsg] = useState('')

  const imageInputRef = useRef(null)
  const qrInputRef = useRef(null)

  async function runTextAnalysis(text) {
    setStatus('loading')
    setError('')
    try {
      const r = await analyzeText(text)
      setResult(r)
      setStatus('done')
    } catch (e) {
      setError(e.message)
      setStatus('error')
    }
  }

  async function handleImageFile(file) {
    setImgPreview(URL.createObjectURL(file))
    setOcrStatusMsg('Reading text from image…')
    setStatus('loading')
    setError('')
    try {
      const r = await analyzeScreenshot(file, ocrLang)
      setMessage(r.extracted_text || '')
      setResult(r)
      setStatus('done')
      setOcrStatusMsg('Text extracted and analyzed.')
      setTab('text')
    } catch (e) {
      setError(e.message)
      setStatus('error')
      setOcrStatusMsg('')
    }
  }

  async function handleQrFile(file) {
    setQrPreview(URL.createObjectURL(file))
    setOcrStatusMsg('Decoding QR code…')
    setStatus('loading')
    setError('')
    try {
      const r = await analyzeQr(file)
      setMessage(r.decoded_content || '')
      setResult(r)
      setStatus('done')
      setOcrStatusMsg('QR decoded and analyzed.')
      setTab('text')
    } catch (e) {
      setError(e.message)
      setStatus('error')
      setOcrStatusMsg('')
    }
  }

  return (
    <>
      <header>
        <div className="brand">
          <div className="brand-mark">LS</div>
          <div>
            <div className="brand-name">LinguaShield AI</div>
            <div className="brand-sub">Omnikon 2026 · Omni_CyberTech_1</div>
          </div>
        </div>
        <div className="badge">
          <span className="dot" />
          React + FastAPI
        </div>
      </header>

      <div className="wrap">
        <section className="hero-simple">
          <div className="eyebrow">Regional-language phishing detection</div>
          <h1>
            Phishing doesn't only speak <span>English.</span>
          </h1>
          <p className="lede">
            Paste a message or link, drop a screenshot, or upload a QR code. LinguaShield scans it
            for phishing signals across languages and mixed-language text, and explains the risk
            in plain words — before you click.
          </p>
        </section>

        <section className="app">
          <div className="panel">
            <div className="panel-title">
              <span className="num">01</span> Check a message
            </div>
            <div className="panel-desc">Paste text or a link, upload a screenshot, or scan a QR code.</div>

            <div className="tabs">
              {['text', 'image', 'qr'].map((t) => (
                <div key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
                  {t === 'text' ? 'Message / URL' : t === 'image' ? 'Screenshot' : 'QR Code'}
                </div>
              ))}
            </div>

            {tab === 'text' && (
              <div className="pane active">
                <textarea
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Paste the suspicious message, SMS, WhatsApp text, or link here…"
                />
                <div className="row-btns">
                  <button className="btn-primary" disabled={!message.trim()} onClick={() => runTextAnalysis(message)}>
                    Analyze
                  </button>
                  <button className="btn-ghost" onClick={() => setMessage(SAMPLE_MESSAGE)}>
                    Try a sample
                  </button>
                  <button
                    className="btn-ghost"
                    onClick={() => {
                      setMessage('')
                      setStatus('idle')
                      setResult(null)
                    }}
                  >
                    Clear
                  </button>
                </div>
              </div>
            )}

            {tab === 'image' && (
              <div className="pane active">
                <div className="dropzone" onClick={() => imageInputRef.current?.click()}>
                  <div className="dz-icon">🖼️</div>
                  <div className="dz-main">Click to upload a screenshot</div>
                  <div className="dz-sub">PNG · JPG — sent to the backend for OCR</div>
                </div>
                <input
                  ref={imageInputRef}
                  type="file"
                  accept="image/*"
                  style={{ display: 'none' }}
                  onChange={(e) => e.target.files[0] && handleImageFile(e.target.files[0])}
                />
                <div className="lang-toggle">
                  <span className="lang-toggle-label">OCR language:</span>
                  {['eng', 'hin', 'tel', 'tam'].map((l) => (
                    <span
                      key={l}
                      className={`lang-pill ${ocrLang === l ? 'on' : ''}`}
                      onClick={() => setOcrLang(l)}
                    >
                      {l}
                    </span>
                  ))}
                </div>
                {imgPreview && (
                  <div className="preview-wrap" style={{ display: 'block' }}>
                    <img src={imgPreview} alt="preview" />
                  </div>
                )}
                <div className="ocr-status">{ocrStatusMsg}</div>
              </div>
            )}

            {tab === 'qr' && (
              <div className="pane active">
                <div className="dropzone" onClick={() => qrInputRef.current?.click()}>
                  <div className="dz-icon">▦</div>
                  <div className="dz-main">Click to upload a QR code image</div>
                  <div className="dz-sub">The hidden URL is decoded and checked</div>
                </div>
                <input
                  ref={qrInputRef}
                  type="file"
                  accept="image/*"
                  style={{ display: 'none' }}
                  onChange={(e) => e.target.files[0] && handleQrFile(e.target.files[0])}
                />
                {qrPreview && (
                  <div className="preview-wrap" style={{ display: 'block' }}>
                    <img src={qrPreview} alt="qr preview" />
                  </div>
                )}
                <div className="ocr-status">{ocrStatusMsg}</div>
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-title">
              <span className="num">02</span> Risk result
            </div>
            <div className="panel-desc">Risk level, reasons, and what to do next.</div>
            <ResultPanel status={status} error={error} result={result} />
          </div>
        </section>
      </div>

      <footer>
        <div className="fl">LINGUASHIELD AI — TEAM VISION RUNNER'S — OMNIKON NATIONAL HACKATHON 2026</div>
        <div className="fl">FRONTEND: REACT · BACKEND: FASTAPI</div>
      </footer>
    </>
  )
}
