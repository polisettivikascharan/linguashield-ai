import { useEffect, useRef, useState } from 'react'
import {
  analyzeText,
  analyzeScreenshot,
  analyzeQr,
} from './api'

const SAMPLE_MESSAGE =
  'Dear customer, aapka SBI account KYC abhi update nahi hua hai. Aapka khata 24 ghante mein block ho jayega. Turant verify karein: sbi-kyc-update.xyz/verify — OTP share karke apna account safe rakhein.'

const RISK_LABEL = {
  high: 'HIGH RISK',
  medium: 'MEDIUM RISK',
  low: 'LOW RISK',
}

const HISTORY_KEY = 'linguashield_history'

function Icon({ children }) {
  return <span className="icon">{children}</span>
}

/* =========================================================
   RESULT PANEL
========================================================= */

function ResultPanel({ status, error, result }) {
  if (status === 'idle') {
    return (
      <div className="empty-result">
        <div className="empty-shield">🛡</div>

        <h3>Ready to protect you</h3>

        <p>
          Run a scan to see the risk level, warning signs,
          and recommended action.
        </p>

        <div className="empty-features">
          <span>✓ Message analysis</span>
          <span>✓ Screenshot OCR</span>
          <span>✓ QR detection</span>
        </div>
      </div>
    )
  }

  if (status === 'loading') {
    return (
      <div className="scanning">
        <div className="scan-circle">
          <div className="scan-dot" />
        </div>

        <h3>Analyzing content...</h3>

        <p>
          Checking phishing indicators and suspicious patterns.
        </p>
      </div>
    )
  }

  if (status === 'error') {
    return (
      <div className="empty-result error-result">
        <div className="empty-shield">⚠</div>

        <h3>Analysis failed</h3>

        <p>
          {error ||
            'Please make sure the backend is running.'}
        </p>
      </div>
    )
  }

  if (!result) {
    return null
  }

  const score = Math.min(
    100,
    Math.max(0, Number(result.score) || 0)
  )

  const level =
    result.level === 'high' ||
    result.level === 'medium' ||
    result.level === 'low'
      ? result.level
      : 'low'

  return (
    <div className="result-content">

      {/* RISK CARD */}

      <div className={`risk-card ${level}`}>

        <div className={`risk-icon ${level}`}>
          {level === 'low' ? '✓' : '!'}
        </div>

        <div className="risk-main">

          <div className={`risk-label ${level}`}>
            {RISK_LABEL[level]}
          </div>

          <div className="risk-message">
            {level === 'high'
              ? 'This content looks unsafe.'
              : level === 'medium'
                ? 'Be careful before interacting.'
                : 'No major warning signs detected.'}
          </div>

        </div>

        <div className="score-box">
          <span>Risk Score</span>

          <strong>{score}</strong>

          <small>/ 100</small>
        </div>

      </div>

      {/* SCORE BAR */}

      <div className="score-bar">
        <div
          className={`score-fill ${level}`}
          style={{
            width: `${score}%`,
          }}
        />
      </div>

      {/* REASONS */}

      <div className="section-heading">
        <span>Why we flagged this</span>
      </div>

      <div className="reason-list">

        {(result.reasons || []).length === 0 ? (
          <div className="no-reasons">
            <span>✓</span>
            No specific warning indicators were returned.
          </div>
        ) : (
          (result.reasons || []).map(
            (reason, index) => {

              const reasonText =
                typeof reason === 'string'
                  ? reason
                  : reason?.text || 'Suspicious behavior detected.'

              return (
                <div
                  className="reason-card"
                  key={index}
                >

                  <div className="reason-icon">
                    {typeof reason === 'object' &&
                    reason?.icon
                      ? reason.icon
                      : '⚠'}
                  </div>

                  <div className="reason-content">

                    <strong>
                      {reasonText}
                    </strong>

                    <p>
                      Suspicious behavior was detected
                      in this content.
                    </p>

                  </div>

                  <div className="reason-arrow">
                    ›
                  </div>

                </div>
              )
            }
          )
        )}

      </div>

      {/* URLS */}

      {Array.isArray(result.urls_found) &&
        result.urls_found.length > 0 && (

          <div className="detected-url">

            <div className="url-title">
              🔗 Suspicious URL detected
            </div>

            {result.urls_found.map(
              (url, index) => (
                <div
                  className="url-value"
                  key={index}
                >
                  {url}
                </div>
              )
            )}

          </div>
        )}

      {/* OCR TEXT */}

      {result.extracted_text && (

        <div className="extracted-box">

          <div className="small-title">
            Extracted text
          </div>

          <p>
            {result.extracted_text}
          </p>

        </div>
      )}

      {/* QR CONTENT */}

      {result.decoded_content && (

        <div className="extracted-box">

          <div className="small-title">
            QR content
          </div>

          <p>
            {result.decoded_content}
          </p>

        </div>
      )}

      {/* RECOMMENDATION */}

      {result.action && (

        <div
          className={`recommendation ${level}`}
        >

          <div className="recommendation-icon">
            🛡
          </div>

          <div>

            <strong>
              {result.action.title ||
                'Recommendation'}
            </strong>

            <p>
              {result.action.text}
            </p>

          </div>

        </div>
      )}

      {/* SECURITY NOTE */}

      <div className="security-note">

        <span>🔒</span>

        <div>

          <strong>Stay safe</strong>

          <p>
            Never share OTP, PIN, CVV, passwords,
            or banking credentials based only on
            a message.
          </p>

        </div>

      </div>

      <div className="engine-note">
        Rule-based phishing detection engine using
        indicators and heuristics. Automated analysis
        is not a guarantee.
      </div>

    </div>
  )
}

/* =========================================================
   MAIN APP
========================================================= */

export default function App() {

  const [darkMode, setDarkMode] =
    useState(false)

  const [activeMenu, setActiveMenu] =
    useState('home')

  const [tab, setTab] =
    useState('text')

  const [message, setMessage] =
    useState('')

  const [status, setStatus] =
    useState('idle')

  const [error, setError] =
    useState('')

  const [result, setResult] =
    useState(null)

  const [ocrLang, setOcrLang] =
    useState('eng')

  const [imgPreview, setImgPreview] =
    useState(null)

  const [qrPreview, setQrPreview] =
    useState(null)

  const [ocrStatusMsg, setOcrStatusMsg] =
    useState('')

  const [history, setHistory] =
    useState([])

  const imageInputRef =
    useRef(null)

  const qrInputRef =
    useRef(null)

  /* =======================================================
     LOAD HISTORY
  ======================================================= */

  useEffect(() => {

    try {

      const saved =
        localStorage.getItem(HISTORY_KEY)

      if (saved) {
        const parsed = JSON.parse(saved)

        if (Array.isArray(parsed)) {
          setHistory(parsed)
        }
      }

    } catch (err) {

      console.error(
        'Unable to load history:',
        err
      )

    }

  }, [])

  /* =======================================================
     SAVE HISTORY
  ======================================================= */

  useEffect(() => {

    try {

      localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(history)
      )

    } catch (err) {

      console.error(
        'Unable to save history:',
        err
      )

    }

  }, [history])

  /* =======================================================
     ADD HISTORY
  ======================================================= */

  function addHistory(r, content) {

    if (!r) {
      return
    }

    const safeContent =
      String(content || 'Scan')

    const item = {

      id:
        Date.now() +
        Math.random(),

      score:
        Number(r.score) || 0,

      level:
        r.level || 'low',

      content:
        safeContent.substring(0, 100),

      time:
        new Date().toLocaleString(
          [],
          {
            dateStyle: 'short',
            timeStyle: 'short',
          }
        ),
    }

    setHistory(prev => [
      item,
      ...prev,
    ].slice(0, 20))
  }

  /* =======================================================
     CLEAR HISTORY
  ======================================================= */

  function clearHistory() {

    if (history.length === 0) {
      return
    }

    const confirmed =
      window.confirm(
        'Are you sure you want to clear all scan history?'
      )

    if (!confirmed) {
      return
    }

    setHistory([])

    try {
      localStorage.removeItem(
        HISTORY_KEY
      )
    } catch (err) {
      console.error(err)
    }
  }

  /* =======================================================
     TEXT ANALYSIS
  ======================================================= */

  async function runTextAnalysis(text) {

    if (!text.trim()) {

      setError(
        'Please enter a message or URL first.'
      )

      setStatus('error')

      return
    }

    setStatus('loading')
    setError('')
    setResult(null)

    try {

      const r =
        await analyzeText(text)

      setResult(r)
      setStatus('done')

      addHistory(r, text)

    } catch (e) {

      setError(
        e?.message ||
        'Unable to analyze this content.'
      )

      setStatus('error')
    }
  }

  /* =======================================================
     SCREENSHOT
  ======================================================= */

  async function handleImageFile(file) {

    if (!file) {
      return
    }

    const preview =
      URL.createObjectURL(file)

    setImgPreview(preview)

    setQrPreview(null)

    setOcrStatusMsg(
      'Reading text from image...'
    )

    setStatus('loading')
    setError('')
    setResult(null)

    try {

      const r =
        await analyzeScreenshot(
          file,
          ocrLang
        )

      setMessage(
        r.extracted_text || ''
      )

      setResult(r)

      setStatus('done')

      setOcrStatusMsg(
        'Text extracted and analyzed.'
      )

      addHistory(
        r,
        r.extracted_text ||
          'Screenshot scan'
      )

    } catch (e) {

      setError(
        e?.message ||
        'Unable to analyze the screenshot.'
      )

      setStatus('error')

      setOcrStatusMsg('')
    }
  }

  /* =======================================================
     QR CODE
  ======================================================= */

  async function handleQrFile(file) {

    if (!file) {
      return
    }

    const preview =
      URL.createObjectURL(file)

    setQrPreview(preview)

    setImgPreview(null)

    setOcrStatusMsg(
      'Decoding QR code...'
    )

    setStatus('loading')
    setError('')
    setResult(null)

    try {

      const r =
        await analyzeQr(file)

      setMessage(
        r.decoded_content || ''
      )

      setResult(r)

      setStatus('done')

      setOcrStatusMsg(
        'QR decoded and analyzed.'
      )

      addHistory(
        r,
        r.decoded_content ||
          'QR code scan'
      )

    } catch (e) {

      setError(
        e?.message ||
        'Unable to decode the QR code.'
      )

      setStatus('error')

      setOcrStatusMsg('')
    }
  }

  /* =======================================================
     NEW SCAN
  ======================================================= */

  function newScan() {

    setMessage('')
    setResult(null)
    setStatus('idle')
    setError('')

    setImgPreview(null)
    setQrPreview(null)

    setOcrStatusMsg('')

    setTab('text')
    setActiveMenu('home')
  }

  /* =======================================================
     CLEAR CURRENT INPUT
  ======================================================= */

  function clearInput() {

    setMessage('')
    setResult(null)
    setStatus('idle')
    setError('')

    setImgPreview(null)
    setQrPreview(null)

    setOcrStatusMsg('')

    if (imageInputRef.current) {
      imageInputRef.current.value = ''
    }

    if (qrInputRef.current) {
      qrInputRef.current.value = ''
    }
  }

  /* =======================================================
     SAMPLE
  ======================================================= */

  function loadSample() {

    setMessage(SAMPLE_MESSAGE)

    setTab('text')

    setActiveMenu('home')

    setStatus('idle')

    setResult(null)

    setError('')
  }

  /* =======================================================
     MENU
  ======================================================= */

  function selectMenu(menu) {

    setActiveMenu(menu)

    if (
      menu === 'home' ||
      menu === 'message'
    ) {
      setTab('text')
    }

    if (menu === 'screenshot') {
      setTab('image')
    }

    if (menu === 'qr') {
      setTab('qr')
    }
  }

  /* =======================================================
     TAB
  ======================================================= */

  function changeTab(newTab) {

    setTab(newTab)

    setError('')

    if (newTab === 'text') {
      setActiveMenu('message')
    }

    if (newTab === 'image') {
      setActiveMenu('screenshot')
    }

    if (newTab === 'qr') {
      setActiveMenu('qr')
    }
  }

  /* =======================================================
     RENDER
  ======================================================= */

  return (

    <div
      className={`app-shell ${
        darkMode
          ? 'dark-mode'
          : 'light-mode'
      }`}
    >

      {/* =================================================
          HEADER
      ================================================= */}

      <header className="topbar">

        <div className="brand-area">

          <div className="logo-shield">
            <span>⌁</span>
          </div>

          <div>

            <div className="brand-name">
              LinguaShield <span>AI</span>
            </div>

            <div className="brand-tagline">
              Your Intelligent Phishing Protection Layer
            </div>

          </div>

        </div>

        <div className="top-actions">

          <div className="ai-badge">
            ✨ AI POWERED
          </div>

          <button
            className="language-button"
            type="button"
          >
            ◉ &nbsp; EN⌄
          </button>

          <button
            className="theme-button"
            type="button"
            onClick={() =>
              setDarkMode(
                prev => !prev
              )
            }
            title={
              darkMode
                ? 'Switch to Day Mode'
                : 'Switch to Dark Mode'
            }
          >
            {darkMode ? '☀' : '☾'}
          </button>

          <div className="protected-badge">

            <span>✓</span>

            <div>
              <strong>
                Protected
              </strong>

              <small>
                24/7
              </small>
            </div>

          </div>

        </div>

      </header>


      {/* =================================================
          DASHBOARD
      ================================================= */}

      <div className="dashboard">

        {/* =================================================
            SIDEBAR
        ================================================= */}

        <aside className="sidebar">

          <nav>

            <button
              className={
                activeMenu === 'home'
                  ? 'side-item active'
                  : 'side-item'
              }
              onClick={() =>
                selectMenu('home')
              }
            >
              <Icon>⌂</Icon>
              Home
            </button>

            <button
              className={
                activeMenu === 'message'
                  ? 'side-item active'
                  : 'side-item'
              }
              onClick={() =>
                selectMenu('message')
              }
            >
              <Icon>▢</Icon>
              Message / URL
            </button>

            <button
              className={
                activeMenu === 'screenshot'
                  ? 'side-item active'
                  : 'side-item'
              }
              onClick={() =>
                selectMenu('screenshot')
              }
            >
              <Icon>▧</Icon>
              Screenshot (OCR)
            </button>

            <button
              className={
                activeMenu === 'qr'
                  ? 'side-item active'
                  : 'side-item'
              }
              onClick={() =>
                selectMenu('qr')
              }
            >
              <Icon>▦</Icon>
              QR Code Scanner
            </button>

            <button
              className={
                activeMenu === 'history'
                  ? 'side-item active'
                  : 'side-item'
              }
              onClick={() =>
                selectMenu('history')
              }
            >
              <Icon>◷</Icon>
              History
            </button>

            <button
              className={
                activeMenu === 'tips'
                  ? 'side-item active'
                  : 'side-item'
              }
              onClick={() =>
                selectMenu('tips')
              }
            >
              <Icon>♢</Icon>
              Safe Tips
            </button>

            <button
              className={
                activeMenu === 'about'
                  ? 'side-item active'
                  : 'side-item'
              }
              onClick={() =>
                selectMenu('about')
              }
            >
              <Icon>ⓘ</Icon>
              About
            </button>

          </nav>

          <div className="sidebar-card">

            <div className="big-shield">
              🛡
            </div>

            <h3>
              Stay Safe Online
            </h3>

            <p>
              Detect phishing attempts in
              messages, images, and QR codes
              before they harm you.
            </p>

          </div>

        </aside>


        {/* =================================================
            MAIN CONTENT
        ================================================= */}

        <main className="main-content">

          {/* =================================================
              HISTORY
          ================================================= */}

          {activeMenu === 'history' ? (

            <section className="info-page">

              <div className="history-header">

                <div>

                  <div className="page-icon">
                    ◷
                  </div>

                  <h1>
                    Scan History
                  </h1>

                  <p>
                    Your recent scans are stored
                    securely in this browser.
                  </p>

                </div>

                {history.length > 0 && (

                  <button
                    className="clear-history-button"
                    type="button"
                    onClick={clearHistory}
                  >
                    🗑 Clear History
                  </button>

                )}

              </div>

              {history.length === 0 ? (

                <div className="empty-history">

                  <div>
                    ◷
                  </div>

                  <h3>
                    No scan history
                  </h3>

                  <p>
                    Your analyzed messages,
                    screenshots, and QR codes
                    will appear here.
                  </p>

                  <button
                    className="primary-small-button"
                    onClick={newScan}
                  >
                    + Start a Scan
                  </button>

                </div>

              ) : (

                <div className="history-list">

                  {history.map(item => (

                    <div
                      className="history-item"
                      key={item.id}
                    >

                      <div
                        className={`history-score ${item.level}`}
                      >
                        {item.score}
                      </div>

                      <div className="history-text">

                        <strong>
                          {item.content}
                        </strong>

                        <span>
                          {item.time}
                        </span>

                      </div>

                      <div
                        className={`history-level ${item.level}`}
                      >
                        {RISK_LABEL[item.level]}
                      </div>

                    </div>

                  ))}

                </div>

              )}

            </section>

          ) : activeMenu === 'tips' ? (

            /* =================================================
               SAFE TIPS
            ================================================= */

            <section className="info-page">

              <div className="page-icon">
                🛡
              </div>

              <h1>
                Safe Tips
              </h1>

              <p>
                Simple habits that can protect
                you from phishing.
              </p>

              <div className="tips-grid">

                <div className="tip-card">
                  <span>01</span>
                  <h3>
                    Never share OTP
                  </h3>
                  <p>
                    Banks and trusted services do
                    not need your OTP, PIN or CVV
                    through messages.
                  </p>
                </div>

                <div className="tip-card">
                  <span>02</span>
                  <h3>
                    Check the domain
                  </h3>
                  <p>
                    Look carefully at links before
                    opening them. Fake domains often
                    imitate trusted brands.
                  </p>
                </div>

                <div className="tip-card">
                  <span>03</span>
                  <h3>
                    Don't panic
                  </h3>
                  <p>
                    Scammers often create urgency
                    to make you act before thinking.
                  </p>
                </div>

                <div className="tip-card">
                  <span>04</span>
                  <h3>
                    Verify independently
                  </h3>
                  <p>
                    Contact the organization using
                    its official website or known
                    phone number.
                  </p>
                </div>

              </div>

            </section>

          ) : activeMenu === 'about' ? (

            /* =================================================
               ABOUT
            ================================================= */

            <section className="info-page about-page">

              <div className="page-icon">
                ◈
              </div>

              <h1>
                About LinguaShield AI
              </h1>

              <p>
                LinguaShield AI is a multilingual
                phishing detection system designed
                to identify suspicious messages,
                URLs, screenshots and QR codes.
              </p>

              <div className="about-grid">

                <div>
                  <strong>
                    Frontend
                  </strong>
                  <span>
                    React + Vite
                  </span>
                </div>

                <div>
                  <strong>
                    Backend
                  </strong>
                  <span>
                    FastAPI + Python
                  </span>
                </div>

                <div>
                  <strong>
                    OCR
                  </strong>
                  <span>
                    Tesseract OCR
                  </span>
                </div>

                <div>
                  <strong>
                    Languages
                  </strong>
                  <span>
                    English · Hindi · Hinglish · Telugu · Tamil
                  </span>
                </div>

              </div>

            </section>

          ) : (

            /* =================================================
               SCANNER PAGE
            ================================================= */

            <>

              <section className="welcome">

                <div>

                  <div className="eyebrow">
                    REGIONAL-LANGUAGE PHISHING DETECTION
                  </div>

                  <h1>
                    Phishing doesn't only speak
                    <span> English.</span>
                  </h1>

                  <p>
                    Analyze messages, screenshots
                    and QR codes across multiple
                    languages before you click.
                  </p>

                </div>

                <button
                  className="new-scan-button"
                  onClick={newScan}
                >
                  + New Scan
                </button>

              </section>


              <section className="scanner-grid">

                {/* =================================================
                    INPUT PANEL
                ================================================= */}

                <div className="panel input-panel">

                  <div className="panel-heading">

                    <div className="heading-icon purple">
                      ◉
                    </div>

                    <div>

                      <h2>
                        Check a Message,
                        Screenshot, or QR Code
                      </h2>

                      <p>
                        Detect phishing attempts
                        and protect yourself from scams.
                      </p>

                    </div>

                  </div>


                  {/* TABS */}

                  <div className="scan-tabs">

                    <button
                      className={
                        tab === 'text'
                          ? 'scan-tab active'
                          : 'scan-tab'
                      }
                      onClick={() =>
                        changeTab('text')
                      }
                    >
                      Message / URL
                    </button>

                    <button
                      className={
                        tab === 'image'
                          ? 'scan-tab active'
                          : 'scan-tab'
                      }
                      onClick={() =>
                        changeTab('image')
                      }
                    >
                      Screenshot (OCR)
                    </button>

                    <button
                      className={
                        tab === 'qr'
                          ? 'scan-tab active'
                          : 'scan-tab'
                      }
                      onClick={() =>
                        changeTab('qr')
                      }
                    >
                      QR Code
                    </button>

                  </div>


                  {/* =================================================
                      MESSAGE TAB
                  ================================================= */}

                  {tab === 'text' && (

                    <div className="scan-pane">

                      <label>
                        Paste a suspicious message or URL
                      </label>

                      <div className="textarea-wrapper">

                        <textarea
                          value={message}
                          onChange={e =>
                            setMessage(
                              e.target.value
                            )
                          }
                          maxLength={5000}
                          placeholder={
                            'Example: Your account will be blocked!\nVerify now: https://secure-login.example.com'
                          }
                        />

                        <div className="character-count">
                          {message.length} / 5000
                        </div>

                      </div>


                      <div className="sample-heading">
                        Or try a sample
                      </div>

                      <div className="sample-buttons">

                        <button
                          onClick={() =>
                            setMessage(
                              'Your bank account will be blocked today. Verify your KYC immediately.'
                            )
                          }
                        >
                          Account Blocked
                        </button>

                        <button
                          onClick={() =>
                            setMessage(
                              'Your KYC has expired. Verify your bank account immediately.'
                            )
                          }
                        >
                          Verify KYC
                        </button>

                        <button
                          onClick={() =>
                            setMessage(
                              'Congratulations! You have won a prize. Click here to claim your reward.'
                            )
                          }
                        >
                          Prize Scam
                        </button>

                        <button
                          onClick={() =>
                            setMessage(
                              'URGENT! Your SBI account will be blocked today. Share your OTP to avoid suspension.'
                            )
                          }
                        >
                          Bank Alert
                        </button>

                      </div>


                      <div className="action-row">

                        <button
                          className="analyze-button"
                          disabled={
                            status === 'loading'
                          }
                          onClick={() =>
                            runTextAnalysis(
                              message
                            )
                          }
                        >
                          🔍 Analyze
                        </button>

                        <button
                          className="clear-input-button"
                          type="button"
                          onClick={clearInput}
                          disabled={
                            !message &&
                            !result
                          }
                        >
                          Clear
                        </button>

                      </div>

                      <div className="privacy-note">
                        🔒 We never store your data.
                        All analysis is secure and private.
                      </div>

                    </div>
                  )}


                  {/* =================================================
                      SCREENSHOT TAB
                  ================================================= */}

                  {tab === 'image' && (

                    <div className="scan-pane">

                      <label>
                        Upload a screenshot
                      </label>

                      <input
                        ref={imageInputRef}
                        className="hidden-file-input"
                        type="file"
                        accept="image/png,image/jpeg,image/jpg"
                        onChange={e =>
                          handleImageFile(
                            e.target.files?.[0]
                          )
                        }
                      />

                      <button
                        className="upload-box"
                        type="button"
                        onClick={() =>
                          imageInputRef.current?.click()
                        }
                      >

                        {imgPreview ? (

                          <img
                            src={imgPreview}
                            alt="Screenshot preview"
                            className="image-preview"
                          />

                        ) : (

                          <>
                            <div className="upload-icon">
                              ▧
                            </div>

                            <strong>
                              Click to upload
                            </strong>

                            <span>
                              PNG, JPG or JPEG
                            </span>
                          </>

                        )}

                      </button>


                      <div className="ocr-controls">

                        <span>
                          OCR Language:
                        </span>

                        {[
                          ['eng', 'English'],
                          ['hin', 'Hindi'],
                          ['tel', 'Telugu'],
                          ['tam', 'Tamil'],
                        ].map(
                          ([value, label]) => (

                            <button
                              key={value}
                              className={
                                ocrLang === value
                                  ? 'language-chip active'
                                  : 'language-chip'
                              }
                              onClick={() =>
                                setOcrLang(value)
                              }
                              type="button"
                              title={label}
                            >
                              {value}
                            </button>

                          )
                        )}

                      </div>


                      {ocrStatusMsg && (

                        <div className="upload-status">
                          {ocrStatusMsg}
                        </div>

                      )}


                      <div className="action-row">

                        <button
                          className="clear-input-button"
                          type="button"
                          onClick={clearInput}
                        >
                          Clear
                        </button>

                      </div>

                    </div>
                  )}


                  {/* =================================================
                      QR TAB
                  ================================================= */}

                  {tab === 'qr' && (

                    <div className="scan-pane">

                      <label>
                        Upload a QR code image
                      </label>

                      <input
                        ref={qrInputRef}
                        className="hidden-file-input"
                        type="file"
                        accept="image/png,image/jpeg,image/jpg"
                        onChange={e =>
                          handleQrFile(
                            e.target.files?.[0]
                          )
                        }
                      />

                      <button
                        className="upload-box qr-upload"
                        type="button"
                        onClick={() =>
                          qrInputRef.current?.click()
                        }
                      >

                        {qrPreview ? (

                          <img
                            src={qrPreview}
                            alt="QR preview"
                            className="image-preview"
                          />

                        ) : (

                          <>
                            <div className="upload-icon">
                              ▦
                            </div>

                            <strong>
                              Click to upload QR
                            </strong>

                            <span>
                              PNG, JPG or JPEG
                            </span>
                          </>

                        )}

                      </button>


                      {ocrStatusMsg && (

                        <div className="upload-status">
                          {ocrStatusMsg}
                        </div>

                      )}


                      <div className="action-row">

                        <button
                          className="clear-input-button"
                          type="button"
                          onClick={clearInput}
                        >
                          Clear
                        </button>

                      </div>

                    </div>
                  )}

                </div>


                {/* =================================================
                    RESULT PANEL
                ================================================= */}

                <div className="panel result-panel">

                  <div className="panel-heading">

                    <div className="heading-icon cyan">
                      ▥
                    </div>

                    <div>

                      <h2>
                        Risk Result
                      </h2>

                      <p>
                        Here's what our detection
                        engine found.
                      </p>

                    </div>

                  </div>

                  <ResultPanel
                    status={status}
                    error={error}
                    result={result}
                  />

                </div>

              </section>

            </>

          )}

        </main>

      </div>

    </div>
  )
}