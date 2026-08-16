// Talks to the FastAPI backend. In dev, Vite proxies /api -> http://localhost:8000
// (see vite.config.js), so these calls work as relative paths.

export async function analyzeText(text) {
  const res = await fetch('/api/analyze/text', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Request failed (${res.status})`)
  }
  return res.json()
}

export async function analyzeScreenshot(file, lang = 'eng') {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`/api/analyze/screenshot?lang=${encodeURIComponent(lang)}`, {
    method: 'POST',
    body: form,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Request failed (${res.status})`)
  }
  return res.json()
}

export async function analyzeQr(file) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch('/api/analyze/qr', {
    method: 'POST',
    body: form,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Request failed (${res.status})`)
  }
  return res.json()
}
