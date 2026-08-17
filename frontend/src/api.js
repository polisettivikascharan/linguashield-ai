const API_BASE_URL = 'https://linguashield-backend-docker.onrender.com'

async function handleResponse(response) {
  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new Error(
      data.detail ||
      data.message ||
      `Server error: ${response.status}`
    )
  }

  return data
}

export async function analyzeText(text) {
  const response = await fetch(
    `${API_BASE_URL}/api/analyze/text`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        text: text,
      }),
    }
  )

  return handleResponse(response)
}

export async function analyzeScreenshot(file, language = 'eng') {
  const formData = new FormData()

  formData.append('file', file)
  formData.append('lang', language)

  const response = await fetch(
    `${API_BASE_URL}/api/analyze/screenshot`,
    {
      method: 'POST',
      body: formData,
    }
  )

  return handleResponse(response)
}

export async function analyzeQr(file) {
  const formData = new FormData()

  formData.append('file', file)

  const response = await fetch(
    `${API_BASE_URL}/api/analyze/qr`,
    {
      method: 'POST',
      body: formData,
    }
  )

  return handleResponse(response)
}