
const API_BASE_URL = 'http://127.0.0.1:5000'

export function getAccessToken() {
  return sessionStorage.getItem('nids_access_token')
}

export function saveAccessToken(token) {
  sessionStorage.setItem('nids_access_token', token)
}

export function clearAccessToken() {
  sessionStorage.removeItem('nids_access_token')
}

export async function apiRequest(endpoint, options = {}) {
  const token = getAccessToken()

  const headers = {
    ...(options.headers || {}),
  }

  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  if (options.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  })

  if (response.status === 401 && endpoint !== '/api/auth/login') {
    clearAccessToken()
    window.dispatchEvent(new Event('nids:unauthorized'))
  }

  if (!response.ok) {
    let message = `API error: ${response.status}`

    try {
      const result = await response.json()
      if (result.error) {
        message = result.error
      }
    } catch {
      // Keep the HTTP status message if the response isn't JSON.
    }

    throw new Error(message)
  }

  return response.json()
}

export async function login(identifier, password) {
  const result = await apiRequest('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ identifier, password }),
  })

  saveAccessToken(result.access_token)

  return result.user
}

export async function createAdminAccount(username, email, password) {
  return apiRequest('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username, email, password }),
  })
}

export async function logout() {
  try {
    if (getAccessToken()) {
      await apiRequest('/api/auth/logout', {
        method: 'POST',
      })
    }
  } finally {
    clearAccessToken()
  }
}

export async function getProfile() {
  return apiRequest('/api/auth/profile')
}

export async function getDashboardStats() {
  return apiRequest('/api/dashboard/stats')
}

export async function checkApiStatus() {
  try {
    await apiRequest('/')
    return 'online'
  } catch {
    return 'offline'
  }
}

export async function getNotificationSettings() {
  return apiRequest('/api/settings/notifications')
}

export async function saveNotificationSettings(alertEmail, telegramChatId) {
  return apiRequest('/api/settings/notifications', {
    method: 'PUT',
    body: JSON.stringify({
      alert_email: alertEmail,
      telegram_chat_id: telegramChatId,
    }),
  })
}
