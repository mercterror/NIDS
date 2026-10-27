
import { useEffect, useState } from 'react'
import {
  Monitor,
  ShieldCheck,
  Bell,
  Palette,
  UserRound,
  LockKeyhole,
  Sun,
  Moon,
  Check,
  Info,
  UserPlus,
} from 'lucide-react'

import {
  getNotificationSettings,
  saveNotificationSettings,
  createAdminAccount,
} from '../services/api'

function Settings() {
  const [theme, setTheme] = useState(
    () => localStorage.getItem('nids-theme') || 'dark'
  )

  const [alertEmail, setAlertEmail] = useState('')
  const [telegramChatId, setTelegramChatId] = useState('')
  const [notificationLoading, setNotificationLoading] = useState(true)
  const [notificationLoadFailed, setNotificationLoadFailed] = useState(false)
  const [notificationSaving, setNotificationSaving] = useState(false)
  const [notificationMessage, setNotificationMessage] = useState('')
  const [notificationError, setNotificationError] = useState(false)

  const [newUsername, setNewUsername] = useState('')
  const [newEmail, setNewEmail] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [accountCreating, setAccountCreating] = useState(false)
  const [accountMessage, setAccountMessage] = useState('')
  const [accountError, setAccountError] = useState(false)

  useEffect(() => {
    let active = true

    async function loadNotificationSettings() {
      try {
        const settings = await getNotificationSettings()

        if (!active) return

        setAlertEmail(settings.alert_email || '')
        setTelegramChatId(settings.telegram_chat_id || '')
        setNotificationLoadFailed(false)
        setNotificationError(false)
        setNotificationMessage('')
      } catch (error) {
        if (!active) return

        setNotificationLoadFailed(true)
        setNotificationError(true)

        if (error.message.includes('403') ||
            error.message.includes('Administrator access required')) {
          setNotificationMessage(
            'Only an administrator can manage notification settings.'
          )
        } else if (
          error.message.includes('401') ||
          error.message.includes('422')
        ) {
          setNotificationMessage(
            'Your session is invalid or expired. Please sign in again.'
          )
        } else {
          setNotificationMessage(
            'Unable to load notification settings. Please try again.'
          )
        }
      } finally {
        if (active) {
          setNotificationLoading(false)
        }
      }
    }

    loadNotificationSettings()

    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('nids-theme', theme)
  }, [theme])

  async function handleCreateAccount(event) {
    event.preventDefault()
    setAccountMessage('')
    setAccountError(false)

    if (newPassword.length < 12) {
      setAccountError(true)
      setAccountMessage('Password must be at least 12 characters long.')
      return
    }

    setAccountCreating(true)

    try {
      const result = await createAdminAccount(
        newUsername.trim(),
        newEmail.trim(),
        newPassword
      )

      setAccountMessage(
        result.message || 'Administrator account created successfully.'
      )
      setNewUsername('')
      setNewEmail('')
      setNewPassword('')
    } catch (error) {
      setAccountError(true)

      if (error.message.includes('409') ||
          error.message.includes('already exists')) {
        setAccountMessage('That username or email is already in use.')
      } else if (
        error.message.includes('403') ||
        error.message.includes('Administrator access required')
      ) {
        setAccountMessage('Administrator access is required to create accounts.')
      } else if (
        error.message.includes('401') ||
        error.message.includes('422')
      ) {
        setAccountMessage('Your session is invalid or expired. Please sign in again.')
      } else {
        setAccountMessage(error.message || 'Unable to create the account.')
      }
    } finally {
      setAccountCreating(false)
    }
  }

  async function handleSaveNotifications(event) {
    event.preventDefault()
    setNotificationMessage('')
    setNotificationError(false)

    if (
      notificationLoading ||
      notificationLoadFailed ||
      notificationSaving
    ) {
      return
    }

    setNotificationSaving(true)

    try {
      const result = await saveNotificationSettings(
        alertEmail.trim(),
        telegramChatId.trim()
      )

      setAlertEmail(result.alert_email || '')
      setTelegramChatId(result.telegram_chat_id || '')
      setNotificationMessage('Notification settings saved successfully.')
    } catch (error) {
      setNotificationError(true)

      if (error.message.includes('401') || error.message.includes('422')) {
        setNotificationMessage(
          'Your session is invalid or expired. Please sign in again.'
        )
      } else if (
        error.message.includes('403') ||
        error.message.includes('Administrator access required')
      ) {
        setNotificationMessage(
          'Administrator access is required to change these settings.'
        )
      } else {
        setNotificationMessage(
          error.message || 'Unable to save notification settings.'
        )
      }
    } finally {
      setNotificationSaving(false)
    }
  }

  const notificationFormDisabled =
    notificationLoading ||
    notificationLoadFailed ||
    notificationSaving

  const inputStyle = {
    width: '100%',
    maxWidth: '420px',
    boxSizing: 'border-box',
    padding: '12px 14px',
    borderRadius: '8px',
    border: '1px solid var(--border-color, #3b4a60)',
    background: 'var(--input-bg, #27364c)',
    color: 'var(--text-primary, #e6edf7)',
    fontSize: '14px',
  }

  const formButtonStyle = {
    padding: '11px 18px',
    border: 'none',
    borderRadius: '8px',
    background: '#4c9dab',
    color: '#10212b',
    fontWeight: 600,
    cursor: 'pointer',
  }

  return (
    <div className="settings-page">
      <div className="settings-intro">
        <h2>System Settings</h2>
        <p>Manage your NIDS dashboard preferences and configuration.</p>
      </div>

      {/* Account and access */}
      <section className="settings-section">
        <div className="settings-section-heading">
          <div className="settings-section-icon">
            <UserRound size={19} />
          </div>
          <div>
            <h3>Account &amp; Access</h3>
            <p>Authentication and account management</p>
          </div>
        </div>

        <div className="settings-info-row">
          <div>
            <strong>Authentication</strong>
            <p>Accounts are authenticated by the Flask backend.</p>
          </div>
          <span className="settings-status settings-status-neutral">
            Backend managed
          </span>
        </div>

        <div className="settings-info-row">
          <div>
            <strong>Session management</strong>
            <p>Access tokens expire after 15 minutes.</p>
          </div>
          <span className="settings-value">JWT</span>
        </div>

        <div className="settings-section-heading" style={{ marginTop: '24px' }}>
          <div className="settings-section-icon">
            <UserPlus size={19} />
          </div>
          <div>
            <h3>Create Administrator Account</h3>
            <p>Create an additional account with administrator access.</p>
          </div>
        </div>

        <p>
          Only an authenticated administrator can create accounts.
          New accounts created here receive the admin role.
        </p>

        <form
          onSubmit={handleCreateAccount}
          style={{ display: 'grid', gap: '16px', marginTop: '16px' }}
        >
          <div style={{ display: 'grid', gap: '8px' }}>
            <label htmlFor="new-admin-username">
              <strong>Username</strong>
            </label>
            <input
              id="new-admin-username"
              type="text"
              autoComplete="off"
              maxLength={80}
              required
              value={newUsername}
              onChange={(event) => setNewUsername(event.target.value)}
              placeholder="Enter username"
              disabled={accountCreating}
              style={inputStyle}
            />
          </div>

          <div style={{ display: 'grid', gap: '8px' }}>
            <label htmlFor="new-admin-email">
              <strong>Email address</strong>
            </label>
            <input
              id="new-admin-email"
              type="email"
              autoComplete="off"
              maxLength={254}
              required
              value={newEmail}
              onChange={(event) => setNewEmail(event.target.value)}
              placeholder="Enter email address"
              disabled={accountCreating}
              style={inputStyle}
            />
          </div>

          <div style={{ display: 'grid', gap: '8px' }}>
            <label htmlFor="new-admin-password">
              <strong>Password</strong>
            </label>
            <input
              id="new-admin-password"
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={128}
              required
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              placeholder="At least 12 characters"
              disabled={accountCreating}
              style={inputStyle}
            />
            <small>Use a password with at least 12 characters.</small>
          </div>

          <div>
            <button
              type="submit"
              disabled={accountCreating}
              style={{
                ...formButtonStyle,
                opacity: accountCreating ? 0.65 : 1,
                cursor: accountCreating ? 'not-allowed' : 'pointer',
              }}
            >
              {accountCreating ? 'Creating account...' : 'Create Account'}
            </button>
          </div>
        </form>

        {accountMessage && (
          <p
            role="status"
            aria-live="polite"
            style={{
              marginTop: '12px',
              color: accountError ? '#ef4444' : '#22c55e',
            }}
          >
            {accountMessage}
          </p>
        )}
      </section>

      {/* Detection and risk */}
      <section className="settings-section">
        <div className="settings-section-heading">
          <div className="settings-section-icon">
            <ShieldCheck size={19} />
          </div>
          <div>
            <h3>Detection &amp; Risk</h3>
            <p>Detection rules and threat assessment</p>
          </div>
        </div>

        <div className="settings-info-row">
          <div>
            <strong>Rule-based detection</strong>
            <p>Detection rules are defined in the existing backend.</p>
          </div>
          <span className="settings-status settings-status-neutral">
            Backend managed
          </span>
        </div>

        <div className="settings-info-row">
          <div>
            <strong>Suspicious score threshold</strong>
            <p>
              The packet-level detector marks scores of 50 or above
              as suspicious.
            </p>
          </div>
          <span className="settings-value">50 / 100</span>
        </div>
      </section>

      {/* Response and blocking */}
      <section className="settings-section">
        <div className="settings-section-heading">
          <div className="settings-section-icon">
            <LockKeyhole size={19} />
          </div>
          <div>
            <h3>Response &amp; Blocking</h3>
            <p>Response engine and enforcement status</p>
          </div>
        </div>

        <div className="settings-info-row">
          <div>
            <strong>Firewall enforcement</strong>
            <p>
              This dashboard does not change firewall rules from this screen.
            </p>
          </div>
          <span className="settings-status settings-status-neutral">
            Not controlled here
          </span>
        </div>

        <div className="settings-info-row">
          <div>
            <strong>Recorded block history</strong>
            <p>Review stored blocked IP records in Blocked Entities.</p>
          </div>
          <a className="settings-link" href="/blocked">
            View records
          </a>
        </div>
      </section>

      {/* Administrator notification settings */}
      <section className="settings-section">
        <div className="settings-section-heading">
          <div className="settings-section-icon">
            <Bell size={19} />
          </div>
          <div>
            <h3>Notifications</h3>
            <p>Choose where administrator alerts are delivered.</p>
          </div>
        </div>

        {notificationLoading ? (
          <p role="status">Loading notification settings...</p>
        ) : (
          <>
            <div className="settings-info-row">
              <div>
                <strong>Email delivery</strong>
                <p>
                  Alerts will be sent to the email address configured below.
                  This is separate from your login email.
                </p>
              </div>
              <span
                className={
                  alertEmail
                    ? 'settings-status settings-status-neutral'
                    : 'settings-value'
                }
              >
                {notificationLoadFailed
                  ? 'Unavailable'
                  : alertEmail
                    ? 'Destination configured'
                    : 'Not configured'}
              </span>
            </div>

            <div className="settings-info-row">
              <div>
                <strong>Telegram delivery</strong>
                <p>
                  Configure the Chat ID where the Telegram bot should send
                  administrator alerts.
                </p>
              </div>
              <span
                className={
                  telegramChatId
                    ? 'settings-status settings-status-neutral'
                    : 'settings-value'
                }
              >
                {notificationLoadFailed
                  ? 'Unavailable'
                  : telegramChatId
                    ? 'Destination configured'
                    : 'Not configured'}
              </span>
            </div>

            <form
              onSubmit={handleSaveNotifications}
              style={{
                display: 'grid',
                gap: '18px',
                marginTop: '16px',
              }}
            >
              <div style={{ display: 'grid', gap: '8px' }}>
                <label htmlFor="alert-email">
                  <strong>Alert recipient email</strong>
                </label>
                <p style={{ margin: 0 }}>
                  Enter the email address that should receive NIDS security
                  alerts. It does not need to match your administrator login.
                </p>
                <input
                  id="alert-email"
                  name="alert_email"
                  type="email"
                  value={alertEmail}
                  onChange={(event) => {
                    setAlertEmail(event.target.value)
                    setNotificationMessage('')
                    setNotificationError(false)
                  }}
                  placeholder="Enter recipient email address"
                  maxLength={254}
                  autoComplete="email"
                  disabled={notificationFormDisabled}
                  style={inputStyle}
                />
                <small>
                  Use an email address you can access. Leave blank to clear
                  the saved recipient.
                </small>
              </div>

              <div style={{ display: 'grid', gap: '8px' }}>
                <label htmlFor="telegram-chat-id">
                  <strong>Telegram Chat ID</strong>
                </label>
                <p style={{ margin: 0 }}>
                  Enter the Chat ID where you want to receive Telegram alerts.
                  Start a conversation with your configured Telegram bot before
                  testing delivery.
                </p>
                <input
                  id="telegram-chat-id"
                  name="telegram_chat_id"
                  type="text"
                  value={telegramChatId}
                  onChange={(event) => {
                    setTelegramChatId(event.target.value)
                    setNotificationMessage('')
                    setNotificationError(false)
                  }}
                  placeholder="Enter Telegram Chat ID"
                  maxLength={64}
                  autoComplete="off"
                  disabled={notificationFormDisabled}
                  style={inputStyle}
                />
                <small>
                  Leave blank to clear the saved Chat ID. The Telegram bot
                  token remains on the backend.
                </small>
              </div>

              <div>
                <button
                  type="submit"
                  disabled={notificationFormDisabled}
                  style={{
                    ...formButtonStyle,
                    opacity: notificationFormDisabled ? 0.65 : 1,
                    cursor: notificationFormDisabled
                      ? 'not-allowed'
                      : 'pointer',
                  }}
                >
                  {notificationSaving
                    ? 'Saving...'
                    : 'Save notification settings'}
                </button>
              </div>
            </form>

            {notificationMessage && (
              <p
                role="status"
                aria-live="polite"
                style={{
                  marginTop: '12px',
                  color: notificationError ? '#ef4444' : '#22c55e',
                }}
              >
                {notificationMessage}
              </p>
            )}
          </>
        )}
      </section>

      {/* Appearance */}
      <section className="settings-section">
        <div className="settings-section-heading">
          <div className="settings-section-icon">
            <Palette size={19} />
          </div>
          <div>
            <h3>Appearance</h3>
            <p>Customize the dashboard's visual theme</p>
          </div>
        </div>

        <div className="settings-theme-options">
          <button
            type="button"
            className={`settings-theme-option ${
              theme === 'dark' ? 'settings-theme-selected' : ''
            }`}
            onClick={() => setTheme('dark')}
            aria-pressed={theme === 'dark'}
          >
            <Moon size={21} />
            <span>
              <strong>Dark theme</strong>
              <small>Muted slate background</small>
            </span>
            {theme === 'dark' && <Check size={18} />}
          </button>

          <button
            type="button"
            className={`settings-theme-option ${
              theme === 'light' ? 'settings-theme-selected' : ''
            }`}
            onClick={() => setTheme('light')}
            aria-pressed={theme === 'light'}
          >
            <Sun size={21} />
            <span>
              <strong>Light theme</strong>
              <small>Bright, low-contrast surfaces</small>
            </span>
            {theme === 'light' && <Check size={18} />}
          </button>
        </div>

        <p className="settings-theme-note">
          <Info size={15} />
          Your appearance preference is saved in this browser.
        </p>
      </section>

      {/* System information */}
      <section className="settings-section">
        <div className="settings-section-heading">
          <div className="settings-section-icon">
            <Monitor size={19} />
          </div>
          <div>
            <h3>System Information</h3>
            <p>Dashboard details</p>
          </div>
        </div>

        <div className="settings-info-row">
          <div>
            <strong>Application</strong>
            <p>Network Intrusion Detection System</p>
          </div>
          <span className="settings-value">NIDS</span>
        </div>

        <div className="settings-info-row">
          <div>
            <strong>Frontend</strong>
            <p>React dashboard</p>
          </div>
          <span className="settings-value">React</span>
        </div>

        <div className="settings-info-row">
          <div>
            <strong>Backend</strong>
            <p>Flask API</p>
          </div>
          <span className="settings-value">Flask</span>
        </div>
      </section>
    </div>
  )
}

export default Settings
