import { useState } from 'react'
import { ShieldCheck, Eye, EyeOff } from 'lucide-react'
import { login } from '../services/api'

function Login({ onLogin }) {
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')
    setLoading(true)

    try {
      const user = await login(identifier.trim(), password)
      onLogin(user)
    } catch (err) {
      setError(
        err.message.includes('401')
          ? 'Invalid username/email or password.'
          : 'Unable to connect to the NIDS server.'
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-card">
        <div className="auth-brand">
          <div className="auth-logo">
            <ShieldCheck size={30} />
          </div>

          <p className="auth-eyebrow">NETWORK SECURITY</p>
          <h1>NIDS</h1>
          <p className="auth-subtitle">
            Network Intrusion Detection & Prevention System
          </p>
        </div>

        <div className="auth-heading">
          <h2>Welcome back</h2>
          <p>Sign in to access your security dashboard.</p>
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          <label htmlFor="identifier">Username or email</label>
          <input
            id="identifier"
            type="text"
            autoComplete="username"
            placeholder="Enter your username or email"
            value={identifier}
            onChange={(event) => setIdentifier(event.target.value)}
            required
          />

          <label htmlFor="password">Password</label>
          <div className="auth-password-wrapper">
            <input
              id="password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="current-password"
              placeholder="Enter your password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />

            <button
              type="button"
              className="auth-password-toggle"
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              onClick={() => setShowPassword((previous) => !previous)}
            >
              {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>

          {error && (
            <p className="auth-error" role="alert">
              {error}
            </p>
          )}

          <button
            type="submit"
            className="auth-submit"
            disabled={loading}
          >
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>

        <p className="auth-footer">
          Authorized access only. Activity may be monitored.
        </p>
      </section>
    </main>
  )
}

export default Login