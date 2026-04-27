import { useState } from 'react'
import { api, setToken } from './api'

export default function Login({ onLogin }) {
  const [pass, setPass] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setErr('')
    try {
      const { token } = await api.login(pass)
      setToken(token)
      onLogin()
    } catch {
      setErr('Invalid passphrase')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center',
      justifyContent: 'center', background: 'var(--bg)',
      position: 'relative', overflow: 'hidden'
    }}>
      {/* Grid background */}
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: 'linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px)',
        backgroundSize: '40px 40px', opacity: 0.4
      }} />

      {/* Scan line effect */}
      <div style={{
        position: 'absolute', left: 0, right: 0, height: '2px',
        background: 'linear-gradient(90deg, transparent, var(--green), transparent)',
        animation: 'scan-line 4s linear infinite', zIndex: 1
      }} />

      <div className="fade-in" style={{
        position: 'relative', zIndex: 2,
        width: 380, padding: '40px 36px',
        background: 'var(--bg2)',
        border: '1px solid var(--border2)',
        borderTop: '2px solid var(--green)',
      }}>
        {/* Header */}
        <div style={{ marginBottom: 32 }}>
          <div className="mono" style={{
            fontSize: 11, color: 'var(--green)', letterSpacing: 3,
            marginBottom: 12, textTransform: 'uppercase'
          }}>
            ◈ NFC-LAB-CTRL-v1.0
          </div>
          <div style={{ fontSize: 22, fontWeight: 600, color: 'var(--text)', marginBottom: 4 }}>
            Access Control Dashboard
          </div>
          <div style={{ fontSize: 13, color: 'var(--text2)' }}>
            Enter admin passphrase to authenticate
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 20 }}>
            <div className="mono" style={{
              fontSize: 10, color: 'var(--text3)', letterSpacing: 1,
              marginBottom: 8, textTransform: 'uppercase'
            }}>
              Passphrase
            </div>
            <input
              type="password"
              value={pass}
              onChange={e => setPass(e.target.value)}
              placeholder="••••••••••••"
              autoFocus
              style={{
                width: '100%', padding: '12px 14px',
                background: 'var(--bg3)', border: '1px solid var(--border2)',
                color: 'var(--text)', fontFamily: 'var(--mono)', fontSize: 14,
                outline: 'none', transition: 'border-color 0.2s',
                borderColor: err ? 'var(--red)' : undefined
              }}
              onFocus={e => e.target.style.borderColor = 'var(--green)'}
              onBlur={e => e.target.style.borderColor = err ? 'var(--red)' : 'var(--border2)'}
            />
            {err && (
              <div className="mono" style={{
                fontSize: 11, color: 'var(--red)', marginTop: 6
              }}>⚠ {err}</div>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || !pass}
            style={{
              width: '100%', padding: '12px',
              background: loading ? 'var(--bg3)' : 'var(--green2)',
              border: '1px solid var(--green)',
              color: 'var(--text)', fontFamily: 'var(--mono)',
              fontSize: 13, letterSpacing: 2, cursor: loading ? 'wait' : 'pointer',
              textTransform: 'uppercase', transition: 'all 0.2s',
              opacity: !pass ? 0.5 : 1
            }}
          >
            {loading ? '[ AUTHENTICATING... ]' : '[ AUTHENTICATE ]'}
          </button>
        </form>

        <div className="mono" style={{
          marginTop: 24, fontSize: 10, color: 'var(--text3)',
          borderTop: '1px solid var(--border)', paddingTop: 16, lineHeight: 1.6
        }}>
          SYS: NFC-ACCESS-CTRL-LAB<br />
          NODE: DASHBOARD-API :3001<br />
          AUTH: JWT/BCRYPT
        </div>
      </div>
    </div>
  )
}
