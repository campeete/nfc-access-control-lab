import { useState, useEffect, useCallback } from 'react'
import { api, clearToken } from './api'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts'

const COLORS = ['#3fb950', '#58a6ff', '#bc8cff', '#d29922', '#f85149']

function StatCard({ label, value, sub, accent }) {
  return (
    <div style={{
      background: 'var(--bg2)', border: '1px solid var(--border)',
      borderTop: `2px solid ${accent || 'var(--border2)'}`,
      padding: '20px 22px'
    }}>
      <div className="mono" style={{
        fontSize: 10, color: 'var(--text3)', letterSpacing: 2,
        textTransform: 'uppercase', marginBottom: 10
      }}>{label}</div>
      <div style={{
        fontSize: 32, fontWeight: 600, color: accent || 'var(--text)',
        fontFamily: 'var(--mono)', lineHeight: 1
      }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: 'var(--text2)', marginTop: 6 }}>{sub}</div>}
    </div>
  )
}

function SectionHeader({ title, count }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10,
      marginBottom: 12, paddingBottom: 10,
      borderBottom: '1px solid var(--border)'
    }}>
      <span className="mono" style={{ fontSize: 11, color: 'var(--green)', letterSpacing: 2 }}>◈</span>
      <span style={{ fontWeight: 500, fontSize: 13, letterSpacing: 1 }}>{title}</span>
      {count !== undefined && (
        <span className="mono" style={{
          fontSize: 10, color: 'var(--text3)',
          background: 'var(--bg3)', padding: '2px 8px',
          border: '1px solid var(--border)'
        }}>{count}</span>
      )}
    </div>
  )
}

function ResultBadge({ result }) {
  const cfg = {
    GRANTED: { color: 'var(--green)', bg: '#1a2e1a' },
    DENIED: { color: 'var(--red)', bg: '#2e1a1a' },
    ERROR: { color: 'var(--amber)', bg: '#2e2a1a' },
  }[result] || { color: 'var(--text2)', bg: 'var(--bg3)' }

  return (
    <span className="mono" style={{
      fontSize: 10, padding: '2px 8px', letterSpacing: 1,
      color: cfg.color, background: cfg.bg,
      border: `1px solid ${cfg.color}33`
    }}>{result}</span>
  )
}

const TOOLTIP_STYLE = {
  background: 'var(--bg2)', border: '1px solid var(--border2)',
  color: 'var(--text)', fontFamily: 'var(--mono)', fontSize: 11
}

export default function Dashboard({ onLogout }) {
  const [metrics, setMetrics] = useState(null)
  const [scans, setScans] = useState([])
  const [attacks, setAttacks] = useState([])
  const [validUids, setValidUids] = useState([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('overview')
  const [lastUpdate, setLastUpdate] = useState(null)

  const load = useCallback(async () => {
    try {
      const [m, s, a, u] = await Promise.all([
        api.metrics(), api.scans({ limit: 100 }),
        api.attacks({ limit: 100 }), api.validUids()
      ])
      setMetrics(m)
      setScans(s.data || [])
      setAttacks(a.data || [])
      setValidUids(u.data || [])
      setLastUpdate(new Date().toLocaleTimeString())
    } catch (err) {
      if (err.message.includes('401')) { clearToken(); onLogout(); }
    } finally { setLoading(false) }
  }, [onLogout])

  useEffect(() => {
    load()
    const interval = setInterval(load, 15000)
    return () => clearInterval(interval)
  }, [load])

  if (loading) return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center',
      justifyContent: 'center', flexDirection: 'column', gap: 16
    }}>
      <div className="mono" style={{ color: 'var(--green)', letterSpacing: 3, fontSize: 13 }}>
        LOADING TELEMETRY...
      </div>
      <div style={{
        width: 200, height: 2, background: 'var(--border)',
        position: 'relative', overflow: 'hidden'
      }}>
        <div style={{
          position: 'absolute', height: '100%', width: '40%',
          background: 'var(--green)',
          animation: 'scan-line 1.5s ease-in-out infinite'
        }} />
      </div>
    </div>
  )

  const s = metrics?.summary || {}

  const tabs = ['overview', 'scans', 'attacks', 'uids']

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)' }}>

      {/* Top nav */}
      <div style={{
        background: 'var(--bg2)', borderBottom: '1px solid var(--border)',
        padding: '0 24px', display: 'flex', alignItems: 'center',
        justifyContent: 'space-between', height: 52
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div className="mono" style={{ fontSize: 12, color: 'var(--green)', letterSpacing: 3 }}>
            ◈ NFC-LAB
          </div>
          <div style={{
            width: 1, height: 20, background: 'var(--border)'
          }} />
          {tabs.map(t => (
            <button key={t} onClick={() => setActiveTab(t)} style={{
              background: 'none', border: 'none',
              color: activeTab === t ? 'var(--text)' : 'var(--text3)',
              fontFamily: 'var(--mono)', fontSize: 11, letterSpacing: 1,
              textTransform: 'uppercase', cursor: 'pointer', padding: '6px 0',
              borderBottom: activeTab === t ? '2px solid var(--green)' : '2px solid transparent'
            }}>{t}</button>
          ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          {lastUpdate && (
            <span className="mono" style={{ fontSize: 10, color: 'var(--text3)' }}>
              SYNC {lastUpdate}
            </span>
          )}
          <div style={{
            width: 6, height: 6, borderRadius: '50%',
            background: 'var(--green)',
            animation: 'pulse-dot 2s ease-in-out infinite'
          }} />
          <button onClick={() => { clearToken(); onLogout(); }} style={{
            background: 'none', border: '1px solid var(--border)',
            color: 'var(--text2)', fontFamily: 'var(--mono)',
            fontSize: 10, padding: '4px 10px', cursor: 'pointer', letterSpacing: 1
          }}>LOGOUT</button>
        </div>
      </div>

      <div style={{ padding: '24px', maxWidth: 1400, margin: '0 auto' }}>

        {/* ── OVERVIEW TAB ── */}
        {activeTab === 'overview' && (
          <div className="fade-in">
            {/* Stat cards */}
            <div style={{
              display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 12, marginBottom: 24
            }}>
              <StatCard label="Total Scans" value={s.total_scans ?? 0}
                sub={`${s.scans_last_24h ?? 0} in last 24h`} accent="var(--blue)" />
              <StatCard label="Grant Rate" value={`${s.grant_rate_pct ?? 0}%`}
                sub={`${s.granted ?? 0} granted / ${s.denied ?? 0} denied`} accent="var(--green)" />
              <StatCard label="Attack Events" value={s.total_attacks ?? 0}
                sub={`${s.attacks_granted ?? 0} breached`} accent="var(--red)" />
              <StatCard label="Valid UIDs Found" value={s.valid_uids_found ?? 0}
                sub={`${s.confirmed_uids ?? 0} hardware confirmed`} accent="var(--purple)" />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 16 }}>

              {/* Scan timeline */}
              <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', padding: 20 }}>
                <SectionHeader title="Scan Activity — 24h" />
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={metrics?.timeline_24h || []}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                    <XAxis dataKey="hour" tick={{ fill: 'var(--text3)', fontSize: 9, fontFamily: 'var(--mono)' }}
                      tickFormatter={v => v.slice(11, 16)} />
                    <YAxis tick={{ fill: 'var(--text3)', fontSize: 9, fontFamily: 'var(--mono)' }} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} />
                    <Area type="monotone" dataKey="granted" stackId="1"
                      stroke="var(--green)" fill="#1a2e1a" strokeWidth={1.5} name="Granted" />
                    <Area type="monotone" dataKey="denied" stackId="1"
                      stroke="var(--red)" fill="#2e1a1a" strokeWidth={1.5} name="Denied" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Attack breakdown */}
              <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', padding: 20 }}>
                <SectionHeader title="Attack Types" />
                {(metrics?.attacks_by_type || []).length === 0 ? (
                  <div className="mono" style={{ color: 'var(--text3)', fontSize: 11, marginTop: 20 }}>
                    NO ATTACKS LOGGED
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={metrics.attacks_by_type} dataKey="count"
                        nameKey="attack_type" cx="50%" cy="50%" outerRadius={70}
                        strokeWidth={0}>
                        {metrics.attacks_by_type.map((_, i) => (
                          <Cell key={i} fill={COLORS[i % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={TOOLTIP_STYLE} />
                    </PieChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* Phase breakdown */}
            <div style={{ background: 'var(--bg2)', border: '1px solid var(--border)', padding: 20 }}>
              <SectionHeader title="Phase Breakdown" />
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={metrics?.scans_by_phase || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis dataKey="phase" tick={{ fill: 'var(--text3)', fontSize: 10, fontFamily: 'var(--mono)' }}
                    tickFormatter={v => `Phase ${v}`} />
                  <YAxis tick={{ fill: 'var(--text3)', fontSize: 10, fontFamily: 'var(--mono)' }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="count" radius={[2,2,0,0]}>
                    {(metrics?.scans_by_phase || []).map((entry, i) => (
                      <Cell key={i}
                        fill={entry.result === 'GRANTED' ? 'var(--green)' : 'var(--red)'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* ── SCANS TAB ── */}
        {activeTab === 'scans' && (
          <div className="fade-in">
            <SectionHeader title="Scan Events" count={scans.length} />
            <div style={{ border: '1px solid var(--border)', overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ background: 'var(--bg3)' }}>
                    {['Timestamp', 'UID', 'Phase', 'Result', 'Response (ms)', 'Reader IP'].map(h => (
                      <th key={h} className="mono" style={{
                        padding: '10px 14px', textAlign: 'left',
                        fontSize: 10, color: 'var(--text3)', fontWeight: 400,
                        letterSpacing: 1, borderBottom: '1px solid var(--border)'
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s, i) => (
                    <tr key={s.id} style={{
                      borderBottom: '1px solid var(--border)',
                      background: i % 2 === 0 ? 'var(--bg2)' : 'var(--bg)'
                    }}>
                      <td className="mono" style={{ padding: '9px 14px', fontSize: 11, color: 'var(--text2)' }}>
                        {s.timestamp?.slice(0, 19).replace('T', ' ')}
                      </td>
                      <td className="mono" style={{ padding: '9px 14px', fontSize: 12, color: 'var(--blue)' }}>
                        {s.uid}
                      </td>
                      <td className="mono" style={{ padding: '9px 14px', fontSize: 11, color: 'var(--purple)' }}>
                        P{s.phase}
                      </td>
                      <td style={{ padding: '9px 14px' }}>
                        <ResultBadge result={s.result} />
                      </td>
                      <td className="mono" style={{ padding: '9px 14px', fontSize: 11, color: 'var(--text2)' }}>
                        {s.response_time_ms ? `${s.response_time_ms.toFixed(1)}ms` : '—'}
                      </td>
                      <td className="mono" style={{ padding: '9px 14px', fontSize: 11, color: 'var(--text3)' }}>
                        {s.reader_ip || '—'}
                      </td>
                    </tr>
                  ))}
                  {scans.length === 0 && (
                    <tr>
                      <td colSpan={6} className="mono" style={{
                        padding: '40px', textAlign: 'center',
                        color: 'var(--text3)', fontSize: 11
                      }}>NO SCAN EVENTS — WAITING FOR FIRMWARE</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── ATTACKS TAB ── */}
        {activeTab === 'attacks' && (
          <div className="fade-in">
            <SectionHeader title="Attack Events" count={attacks.length} />
            <div style={{ border: '1px solid var(--border)', overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ background: 'var(--bg3)' }}>
                    {['Timestamp', 'Attack Type', 'UID', 'Phase Target', 'Result', 'Notes'].map(h => (
                      <th key={h} className="mono" style={{
                        padding: '10px 14px', textAlign: 'left',
                        fontSize: 10, color: 'var(--text3)', fontWeight: 400,
                        letterSpacing: 1, borderBottom: '1px solid var(--border)'
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {attacks.map((a, i) => (
                    <tr key={a.id} style={{
                      borderBottom: '1px solid var(--border)',
                      background: i % 2 === 0 ? 'var(--bg2)' : 'var(--bg)'
                    }}>
                      <td className="mono" style={{ padding: '9px 14px', fontSize: 11, color: 'var(--text2)' }}>
                        {a.timestamp?.slice(0, 19).replace('T', ' ')}
                      </td>
                      <td className="mono" style={{ padding: '9px 14px', fontSize: 11, color: 'var(--amber)' }}>
                        {a.attack_type}
                      </td>
                      <td className="mono" style={{ padding: '9px 14px', fontSize: 12, color: 'var(--blue)' }}>
                        {a.uid || '—'}
                      </td>
                      <td className="mono" style={{ padding: '9px 14px', fontSize: 11, color: 'var(--purple)' }}>
                        {a.phase_target ? `P${a.phase_target}` : '—'}
                      </td>
                      <td style={{ padding: '9px 14px' }}>
                        {a.result ? <ResultBadge result={a.result} /> : <span style={{ color: 'var(--text3)' }}>—</span>}
                      </td>
                      <td className="mono" style={{ padding: '9px 14px', fontSize: 10, color: 'var(--text3)' }}>
                        {a.notes || '—'}
                      </td>
                    </tr>
                  ))}
                  {attacks.length === 0 && (
                    <tr>
                      <td colSpan={6} className="mono" style={{
                        padding: '40px', textAlign: 'center',
                        color: 'var(--text3)', fontSize: 11
                      }}>NO ATTACK EVENTS LOGGED</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── VALID UIDs TAB ── */}
        {activeTab === 'uids' && (
          <div className="fade-in">
            <SectionHeader title="Valid UIDs Discovered" count={validUids.length} />
            <div style={{ border: '1px solid var(--border)', overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ background: 'var(--bg3)' }}>
                    {['UID', 'Discovered At', 'Method', 'Confirmed'].map(h => (
                      <th key={h} className="mono" style={{
                        padding: '10px 14px', textAlign: 'left',
                        fontSize: 10, color: 'var(--text3)', fontWeight: 400,
                        letterSpacing: 1, borderBottom: '1px solid var(--border)'
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {validUids.map((u, i) => (
                    <tr key={u.id} style={{
                      borderBottom: '1px solid var(--border)',
                      background: i % 2 === 0 ? 'var(--bg2)' : 'var(--bg)'
                    }}>
                      <td className="mono" style={{
                        padding: '12px 14px', fontSize: 15,
                        color: 'var(--green)', letterSpacing: 2
                      }}>{u.uid}</td>
                      <td className="mono" style={{ padding: '12px 14px', fontSize: 11, color: 'var(--text2)' }}>
                        {u.discovered_at?.slice(0, 19).replace('T', ' ')}
                      </td>
                      <td className="mono" style={{ padding: '12px 14px', fontSize: 11, color: 'var(--amber)' }}>
                        {u.discovery_method || '—'}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span className="mono" style={{
                          fontSize: 10, padding: '2px 8px',
                          color: u.confirmed ? 'var(--green)' : 'var(--text3)',
                          background: u.confirmed ? '#1a2e1a' : 'var(--bg3)',
                          border: `1px solid ${u.confirmed ? 'var(--green)33' : 'var(--border)'}`
                        }}>
                          {u.confirmed ? '✓ YES' : '○ NO'}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {validUids.length === 0 && (
                    <tr>
                      <td colSpan={4} className="mono" style={{
                        padding: '40px', textAlign: 'center',
                        color: 'var(--text3)', fontSize: 11
                      }}>NO VALID UIDs DISCOVERED YET</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
