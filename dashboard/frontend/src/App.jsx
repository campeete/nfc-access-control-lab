import { useState } from 'react'
import { hasToken } from './api'
import Login from './Login'
import Dashboard from './Dashboard'

export default function App() {
  const [authed, setAuthed] = useState(hasToken())

  return authed
    ? <Dashboard onLogout={() => setAuthed(false)} />
    : <Login onLogin={() => setAuthed(true)} />
}
