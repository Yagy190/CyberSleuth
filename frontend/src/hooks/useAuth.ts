// CyberSleuth AI – Auth Hook
// Member 3: Frontend & Security Visualization
import { useState, useEffect, useCallback } from 'react'
import { login as apiLogin, getMe } from '../services/api'
import type { User } from '../types'

export function useAuth() {
  const [user, setUser]       = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem('cs_token')
    if (!token) { setLoading(false); return }
    getMe()
      .then(setUser)
      .catch(() => localStorage.removeItem('cs_token'))
      .finally(() => setLoading(false))
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const token = await apiLogin(username, password)
    localStorage.setItem('cs_token', token.access_token)
    const me = await getMe()
    setUser(me)
    return me
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem('cs_token')
    setUser(null)
    window.location.href = '/login'
  }, [])

  return { user, loading, login, logout, isAuthenticated: !!user }
}
