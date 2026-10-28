// CyberSleuth AI – API Service Layer
// Member 3: Frontend & Security Visualization

import axios from 'axios'
import type { Alert, Incident, SecurityEvent, TokenResponse, User } from '../types'

const BASE = import.meta.env.VITE_BACKEND_URL ?? ''

const api = axios.create({
  baseURL: `${BASE}/api/v1`,
  withCredentials: true,
})

// Attach JWT from localStorage on every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('cs_token')
  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`
  }
  return config
})

// Redirect to login on 401
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('cs_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

// ── Auth ───────────────────────────────────────────────────────────────────────

export async function login(username: string, password: string): Promise<TokenResponse> {
  const { data } = await api.post<TokenResponse>('/auth/login', { username, password })
  return data
}

export async function getMe(): Promise<User> {
  const { data } = await api.get<User>('/auth/me')
  return data
}

export async function register(username: string, email: string, password: string): Promise<User> {
  const { data } = await api.post<User>('/auth/register', { username, email, password })
  return data
}

// ── Events ─────────────────────────────────────────────────────────────────────

export async function listEvents(params?: {
  username?: string; host?: string; event_type?: string; limit?: number; offset?: number
}): Promise<SecurityEvent[]> {
  const { data } = await api.get<SecurityEvent[]>('/events', { params })
  return data
}

export async function getEvent(eventId: string): Promise<SecurityEvent> {
  const { data } = await api.get<SecurityEvent>(`/events/${eventId}`)
  return data
}

// ── Alerts ─────────────────────────────────────────────────────────────────────

export async function listAlerts(params?: {
  status?: string; severity?: string; username?: string; limit?: number
}): Promise<Alert[]> {
  const { data } = await api.get<Alert[]>('/alerts', { params })
  return data
}

export async function getAlert(alertId: string): Promise<Alert> {
  const { data } = await api.get<Alert>(`/alerts/${alertId}`)
  return data
}

export async function updateAlertStatus(alertId: string, status: string): Promise<Alert> {
  const { data } = await api.patch<Alert>(`/alerts/${alertId}`, { status })
  return data
}

// ── Incidents ──────────────────────────────────────────────────────────────────

export async function listIncidents(params?: { status?: string; limit?: number }): Promise<Incident[]> {
  const { data } = await api.get<Incident[]>('/incidents', { params })
  return data
}

export async function getIncident(incidentId: string): Promise<Incident> {
  const { data } = await api.get<Incident>(`/incidents/${incidentId}`)
  return data
}

export async function runInvestigation(alertIds: string[], title?: string): Promise<Incident> {
  const { data } = await api.post<Incident>('/incidents/run', { alert_ids: alertIds, title })
  return data
}

export async function submitFeedback(incidentId: string, feedback: string): Promise<Incident> {
  const { data } = await api.post<Incident>(`/incidents/${incidentId}/feedback`, { analyst_feedback: feedback })
  return data
}

export async function getIncidentGraph(incidentId: string) {
  const { data } = await api.get(`/incidents/${incidentId}/graph`)
  return data
}
