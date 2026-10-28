// CyberSleuth AI – App Root
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ConfigProvider, theme } from 'antd'
import './index.css'

import { useAuth } from './hooks/useAuth'
import Login          from './pages/Login'
import Dashboard      from './pages/Dashboard'
import IncidentList   from './pages/IncidentList'
import IncidentDetail from './pages/IncidentDetail'
import AppLayout      from './components/AppLayout'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth()
  if (loading) return <div style={{ color: '#fff', padding: 40 }}>Loading…</div>
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />
}

function App() {
  return (
    <ConfigProvider theme={{ algorithm: theme.darkAlgorithm }}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <AppLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="incidents" element={<IncidentList />} />
            <Route path="incidents/:id" element={<IncidentDetail />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ConfigProvider>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
