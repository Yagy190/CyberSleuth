// CyberSleuth AI – Dashboard Page
// Member 3: Frontend & Security Visualization
import { useEffect, useState } from 'react'
import { Row, Col, Statistic, Card, Typography, Spin, message } from 'antd'
import {
  AlertOutlined, FileSearchOutlined,
  CheckCircleOutlined, ExclamationCircleOutlined
} from '@ant-design/icons'
import { listAlerts, listIncidents } from '../services/api'
import AlertCard from '../components/AlertCard'
import { runInvestigation, updateAlertStatus } from '../services/api'
import type { Alert, Incident } from '../types'

const { Title } = Typography

export default function Dashboard() {
  const [alerts,    setAlerts]    = useState<Alert[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading,   setLoading]   = useState(true)

  const load = async () => {
    try {
      const [a, i] = await Promise.all([
        listAlerts({ status: 'open', limit: 10 }),
        listIncidents({ limit: 5 }),
      ])
      setAlerts(a)
      setIncidents(i)
    } catch {
      message.error('Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleInvestigate = async (alertId: string) => {
    try {
      await runInvestigation([alertId])
      message.success('Investigation started! Check the Incidents tab.')
      load()
    } catch {
      message.error('Failed to start investigation')
    }
  }

  const handleStatusChange = async (alertId: string, status: string) => {
    try {
      await updateAlertStatus(alertId, status)
      message.success('Alert updated')
      load()
    } catch {
      message.error('Failed to update alert')
    }
  }

  if (loading) return <Spin style={{ display: 'block', marginTop: 80 }} />

  const criticalCount = alerts.filter((a) => a.severity === 'critical').length
  const highCount     = alerts.filter((a) => a.severity === 'high').length
  const completedInc  = incidents.filter((i) => i.status === 'completed').length

  return (
    <div>
      <Title level={4} style={{ color: '#e6edf3', marginBottom: 20 }}>
        Security Dashboard
      </Title>

      {/* Stats row */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        {[
          { title: 'Open Alerts',         value: alerts.length,   icon: <AlertOutlined />,              color: '#1677ff' },
          { title: 'Critical',            value: criticalCount,   icon: <ExclamationCircleOutlined />,  color: '#ff4d4f' },
          { title: 'High Severity',       value: highCount,       icon: <AlertOutlined />,              color: '#fa8c16' },
          { title: 'Completed Reports',   value: completedInc,    icon: <CheckCircleOutlined />,        color: '#52c41a' },
          { title: 'Total Incidents',     value: incidents.length, icon: <FileSearchOutlined />,        color: '#722ed1' },
        ].map((s) => (
          <Col xs={24} sm={12} md={8} lg={5} key={s.title}>
            <Card
              style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }}
              size="small"
            >
              <Statistic
                title={<span style={{ color: '#8b949e' }}>{s.title}</span>}
                value={s.value}
                prefix={<span style={{ color: s.color }}>{s.icon}</span>}
                valueStyle={{ color: s.color, fontWeight: 700 }}
              />
            </Card>
          </Col>
        ))}
      </Row>

      {/* Open Alerts */}
      <Row gutter={24}>
        <Col xs={24} lg={14}>
          <Title level={5} style={{ color: '#e6edf3', marginBottom: 12 }}>
            Open Alerts ({alerts.length})
          </Title>
          {alerts.length === 0 ? (
            <Card style={{ background: '#161b22', border: '1px solid #30363d' }}>
              <CheckCircleOutlined style={{ color: '#52c41a', marginRight: 8 }} />
              <span style={{ color: '#8b949e' }}>No open alerts. System looks clean.</span>
            </Card>
          ) : (
            alerts.map((a) => (
              <AlertCard
                key={a.alert_id}
                alert={a}
                onInvestigate={handleInvestigate}
                onStatusChange={handleStatusChange}
              />
            ))
          )}
        </Col>

        <Col xs={24} lg={10}>
          <Title level={5} style={{ color: '#e6edf3', marginBottom: 12 }}>
            Recent Investigations
          </Title>
          {incidents.map((inc) => (
            <Card
              key={inc.incident_id}
              size="small"
              style={{ background: '#161b22', border: '1px solid #30363d', marginBottom: 10 }}
            >
              <div style={{ color: '#e6edf3', fontWeight: 500, marginBottom: 4 }}>{inc.title}</div>
              <div style={{ color: '#8b949e', fontSize: 12 }}>
                Status: <span style={{ color: inc.status === 'completed' ? '#52c41a' : '#faad14' }}>
                  {inc.status}
                </span>
                {inc.confidence > 0 && (
                  <> · Confidence: {(inc.confidence * 100).toFixed(0)}%</>
                )}
              </div>
            </Card>
          ))}
        </Col>
      </Row>
    </div>
  )
}
