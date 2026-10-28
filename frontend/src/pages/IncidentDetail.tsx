// CyberSleuth AI – Incident Detail Page
// Member 3: Frontend & Security Visualization
import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Tabs, Tag, Typography, Button, Spin, message,
  Form, Input, Breadcrumb, Space, Badge
} from 'antd'
import {
  ArrowLeftOutlined, ClockCircleOutlined, ApartmentOutlined,
  FileTextOutlined, SafetyOutlined
} from '@ant-design/icons'
import { getIncident, submitFeedback } from '../services/api'
import EventTimeline from '../components/EventTimeline'
import ThreatGraph   from '../components/ThreatGraph'
import ReportViewer  from '../components/ReportViewer'
import type { Incident, SecurityEvent } from '../types'

const { Title, Text } = Typography

const STATUS_BADGE: Record<string, 'processing' | 'success' | 'warning' | 'default'> = {
  pending:       'warning',
  investigating: 'processing',
  completed:     'success',
  closed:        'default',
}

export default function IncidentDetail() {
  const { id }     = useParams<{ id: string }>()
  const navigate   = useNavigate()
  const [incident, setIncident] = useState<Incident | null>(null)
  const [loading,  setLoading]  = useState(true)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (!id) return
    getIncident(id)
      .then(setIncident)
      .catch(() => message.error('Incident not found'))
      .finally(() => setLoading(false))
  }, [id])

  const handleFeedback = async (values: { feedback: string }) => {
    if (!incident) return
    setSubmitting(true)
    try {
      const updated = await submitFeedback(incident.incident_id, values.feedback)
      setIncident(updated)
      message.success('Feedback submitted')
    } catch {
      message.error('Failed to submit feedback')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) return <Spin style={{ display: 'block', marginTop: 80 }} />
  if (!incident) return <Text style={{ color: '#ff4d4f' }}>Incident not found.</Text>

  const timelineEvents = (incident.timeline ?? []) as unknown as SecurityEvent[]

  const tabs = [
    {
      key: 'report',
      label: <><FileTextOutlined /> Report</>,
      children: <ReportViewer incident={incident} />,
    },
    {
      key: 'timeline',
      label: <><ClockCircleOutlined /> Timeline ({timelineEvents.length})</>,
      children: <EventTimeline events={timelineEvents} />,
    },
    {
      key: 'graph',
      label: <><ApartmentOutlined /> Relationship Graph</>,
      children: (
        <ThreatGraph
          nodes={incident.graph_data?.nodes ?? []}
          edges={incident.graph_data?.edges ?? []}
        />
      ),
    },
    {
      key: 'feedback',
      label: <><SafetyOutlined /> Analyst Feedback</>,
      children: (
        <div style={{ maxWidth: 600 }}>
          <Text style={{ color: '#8b949e', display: 'block', marginBottom: 12 }}>
            Existing feedback: {incident.analyst_feedback || 'None yet.'}
          </Text>
          <Form onFinish={handleFeedback} layout="vertical">
            <Form.Item name="feedback" label={<span style={{ color: '#c9d1d9' }}>Add Feedback</span>}>
              <Input.TextArea rows={4} placeholder="Analyst notes…" />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={submitting}>Submit</Button>
          </Form>
        </div>
      ),
    },
  ]

  return (
    <div>
      {/* Breadcrumb */}
      <Breadcrumb
        style={{ marginBottom: 12 }}
        items={[
          { title: <a onClick={() => navigate('/incidents')} style={{ color: '#58a6ff' }}>Incidents</a> },
          { title: <span style={{ color: '#8b949e' }}>{incident.incident_id.slice(0, 8)}…</span> },
        ]}
      />

      {/* Header */}
      <Space align="start" style={{ marginBottom: 20 }}>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/incidents')} type="text" style={{ color: '#8b949e' }} />
        <div>
          <Title level={4} style={{ color: '#e6edf3', margin: 0 }}>{incident.title}</Title>
          <Space style={{ marginTop: 6 }}>
            <Badge status={STATUS_BADGE[incident.status]} text={
              <Tag color={incident.status === 'completed' ? 'green' : 'gold'}>{incident.status.toUpperCase()}</Tag>
            } />
            <Tag color={incident.severity === 'high' || incident.severity === 'critical' ? 'red' : 'orange'}>
              {incident.severity?.toUpperCase()}
            </Tag>
            {(incident.mitre_techniques ?? []).map((t) => (
              <Tag key={t} color="geekblue">{t}</Tag>
            ))}
          </Space>
        </div>
      </Space>

      {/* Tabs */}
      <Tabs
        defaultActiveKey="report"
        items={tabs}
        style={{ color: '#c9d1d9' }}
        tabBarStyle={{ borderBottom: '1px solid #30363d' }}
      />
    </div>
  )
}
