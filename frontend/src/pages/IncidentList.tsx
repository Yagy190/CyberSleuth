// CyberSleuth AI – Incident List Page
// Member 3: Frontend & Security Visualization
import { useEffect, useState } from 'react'
import { Table, Tag, Select, Typography, Button, Space, Spin, message } from 'antd'
import { useNavigate } from 'react-router-dom'
import dayjs from 'dayjs'
import { listIncidents } from '../services/api'
import type { Incident, IncidentStatus } from '../types'

const { Title } = Typography

const STATUS_COLOR: Record<IncidentStatus, string> = {
  pending:      'blue',
  investigating:'gold',
  completed:    'green',
  closed:       'default',
}

export default function IncidentList() {
  const navigate = useNavigate()
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading,   setLoading]   = useState(true)
  const [status,    setStatus]    = useState<string | undefined>()

  const load = async () => {
    setLoading(true)
    try {
      const data = await listIncidents({ status, limit: 100 })
      setIncidents(data)
    } catch {
      message.error('Failed to load incidents')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [status])  // eslint-disable-line

  const columns = [
    {
      title: 'ID',
      dataIndex: 'incident_id',
      render: (id: string) => (
        <span style={{ color: '#58a6ff', fontFamily: 'monospace', fontSize: 12 }}>
          {id.slice(0, 8)}…
        </span>
      ),
      width: 100,
    },
    {
      title: 'Title',
      dataIndex: 'title',
      render: (t: string, row: Incident) => (
        <Button type="link" onClick={() => navigate(`/incidents/${row.incident_id}`)} style={{ padding: 0 }}>
          {t}
        </Button>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      render: (s: IncidentStatus) => <Tag color={STATUS_COLOR[s]}>{s.toUpperCase()}</Tag>,
      width: 130,
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      render: (s: string) => (
        <Tag color={s === 'critical' ? 'red' : s === 'high' ? 'orange' : s === 'medium' ? 'gold' : 'green'}>
          {s.toUpperCase()}
        </Tag>
      ),
      width: 100,
    },
    {
      title: 'Confidence',
      dataIndex: 'confidence',
      render: (c: number) => c > 0 ? `${(c * 100).toFixed(0)}%` : '—',
      width: 100,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      render: (d: string) => dayjs(d).format('YYYY-MM-DD HH:mm'),
      width: 150,
    },
  ]

  return (
    <div>
      <Space style={{ marginBottom: 16 }} align="center">
        <Title level={4} style={{ color: '#e6edf3', margin: 0 }}>
          Incident Investigations
        </Title>
        <Select
          allowClear
          placeholder="Filter by status"
          options={[
            { value: 'pending',       label: 'Pending' },
            { value: 'investigating', label: 'Investigating' },
            { value: 'completed',     label: 'Completed' },
            { value: 'closed',        label: 'Closed' },
          ]}
          onChange={setStatus}
          style={{ width: 180 }}
        />
      </Space>

      {loading ? (
        <Spin style={{ display: 'block', marginTop: 60 }} />
      ) : (
        <Table
          dataSource={incidents}
          columns={columns}
          rowKey="incident_id"
          pagination={{ pageSize: 20 }}
          style={{ background: '#161b22' }}
          onRow={(row) => ({
            style: { cursor: 'pointer', background: '#161b22' },
            onClick: () => navigate(`/incidents/${row.incident_id}`),
          })}
        />
      )}
    </div>
  )
}
