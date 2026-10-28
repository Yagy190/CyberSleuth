// CyberSleuth AI – Alert Card Component
// Member 3: Frontend & Security Visualization
import { Card, Tag, Button, Space, Typography, Tooltip } from 'antd'
import { AlertOutlined, SearchOutlined, CheckCircleOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import type { Alert } from '../types'

const { Text, Paragraph } = Typography

const SEV_COLOR: Record<string, string> = {
  critical: 'red',
  high:     'orange',
  medium:   'gold',
  low:      'green',
}

interface Props {
  alert: Alert
  onInvestigate?: (alertId: string) => void
  onStatusChange?: (alertId: string, status: string) => void
}

export default function AlertCard({ alert, onInvestigate, onStatusChange }: Props) {
  return (
    <Card
      size="small"
      style={{
        background: '#161b22',
        border: '1px solid #30363d',
        marginBottom: 12,
        borderLeft: `3px solid ${SEV_COLOR[alert.severity] === 'red' ? '#ff4d4f'
          : SEV_COLOR[alert.severity] === 'orange' ? '#fa8c16'
          : SEV_COLOR[alert.severity] === 'gold' ? '#faad14' : '#52c41a'}`,
      }}
      extra={
        <Space size={4}>
          <Tag color={SEV_COLOR[alert.severity]}>{alert.severity.toUpperCase()}</Tag>
          <Tag color={alert.status === 'open' ? 'blue' : alert.status === 'resolved' ? 'green' : 'default'}>
            {alert.status}
          </Tag>
        </Space>
      }
      title={
        <Space>
          <AlertOutlined style={{ color: '#fa8c16' }} />
          <Text strong style={{ color: '#e6edf3' }}>{alert.rule_name}</Text>
        </Space>
      }
    >
      <Paragraph style={{ color: '#8b949e', marginBottom: 8, fontSize: 13 }}>
        {alert.description}
      </Paragraph>

      <Space split={<Text style={{ color: '#30363d' }}>|</Text>} wrap>
        {alert.username && <Text style={{ color: '#58a6ff', fontSize: 12 }}>👤 {alert.username}</Text>}
        {alert.host     && <Text style={{ color: '#79c0ff', fontSize: 12 }}>🖥 {alert.host}</Text>}
        <Text style={{ color: '#8b949e', fontSize: 12 }}>
          🕐 {dayjs(alert.triggered_at).format('YYYY-MM-DD HH:mm')}
        </Text>
        {alert.anomaly_score > 0 && (
          <Tooltip title="IsolationForest anomaly score">
            <Text style={{ color: '#d29922', fontSize: 12 }}>
              ⚡ Score: {(alert.anomaly_score * 100).toFixed(0)}%
            </Text>
          </Tooltip>
        )}
      </Space>

      {alert.evidence_events && alert.evidence_events.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <Text style={{ color: '#6e7681', fontSize: 11 }}>
            Evidence events: {alert.evidence_events.slice(0, 3).join(', ')}
            {alert.evidence_events.length > 3 && ` +${alert.evidence_events.length - 3} more`}
          </Text>
        </div>
      )}

      <Space style={{ marginTop: 12 }}>
        {onInvestigate && alert.status === 'open' && (
          <Button
            size="small"
            type="primary"
            icon={<SearchOutlined />}
            onClick={() => onInvestigate(alert.alert_id)}
          >
            Investigate
          </Button>
        )}
        {onStatusChange && alert.status !== 'resolved' && (
          <Button
            size="small"
            icon={<CheckCircleOutlined />}
            onClick={() => onStatusChange(alert.alert_id, 'resolved')}
          >
            Resolve
          </Button>
        )}
      </Space>
    </Card>
  )
}
