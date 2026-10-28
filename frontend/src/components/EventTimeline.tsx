// CyberSleuth AI – Event Timeline Component
// Member 3: Frontend & Security Visualization
import { Timeline, Tag, Typography, Tooltip } from 'antd'
import {
  LockOutlined, UnlockOutlined, ArrowUpOutlined,
  WifiOutlined, FileOutlined, WarningOutlined
} from '@ant-design/icons'
import dayjs from 'dayjs'
import type { SecurityEvent } from '../types'

const { Text } = Typography

const TYPE_ICON: Record<string, React.ReactNode> = {
  login_failure:    <LockOutlined style={{ color: '#ff4d4f' }} />,
  login_success:    <UnlockOutlined style={{ color: '#52c41a' }} />,
  privilege_change: <ArrowUpOutlined style={{ color: '#fa8c16' }} />,
  network_outbound: <WifiOutlined style={{ color: '#1677ff' }} />,
  file_access:      <FileOutlined style={{ color: '#722ed1' }} />,
  process_exec:     <WarningOutlined style={{ color: '#faad14' }} />,
}

const TYPE_COLOR: Record<string, string> = {
  login_failure:    'red',
  login_success:    'green',
  privilege_change: 'orange',
  network_outbound: 'blue',
  file_access:      'purple',
  process_exec:     'gold',
}

interface Props {
  events: SecurityEvent[]
}

export default function EventTimeline({ events }: Props) {
  if (!events || events.length === 0) {
    return <Text style={{ color: '#8b949e' }}>No events in timeline.</Text>
  }

  const items = events.map((e) => ({
    dot: TYPE_ICON[e.event_type] ?? <WarningOutlined />,
    color: TYPE_COLOR[e.event_type] ?? 'gray',
    children: (
      <div style={{ marginBottom: 4 }}>
        <Tag color={TYPE_COLOR[e.event_type] ?? 'default'} style={{ fontSize: 11 }}>
          {e.event_type.replace(/_/g, ' ').toUpperCase()}
        </Tag>
        <Text style={{ color: '#e6edf3', fontSize: 13 }}>
          {e.username && <><strong>{e.username}</strong> · </>}
          {e.host && <>{e.host} · </>}
          {e.source_ip && <Text style={{ color: '#58a6ff' }}>{e.source_ip}</Text>}
        </Text>
        <br />
        <Tooltip title={e.event_id}>
          <Text style={{ color: '#6e7681', fontSize: 11 }}>
            {dayjs(e.timestamp).format('YYYY-MM-DD HH:mm:ss')} · {e.event_id.slice(0, 16)}…
          </Text>
        </Tooltip>
      </div>
    ),
  }))

  return <Timeline items={items} />
}
