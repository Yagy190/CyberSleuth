// CyberSleuth AI – AI Report Viewer Component
// Member 3: Frontend & Security Visualization
import { Typography, Progress, Tag, List, Divider } from 'antd'
import ReactMarkdown from 'react-markdown'
import type { Incident } from '../types'

const { Title, Text } = Typography

const CONF_COLOR = (c: number) =>
  c >= 0.8 ? '#52c41a' : c >= 0.5 ? '#faad14' : '#ff4d4f'

interface Props {
  incident: Incident
}

export default function ReportViewer({ incident }: Props) {
  return (
    <div>
      {/* Confidence & Severity */}
      <div style={{ display: 'flex', gap: 24, marginBottom: 20, flexWrap: 'wrap' }}>
        <div>
          <Text style={{ color: '#8b949e', display: 'block', marginBottom: 4 }}>Confidence</Text>
          <Progress
            type="circle"
            percent={Math.round(incident.confidence * 100)}
            size={72}
            strokeColor={CONF_COLOR(incident.confidence)}
            format={(p) => <span style={{ color: '#e6edf3', fontSize: 13 }}>{p}%</span>}
          />
        </div>
        <div style={{ flex: 1, minWidth: 200 }}>
          <Text style={{ color: '#8b949e', display: 'block', marginBottom: 4 }}>Summary</Text>
          <Text style={{ color: '#c9d1d9' }}>{incident.summary || 'Investigation in progress…'}</Text>
        </div>
      </div>

      {/* MITRE Techniques */}
      {incident.mitre_techniques && incident.mitre_techniques.length > 0 && (
        <>
          <Divider style={{ borderColor: '#30363d' }} />
          <Title level={5} style={{ color: '#e6edf3' }}>MITRE ATT&CK Techniques</Title>
          <div style={{ marginBottom: 16 }}>
            {incident.mitre_techniques.map((t) => (
              <Tag key={t} color="geekblue" style={{ marginBottom: 4 }}>
                <a
                  href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: 'inherit' }}
                >
                  {t}
                </a>
              </Tag>
            ))}
          </div>
        </>
      )}

      {/* Recommendations */}
      {incident.recommendations && incident.recommendations.length > 0 && (
        <>
          <Divider style={{ borderColor: '#30363d' }} />
          <Title level={5} style={{ color: '#e6edf3' }}>Recommendations</Title>
          <List
            size="small"
            dataSource={incident.recommendations}
            renderItem={(item, i) => (
              <List.Item style={{ borderColor: '#30363d', padding: '6px 0' }}>
                <Text style={{ color: '#c9d1d9' }}>
                  <Text style={{ color: '#1677ff', marginRight: 8 }}>{i + 1}.</Text>
                  {item}
                </Text>
              </List.Item>
            )}
          />
        </>
      )}

      {/* Full Report Markdown */}
      {incident.report_markdown && (
        <>
          <Divider style={{ borderColor: '#30363d' }} />
          <Title level={5} style={{ color: '#e6edf3' }}>Full Investigation Report</Title>
          <div
            className="report-content"
            style={{
              background: '#161b22',
              padding: 20,
              borderRadius: 8,
              border: '1px solid #30363d',
              maxHeight: 500,
              overflowY: 'auto',
            }}
          >
            <ReactMarkdown>{incident.report_markdown}</ReactMarkdown>
          </div>
        </>
      )}
    </div>
  )
}
