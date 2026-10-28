// CyberSleuth AI – Shared TypeScript Types
// Member 3: Frontend & Security Visualization

export interface User {
  id: number
  username: string
  email: string
  is_admin: boolean
}

export interface SecurityEvent {
  id: number
  event_id: string
  timestamp: string
  event_type: string
  username?: string
  host?: string
  source_ip?: string
  severity_score: number
  ground_truth: string
  ingested_at: string
}

export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus   = 'open' | 'investigating' | 'resolved' | 'false_positive'

export interface Alert {
  id: number
  alert_id: string
  rule_name: string
  severity: AlertSeverity
  status: AlertStatus
  username?: string
  host?: string
  triggered_at: string
  description?: string
  anomaly_score: number
  evidence_events?: string[]
}

export type IncidentStatus = 'pending' | 'investigating' | 'completed' | 'closed'

export interface GraphNode {
  id: string
  type: 'user' | 'host' | 'ip' | 'technique'
  label: string
}

export interface GraphEdge {
  source: string
  target: string
  label: string
  event_id?: string
}

export interface Incident {
  id: number
  incident_id: string
  title: string
  status: IncidentStatus
  severity: string
  confidence: number
  summary?: string
  report_markdown?: string
  graph_data?: { nodes: GraphNode[]; edges: GraphEdge[] }
  timeline?: SecurityEvent[]
  mitre_techniques?: string[]
  recommendations?: string[]
  created_at: string
  updated_at: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
}
