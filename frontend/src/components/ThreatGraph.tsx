// CyberSleuth AI – Threat Relationship Graph
// Member 3: Frontend & Security Visualization
// Uses ReactFlow to render a node-edge graph of entities in an incident.
import ReactFlow, {
  Background, Controls, MiniMap,
  type Node, type Edge, MarkerType
} from 'reactflow'
import 'reactflow/dist/style.css'
import type { GraphNode, GraphEdge } from '../types'

const TYPE_COLOR: Record<string, string> = {
  user:      '#1677ff',
  host:      '#52c41a',
  ip:        '#fa8c16',
  technique: '#722ed1',
}

interface Props {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export default function ThreatGraph({ nodes, edges }: Props) {
  if (!nodes || nodes.length === 0) {
    return (
      <div style={{ color: '#8b949e', padding: 24, textAlign: 'center' }}>
        No relationship graph available yet. Run an investigation to generate the graph.
      </div>
    )
  }

  // Layout: simple circular arrangement
  const rfNodes: Node[] = nodes.map((n, i) => ({
    id: n.id,
    data: { label: n.label },
    position: {
      x: 250 + 180 * Math.cos((2 * Math.PI * i) / nodes.length),
      y: 200 + 150 * Math.sin((2 * Math.PI * i) / nodes.length),
    },
    style: {
      background: TYPE_COLOR[n.type] ?? '#555',
      color: '#fff',
      border: 'none',
      borderRadius: n.type === 'ip' ? '50%' : 8,
      padding: '6px 12px',
      fontSize: 12,
      fontWeight: 600,
    },
  }))

  // De-duplicate edges by source+target+label
  const seenEdges = new Set<string>()
  const rfEdges: Edge[] = edges
    .filter((e) => {
      const key = `${e.source}→${e.target}→${e.label}`
      if (seenEdges.has(key)) return false
      seenEdges.add(key)
      return true
    })
    .map((e, i) => ({
      id: `e${i}`,
      source: e.source,
      target: e.target,
      label: e.label.replace(/_/g, ' '),
      animated: e.label.includes('login') || e.label.includes('c2'),
      markerEnd: { type: MarkerType.ArrowClosed, color: '#58a6ff' },
      style: { stroke: '#58a6ff', strokeWidth: 1.5 },
      labelStyle: { fill: '#8b949e', fontSize: 10 },
    }))

  return (
    <div style={{ height: 420, border: '1px solid #30363d', borderRadius: 8, overflow: 'hidden' }}>
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        fitView
        proOptions={{ hideAttribution: true }}
      >
        <MiniMap
          nodeColor={(n) => n.style?.background as string ?? '#555'}
          style={{ background: '#161b22' }}
        />
        <Controls />
        <Background color="#21262d" gap={20} />
      </ReactFlow>
    </div>
  )
}
