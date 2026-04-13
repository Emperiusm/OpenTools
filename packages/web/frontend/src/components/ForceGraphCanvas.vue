<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import ForceGraph from 'force-graph'

interface GraphNode {
  id: string
  name: string
  severity: string
  tool: string
  phase: string | null
  x?: number
  y?: number
  fx?: number | undefined
  fy?: number | undefined
  neighborCount?: number
  created_at?: string | null
  engagement_id?: string
  pivotality?: number
}

interface GraphLink {
  id: string
  source: string | GraphNode
  target: string | GraphNode
  value: number
  status: string
  drift: boolean
  reasons: string[]
  relation_type: string | null
  rationale: string | null
}

interface GraphData {
  nodes: GraphNode[]
  links: GraphLink[]
}

const props = withDefaults(defineProps<{
  data: GraphData
  selectedNodeId: string | null
  selectedLinkId: string | null
  timeRange?: { start: Date; end: Date } | null
  layoutMode?: 'force' | 'killchain'
  colorMode?: 'severity' | 'engagement'
  engagementColors?: Record<string, string>
}>(), {
  timeRange: null,
  layoutMode: 'force',
  colorMode: 'severity',
  engagementColors: () => ({}),
})

const emit = defineEmits<{
  (e: 'node-click', node: GraphNode): void
  (e: 'link-click', link: GraphLink): void
  (e: 'background-click'): void
}>()

const container = ref<HTMLDivElement | null>(null)
let graph: any = null

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#e74c3c',
  high: '#e67e22',
  medium: '#f1c40f',
  low: '#3498db',
  info: '#95a5a6',
}

const MITRE_ABBREVS: Record<string, string> = {
  'reconnaissance': 'RE',
  'resource-development': 'RD',
  'initial-access': 'IA',
  'execution': 'EX',
  'persistence': 'PE',
  'privilege-escalation': 'PR',
  'defense-evasion': 'DE',
  'credential-access': 'CA',
  'discovery': 'DI',
  'lateral-movement': 'LM',
  'collection': 'CO',
  'command-and-control': 'C2',
  'exfiltration': 'EF',
  'impact': 'IM',
}

const KILL_CHAIN_PHASES = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
]

function applyKillChainLayout() {
  if (!graph || !container.value) return
  const width = container.value.clientWidth
  const laneCount = KILL_CHAIN_PHASES.length + 1
  const laneWidth = width / laneCount

  const nodes = graph.graphData().nodes as GraphNode[]
  for (const n of nodes) {
    const phaseIdx = n.phase ? KILL_CHAIN_PHASES.indexOf(n.phase) : -1
    const lane = phaseIdx >= 0 ? phaseIdx : KILL_CHAIN_PHASES.length
    n.fx = laneWidth * lane + laneWidth / 2
  }
  graph.d3ReheatSimulation()
}

function clearKillChainLayout() {
  if (!graph) return
  const nodes = graph.graphData().nodes as GraphNode[]
  for (const n of nodes) {
    n.fx = undefined
  }
  graph.d3ReheatSimulation()
}

function getNodeId(ref: string | GraphNode): string {
  return typeof ref === 'string' ? ref : ref.id
}

function countConnections(nodeId: string): number {
  return props.data.links.filter(
    l => getNodeId(l.source) === nodeId || getNodeId(l.target) === nodeId
  ).length
}

function initGraph() {
  if (!container.value) return

  graph = new ForceGraph(container.value)
    .graphData(props.data)
    .nodeId('id')
    .linkSource('source')
    .linkTarget('target')
    .nodeCanvasObject((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const n = node as GraphNode

      // Time range visibility
      if (props.timeRange && n.created_at) {
        const t = new Date(n.created_at).getTime()
        if (t < props.timeRange.start.getTime() || t > props.timeRange.end.getTime()) {
          return  // Don't render — outside time window
        }
      }

      const connCount = countConnections(n.id)
      const radius = Math.min(4 + connCount * 0.8, 12)
      const color = props.colorMode === 'engagement' && n.engagement_id
        ? (props.engagementColors[n.engagement_id] || '#95a5a6')
        : (SEVERITY_COLORS[n.severity] || '#95a5a6')
      const isSelected = n.id === props.selectedNodeId

      // Pivotality glow
      if (n.pivotality && n.pivotality > 0.1) {
        const glowRadius = radius + 4 + n.pivotality * 8
        ctx.beginPath()
        ctx.arc(node.x, node.y, glowRadius, 0, 2 * Math.PI)
        ctx.fillStyle = `rgba(251, 191, 36, ${n.pivotality * 0.3})`
        ctx.fill()
      }

      // Circle
      ctx.beginPath()
      ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.fill()

      // Selection ring
      if (isSelected) {
        ctx.strokeStyle = '#ffffff'
        ctx.lineWidth = 2 / globalScale
        ctx.stroke()
        ctx.beginPath()
        ctx.arc(node.x, node.y, radius + 1 / globalScale, 0, 2 * Math.PI)
        ctx.strokeStyle = color
        ctx.lineWidth = 1 / globalScale
        ctx.stroke()
      }

      // Severity ring in engagement color mode
      if (props.colorMode === 'engagement') {
        const sevColor = SEVERITY_COLORS[n.severity] || '#95a5a6'
        ctx.beginPath()
        ctx.arc(node.x, node.y, radius + 2 / globalScale, 0, 2 * Math.PI)
        ctx.strokeStyle = sevColor
        ctx.lineWidth = 1.5 / globalScale
        ctx.stroke()
      }

      // Label (visible at medium+ zoom)
      if (globalScale > 1.5) {
        const label = n.name.length > 30 ? n.name.slice(0, 27) + '\u2026' : n.name
        ctx.font = `${10 / globalScale}px sans-serif`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'top'
        ctx.fillStyle = '#666'
        ctx.fillText(label, node.x, node.y + radius + 2 / globalScale)
      }

      // MITRE phase pill (visible at medium+ zoom)
      if (n.phase && globalScale > 2) {
        const abbrev = MITRE_ABBREVS[n.phase] || n.phase.slice(0, 2).toUpperCase()
        const pillX = node.x + radius
        const pillY = node.y - radius
        ctx.font = `bold ${7 / globalScale}px sans-serif`
        const textWidth = ctx.measureText(abbrev).width
        const padding = 2 / globalScale

        ctx.fillStyle = 'rgba(0,0,0,0.6)'
        ctx.beginPath()
        ctx.roundRect(
          pillX - padding,
          pillY - 4 / globalScale - padding,
          textWidth + padding * 2,
          8 / globalScale + padding * 2,
          2 / globalScale
        )
        ctx.fill()

        ctx.fillStyle = '#fff'
        ctx.textAlign = 'left'
        ctx.textBaseline = 'middle'
        ctx.fillText(abbrev, pillX, pillY)
      }
    })
    .nodePointerAreaPaint((node: any, color: string, ctx: CanvasRenderingContext2D) => {
      const connCount = countConnections(node.id)
      const radius = Math.min(4 + connCount * 0.8, 12)
      ctx.beginPath()
      ctx.arc(node.x, node.y, radius + 2, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.fill()
    })
    .linkCanvasObject((link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const l = link as GraphLink
      const src = link.source
      const tgt = link.target
      if (!src.x || !tgt.x) return

      // Hide edges where either endpoint is outside time window
      if (props.timeRange) {
        const srcNode = src as GraphNode
        const tgtNode = tgt as GraphNode
        if (srcNode.created_at) {
          const st = new Date(srcNode.created_at).getTime()
          if (st < props.timeRange.start.getTime() || st > props.timeRange.end.getTime()) return
        }
        if (tgtNode.created_at) {
          const tt = new Date(tgtNode.created_at).getTime()
          if (tt < props.timeRange.start.getTime() || tt > props.timeRange.end.getTime()) return
        }
      }

      const isSelected = l.id === props.selectedLinkId

      // Style by status
      const isConfirmed = l.status === 'auto_confirmed' || l.status === 'user_confirmed'
      const isCandidate = l.status === 'candidate'
      const isRejected = l.status === 'rejected' || l.status === 'user_rejected'

      // Draw path — bezier in kill chain mode, straight in force mode
      ctx.beginPath()
      if (props.layoutMode === 'killchain') {
        const dx = tgt.x - src.x
        const dy = tgt.y - src.y
        const dist = Math.sqrt(dx * dx + dy * dy)
        const midX = (src.x + tgt.x) / 2
        const midY = (src.y + tgt.y) / 2

        ctx.moveTo(src.x, src.y)
        if (Math.abs(dx) < 30) {
          // Intra-lane: arc
          const cpX = midX + dist * 0.3
          ctx.quadraticCurveTo(cpX, midY, tgt.x, tgt.y)
        } else {
          // Inter-lane: bezier
          const cpOffset = Math.min(dist * 0.2, 50)
          ctx.bezierCurveTo(
            src.x + dx * 0.25, src.y - cpOffset,
            tgt.x - dx * 0.25, tgt.y - cpOffset,
            tgt.x, tgt.y
          )
        }
      } else {
        ctx.moveTo(src.x, src.y)
        ctx.lineTo(tgt.x, tgt.y)
      }

      if (isRejected) {
        ctx.strokeStyle = 'rgba(231, 76, 60, 0.4)'
        ctx.setLineDash([4 / globalScale, 4 / globalScale])
        ctx.lineWidth = (isSelected ? 2 : 0.5) / globalScale
      } else if (isCandidate) {
        ctx.strokeStyle = `rgba(100, 100, 100, ${0.3 + l.value * 0.3})`
        ctx.setLineDash([4 / globalScale, 4 / globalScale])
        ctx.lineWidth = (isSelected ? 2 : 1) / globalScale
      } else {
        const opacity = l.status === 'user_confirmed' ? 1 : 0.4 + l.value * 0.6
        ctx.strokeStyle = `rgba(80, 80, 80, ${opacity})`
        ctx.setLineDash([])
        ctx.lineWidth = (isSelected ? 2.5 : l.status === 'user_confirmed' ? 1.5 : 1) / globalScale
      }

      ctx.stroke()
      ctx.setLineDash([])

      // Arrowhead
      const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x)
      const arrowLen = 6 / globalScale
      const tgtConnCount = countConnections(getNodeId(l.target))
      const tgtRadius = Math.min(4 + tgtConnCount * 0.8, 12)
      const endX = tgt.x - Math.cos(angle) * tgtRadius
      const endY = tgt.y - Math.sin(angle) * tgtRadius
      ctx.beginPath()
      ctx.moveTo(endX, endY)
      ctx.lineTo(
        endX - arrowLen * Math.cos(angle - Math.PI / 6),
        endY - arrowLen * Math.sin(angle - Math.PI / 6)
      )
      ctx.lineTo(
        endX - arrowLen * Math.cos(angle + Math.PI / 6),
        endY - arrowLen * Math.sin(angle + Math.PI / 6)
      )
      ctx.closePath()
      ctx.fillStyle = ctx.strokeStyle
      ctx.fill()

      // Drift badge
      if (l.drift) {
        const midX = (src.x + tgt.x) / 2
        const midY = (src.y + tgt.y) / 2
        ctx.font = `${10 / globalScale}px sans-serif`
        ctx.fillStyle = '#f59e0b'
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText('\u25B2', midX, midY)
      }
    })
    .linkPointerAreaPaint((link: any, color: string, ctx: CanvasRenderingContext2D) => {
      const src = link.source
      const tgt = link.target
      if (!src.x || !tgt.x) return
      ctx.beginPath()
      ctx.moveTo(src.x, src.y)
      ctx.lineTo(tgt.x, tgt.y)
      ctx.lineWidth = 8
      ctx.strokeStyle = color
      ctx.stroke()
    })
    .onNodeClick((node: any) => emit('node-click', node))
    .onLinkClick((link: any) => emit('link-click', link))
    .onBackgroundClick(() => emit('background-click'))
    .cooldownTicks(100)
    .warmupTicks(50)
    .onRenderFramePost((ctx: CanvasRenderingContext2D, globalScale: number) => {
      if (props.layoutMode !== 'killchain' || !container.value) return

      const width = container.value.clientWidth
      const height = container.value.clientHeight
      const laneCount = KILL_CHAIN_PHASES.length + 1
      const laneWidth = width / laneCount

      ctx.save()
      ctx.setTransform(1, 0, 0, 1, 0, 0)

      for (let i = 0; i <= laneCount; i++) {
        const x = i * laneWidth
        ctx.beginPath()
        ctx.moveTo(x, 0)
        ctx.lineTo(x, height)
        ctx.strokeStyle = 'rgba(150, 150, 150, 0.2)'
        ctx.setLineDash([4, 4])
        ctx.lineWidth = 1
        ctx.stroke()
        ctx.setLineDash([])

        if (i < KILL_CHAIN_PHASES.length) {
          const label = MITRE_ABBREVS[KILL_CHAIN_PHASES[i]] || KILL_CHAIN_PHASES[i].slice(0, 4)
          ctx.font = '10px sans-serif'
          ctx.fillStyle = 'rgba(150, 150, 150, 0.6)'
          ctx.textAlign = 'center'
          ctx.fillText(label, x + laneWidth / 2, 14)
        } else if (i === KILL_CHAIN_PHASES.length) {
          ctx.font = '10px sans-serif'
          ctx.fillStyle = 'rgba(150, 150, 150, 0.6)'
          ctx.textAlign = 'center'
          ctx.fillText('Other', x + laneWidth / 2, 14)
        }
      }

      ctx.restore()
    })

  // Zoom to fit after initial layout
  setTimeout(() => graph?.zoomToFit(400, 50), 500)
}

function updateData(newData: GraphData) {
  if (!graph) return

  // Preserve positions of existing nodes
  const oldNodes = graph.graphData().nodes as GraphNode[]
  const posMap = new Map<string, { x: number; y: number }>()
  for (const n of oldNodes) {
    if (n.x !== undefined && n.y !== undefined) {
      posMap.set(n.id, { x: n.x, y: n.y })
    }
  }

  for (const n of newData.nodes) {
    const pos = posMap.get(n.id)
    if (pos) {
      n.x = pos.x
      n.y = pos.y
      n.fx = pos.x
      n.fy = pos.y
      // Unpin after short delay to let simulation settle
      setTimeout(() => {
        n.fx = undefined
        n.fy = undefined
      }, 1000)
    }
  }

  graph.graphData(newData)
}

watch(() => props.data, (newData) => {
  if (graph) {
    updateData(newData)
  }
}, { deep: true })

watch(() => props.layoutMode, (mode) => {
  if (mode === 'killchain') {
    applyKillChainLayout()
  } else {
    clearKillChainLayout()
  }
})

onMounted(() => {
  nextTick(() => initGraph())
})

onUnmounted(() => {
  if (graph) {
    graph._destructor?.()
    graph = null
  }
})

function resize() {
  if (graph && container.value) {
    graph.width(container.value.clientWidth)
    graph.height(container.value.clientHeight)
  }
}

defineExpose({ resize })
</script>

<template>
  <div ref="container" class="w-full h-full" />
</template>
