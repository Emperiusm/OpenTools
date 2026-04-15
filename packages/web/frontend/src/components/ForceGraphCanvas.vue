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

const props = defineProps<{
  data: GraphData
  selectedNodeId: string | null
  selectedLinkId: string | null
  highlightedNodeIds: string[]
}>()

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
      const connCount = countConnections(n.id)
      const radius = Math.min(4 + connCount * 0.8, 12)
      const color = SEVERITY_COLORS[n.severity] || '#95a5a6'
      const isSelected = n.id === props.selectedNodeId
      const isHighlighted = props.highlightedNodeIds.includes(n.id)

      // Highlight glow (from query results)
      if (isHighlighted) {
        ctx.save()
        ctx.shadowColor = '#FFD700'
        ctx.shadowBlur = 8 / globalScale
        ctx.beginPath()
        ctx.arc(node.x, node.y, radius + 2 / globalScale, 0, 2 * Math.PI)
        ctx.fillStyle = 'rgba(255, 215, 0, 0.3)'
        ctx.fill()
        ctx.restore()
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

      const isSelected = l.id === props.selectedLinkId

      // Style by status
      const isConfirmed = l.status === 'auto_confirmed' || l.status === 'user_confirmed'
      const isCandidate = l.status === 'candidate'
      const isRejected = l.status === 'rejected' || l.status === 'user_rejected'

      ctx.beginPath()
      ctx.moveTo(src.x, src.y)
      ctx.lineTo(tgt.x, tgt.y)

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

watch(() => props.highlightedNodeIds, () => {
  if (graph) {
    graph.refresh()
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
