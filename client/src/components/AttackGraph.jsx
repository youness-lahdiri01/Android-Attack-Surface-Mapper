import { useEffect, useRef, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import * as d3 from 'd3'
import { Network, ZoomIn, ZoomOut, Maximize2, X, Lock, Unlock, Wifi } from 'lucide-react'
import { calcComponentRisk, riskLevel } from '../lib/parser.js'

const TYPE_COLOR = {
  Activity: '#58a6ff',
  Service:  '#a371f7',
  Receiver: '#d29922',
  Provider: '#ff3b5c',
  app:      '#00d4ff',
}

const TYPE_LABEL = { Activity: 'A', Service: 'S', Receiver: 'R', Provider: 'P', app: '⬡' }
const SEV_COLOR  = { critical: '#ff3b5c', high: '#ff9500', medium: '#ffd60a', low: '#3fb950' }

function buildGraphData(scanState) {
  const { parsed } = scanState
  const nodes = [
    { id: '__app__', label: parsed.pkg.split('.').pop(), type: 'app', risk: 0, exported: false },
    ...parsed.components.map(c => ({
      id: c.name,
      label: c.name.replace(/^.*\./, ''),
      type: c.type,
      risk: calcComponentRisk(c),
      exported: c.inferredExported,
      perm: c.perm,
      actions: c.actions,
      schemes: c.schemes,
      component: c,
    })),
  ]

  const seen  = new Set()
  const links = []

  parsed.components.forEach(c => {
    if (c.inferredExported) {
      const k = `__app__→${c.name}`
      if (!seen.has(k)) {
        seen.add(k)
        links.push({ source: '__app__', target: c.name, type: 'exposed', dangerous: !c.perm })
      }
    }
    c.actions.slice(0, 1).forEach(() => {
      const k = `${c.name}→__app__`
      if (!seen.has(k)) {
        seen.add(k)
        links.push({ source: c.name, target: '__app__', type: 'intent', dangerous: false })
      }
    })
    if (c.schemes.length > 0 && c.inferredExported) {
      const k = `deeplink→${c.name}`
      if (!seen.has(k)) {
        seen.add(k)
        links.push({ source: c.name, target: '__app__', type: 'deeplink', dangerous: true, label: c.schemes[0] + '://' })
      }
    }
  })

  return { nodes, links }
}

function getConnectedIds(selectedId, links) {
  const ids = new Set([selectedId])
  links.forEach(l => {
    const s = typeof l.source === 'object' ? l.source.id : l.source
    const t = typeof l.target === 'object' ? l.target.id : l.target
    if (s === selectedId) ids.add(t)
    if (t === selectedId) ids.add(s)
  })
  return ids
}

function pulsate(sel) {
  if (sel.empty()) return
  sel.each(function() {
    const el = d3.select(this)
    const baseR = +el.attr('data-base-r') || 24
    function run() {
      el.attr('r', baseR).attr('opacity', 0.5)
        .transition().duration(1400).ease(d3.easeSinInOut)
        .attr('r', baseR + 10).attr('opacity', 0)
        .on('end', run)
    }
    run()
  })
}

// Curved path between two nodes
function makePath(d) {
  const sx = d.source.x, sy = d.source.y
  const tx = d.target.x, ty = d.target.y
  if (d.type === 'exposed') return `M${sx},${sy}L${tx},${ty}`
  const mx = (sx + tx) / 2 + (ty - sy) * 0.25
  const my = (sy + ty) / 2 - (tx - sx) * 0.25
  return `M${sx},${sy}Q${mx},${my},${tx},${ty}`
}

export default function AttackGraph({ scanState, highlightedNode, onHighlight }) {
  const svgRef    = useRef(null)
  const zoomRef   = useRef(null)
  const nodesRef  = useRef(null)
  const linksRef  = useRef(null)
  const linksData = useRef([])
  const [tooltip, setTooltip] = useState(null)
  const [focusInfo, setFocusInfo] = useState(null)

  useEffect(() => {
    if (!scanState || !svgRef.current) return

    const { nodes, links } = buildGraphData(scanState)
    linksData.current = links
    const el    = svgRef.current
    const width  = el.clientWidth  || 600
    const height = el.clientHeight || 400

    const svg = d3.select(el)
    svg.selectAll('*').remove()

    /* ── Defs ─────────────────────────────────────────────────── */
    const defs = svg.append('defs')

    // Glow filters
    const addGlow = (id, color, blur = 4) => {
      const f = defs.append('filter').attr('id', id)
        .attr('x', '-60%').attr('y', '-60%').attr('width', '220%').attr('height', '220%')
      f.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', blur).attr('result', 'blur')
      const m = f.append('feMerge')
      m.append('feMergeNode').attr('in', 'blur')
      m.append('feMergeNode').attr('in', 'SourceGraphic')
    }
    Object.entries(TYPE_COLOR).forEach(([type, color]) => addGlow(`glow-${type}`, color, type === 'app' ? 7 : 3))
    addGlow('glow-critical', '#ff3b5c', 8)

    // Arrow markers per edge type
    const addMarker = (id, color, refX = 20) => {
      defs.append('marker').attr('id', id)
        .attr('viewBox', '0 -4 8 8').attr('refX', refX).attr('refY', 0)
        .attr('markerWidth', 5).attr('markerHeight', 5).attr('orient', 'auto')
        .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', color)
    }
    addMarker('arrow-exposed',  'rgba(255,59,92,0.6)')
    addMarker('arrow-intent',   'rgba(88,166,255,0.5)')
    addMarker('arrow-deeplink', 'rgba(210,153,34,0.7)')

    /* ── Subtle grid background ───────────────────────────────── */
    const gridSize = 40
    const gridG = svg.append('g').attr('class', 'grid').attr('pointer-events', 'none')
    for (let x = 0; x < width; x += gridSize)
      gridG.append('line').attr('x1', x).attr('y1', 0).attr('x2', x).attr('y2', height)
        .attr('stroke', 'rgba(255,255,255,0.018)').attr('stroke-width', 0.5)
    for (let y = 0; y < height; y += gridSize)
      gridG.append('line').attr('x1', 0).attr('y1', y).attr('x2', width).attr('y2', y)
        .attr('stroke', 'rgba(255,255,255,0.018)').attr('stroke-width', 0.5)

    /* ── Zoom ─────────────────────────────────────────────────── */
    const zoom = d3.zoom().scaleExtent([0.25, 4])
      .on('zoom', e => g.attr('transform', e.transform))
    zoomRef.current = zoom
    svg.call(zoom)
    svg.on('click.deselect', () => { onHighlight(null); setFocusInfo(null) })

    const g = svg.append('g')

    /* ── Force simulation ─────────────────────────────────────── */
    const sim = d3.forceSimulation(nodes)
      .force('link',  d3.forceLink(links).id(d => d.id).distance(d => d.type === 'exposed' ? 130 : 100))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(36))

    /* ── Links (paths for curves) ─────────────────────────────── */
    const linkG = g.append('g')
    const link = linkG.selectAll('path')
      .data(links).join('path')
      .attr('fill', 'none')
      .attr('stroke-width', d => d.type === 'exposed' ? 1.5 : 1)
      .attr('stroke', d =>
        d.type === 'exposed' && d.dangerous ? 'rgba(255,59,92,0.55)'
        : d.type === 'exposed'              ? 'rgba(255,149,0,0.45)'
        : d.type === 'deeplink'             ? 'rgba(210,153,34,0.5)'
        :                                     'rgba(88,166,255,0.3)')
      .attr('stroke-dasharray', d => d.type === 'exposed' ? '7 3' : d.type === 'deeplink' ? '3 3' : '5 5')
      .attr('class', d =>
        d.type === 'exposed' && d.dangerous ? 'edge-critical'
        : d.type === 'exposed'              ? 'edge-exposed'
        : d.type === 'deeplink'             ? 'edge-deeplink'
        :                                     'edge-intent')
      .attr('marker-end', d =>
        d.type === 'exposed'  ? 'url(#arrow-exposed)'
        : d.type === 'deeplink' ? 'url(#arrow-deeplink)'
        :                         'url(#arrow-intent)')

    linksRef.current = link

    /* ── Nodes ────────────────────────────────────────────────── */
    const node = g.append('g').selectAll('g')
      .data(nodes).join('g')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y })
        .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null })
      )
      .on('click', (e, d) => {
        e.stopPropagation()
        const newId = d.id === '__app__' ? null : d.id
        onHighlight(newId === highlightedNode ? null : newId)
        setFocusInfo(newId ? d : null)
      })
      .on('mouseover', (e, d) => {
        const rect = el.getBoundingClientRect()
        setTooltip({ x: e.clientX - rect.left, y: e.clientY - rect.top, node: d })
      })
      .on('mouseout', () => setTooltip(null))

    nodesRef.current = node

    // Pulse ring for critical unguarded exported nodes
    const criticalNodes = node.filter(d => d.exported && !d.perm && d.type !== 'app')
    criticalNodes.append('circle')
      .attr('r', 22).attr('data-base-r', 22)
      .attr('fill', 'none')
      .attr('stroke', '#ff3b5c')
      .attr('stroke-width', 1)
      .attr('pointer-events', 'none')
      .call(pulsate)

    // Outer ring for all exported nodes
    node.filter(d => d.exported || d.type === 'app')
      .append('circle')
      .attr('r', d => d.type === 'app' ? 30 : 22)
      .attr('fill', 'none')
      .attr('stroke', d => TYPE_COLOR[d.type])
      .attr('stroke-width', 1)
      .attr('opacity', 0.25)
      .attr('stroke-dasharray', '3 3')
      .attr('pointer-events', 'none')

    // Main circle
    node.append('circle')
      .attr('r', d => d.type === 'app' ? 22 : Math.max(14, 10 + d.risk * 0.08))
      .attr('fill', d => TYPE_COLOR[d.type] + '1a')
      .attr('stroke', d => TYPE_COLOR[d.type])
      .attr('stroke-width', d => d.type === 'app' ? 2 : d.exported ? 1.5 : 1)
      .attr('stroke-opacity', d => d.type === 'app' ? 1 : d.exported ? 0.9 : 0.4)
      .attr('filter', d => `url(#glow-${d.type})`)

    // Type letter
    node.append('text')
      .text(d => TYPE_LABEL[d.type] || d.type[0])
      .attr('text-anchor', 'middle').attr('dy', '0.1em')
      .attr('font-size', d => d.type === 'app' ? '14px' : '10px')
      .attr('font-family', 'JetBrains Mono, monospace').attr('font-weight', '700')
      .attr('fill', d => TYPE_COLOR[d.type]).attr('pointer-events', 'none')

    // Label below node
    node.append('text')
      .text(d => d.label.length > 10 ? d.label.slice(0, 10) + '…' : d.label)
      .attr('text-anchor', 'middle')
      .attr('y', d => d.type === 'app' ? 36 : 28)
      .attr('font-size', '8px').attr('font-family', 'JetBrains Mono, monospace')
      .attr('fill', 'rgba(255,255,255,0.4)').attr('pointer-events', 'none')

    /* ── Tick ─────────────────────────────────────────────────── */
    sim.on('tick', () => {
      link.attr('d', makePath)
      node.attr('transform', d => `translate(${d.x ?? 0},${d.y ?? 0})`)
    })

    return () => { sim.stop(); svg.on('click.deselect', null) }
  }, [scanState])

  /* ── Focus effect (highlight + dim) ─────────────────────────── */
  useEffect(() => {
    const nodesSel = nodesRef.current
    const linksSel = linksRef.current
    if (!nodesSel || !linksSel) return

    const ld = linksData.current
    if (!highlightedNode) {
      nodesSel.transition().duration(200).attr('opacity', 1)
      linksSel.transition().duration(200).attr('opacity', 1)
      return
    }

    const connected = getConnectedIds(highlightedNode, ld)
    nodesSel.transition().duration(200)
      .attr('opacity', d => connected.has(d.id) ? 1 : 0.1)
    linksSel.transition().duration(200)
      .attr('opacity', d => {
        const s = typeof d.source === 'object' ? d.source.id : d.source
        const t = typeof d.target === 'object' ? d.target.id : d.target
        return s === highlightedNode || t === highlightedNode ? 1 : 0.04
      })
  }, [highlightedNode])

  const handleZoom = factor => {
    if (!svgRef.current || !zoomRef.current) return
    d3.select(svgRef.current).transition().duration(250).call(zoomRef.current.scaleBy, factor)
  }
  const handleFit = () => {
    if (!svgRef.current || !zoomRef.current) return
    d3.select(svgRef.current).transition().duration(350).call(zoomRef.current.transform, d3.zoomIdentity)
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.2 }}
      className="flex-1 relative rounded-xl border border-b1 overflow-hidden"
      style={{ background: 'rgba(13,17,23,0.9)' }}
    >
      {/* Header bar */}
      <div
        className="absolute top-0 left-0 right-0 flex items-center justify-between px-3 py-2 z-10"
        style={{ background: 'rgba(13,17,23,0.8)', backdropFilter: 'blur(8px)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      >
        <div className="flex items-center gap-2">
          <Network size={11} className="text-neon-cyan" />
          <span className="text-[10px] font-mono text-t3 tracking-widest">ATTACK GRAPH</span>
          {highlightedNode && (
            <motion.span
              initial={{ opacity: 0, x: -6 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono"
              style={{ background: 'rgba(0,212,255,0.12)', border: '1px solid rgba(0,212,255,0.3)', color: '#00d4ff' }}
            >
              FOCUSED
              <button onClick={() => { onHighlight(null); setFocusInfo(null) }} className="ml-1 opacity-60 hover:opacity-100">
                <X size={8} />
              </button>
            </motion.span>
          )}
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3">
          {Object.entries(TYPE_COLOR).filter(([k]) => k !== 'app').map(([type, color]) => (
            <div key={type} className="flex items-center gap-1">
              <div className="w-1.5 h-1.5 rounded-full" style={{ background: color, boxShadow: `0 0 4px ${color}` }} />
              <span className="text-[9px] font-mono text-t3">{type}</span>
            </div>
          ))}
          <div className="w-px h-3 bg-b1 mx-0.5" />
          <div className="flex items-center gap-1">
            <div className="w-3 border-t border-dashed" style={{ borderColor: 'rgba(255,59,92,0.6)' }} />
            <span className="text-[9px] font-mono text-t3">exposed</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 border-t border-dashed" style={{ borderColor: 'rgba(88,166,255,0.5)' }} />
            <span className="text-[9px] font-mono text-t3">intent</span>
          </div>
        </div>

        {/* Zoom controls */}
        <div className="flex items-center gap-1">
          <button onClick={() => handleZoom(1.3)} className="p-1 rounded glass-light text-t3 hover:text-t1 transition-colors"><ZoomIn size={11} /></button>
          <button onClick={() => handleZoom(0.77)} className="p-1 rounded glass-light text-t3 hover:text-t1 transition-colors"><ZoomOut size={11} /></button>
          <button onClick={handleFit} className="p-1 rounded glass-light text-t3 hover:text-t1 transition-colors"><Maximize2 size={11} /></button>
        </div>
      </div>

      <svg ref={svgRef} className="w-full h-full" style={{ cursor: 'grab' }} />

      {/* Rich tooltip */}
      <AnimatePresence>
        {tooltip && (
          <motion.div
            key="tooltip"
            initial={{ opacity: 0, scale: 0.9, y: 4 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9 }}
            transition={{ duration: 0.1 }}
            className="absolute pointer-events-none z-20"
            style={{ left: tooltip.x + 14, top: tooltip.y - 8 }}
          >
            <div
              className="rounded-lg p-2.5 min-w-[160px]"
              style={{ background: '#1c2128', border: `1px solid ${TYPE_COLOR[tooltip.node.type]}40`, boxShadow: `0 8px 32px rgba(0,0,0,0.5), 0 0 16px ${TYPE_COLOR[tooltip.node.type]}20` }}
            >
              <div className="flex items-center gap-1.5 mb-1.5">
                <div className="w-2 h-2 rounded-full" style={{ background: TYPE_COLOR[tooltip.node.type], boxShadow: `0 0 6px ${TYPE_COLOR[tooltip.node.type]}` }} />
                <span className="text-[10px] font-mono font-bold" style={{ color: TYPE_COLOR[tooltip.node.type] }}>
                  {tooltip.node.type === 'app' ? 'Application Root' : tooltip.node.type}
                </span>
              </div>
              <div className="text-[11px] font-mono text-t1 mb-1.5">{tooltip.node.label}</div>
              {tooltip.node.type !== 'app' && (
                <div className="flex flex-col gap-0.5">
                  <div className="flex items-center gap-1 text-[9px] font-mono">
                    {tooltip.node.exported
                      ? <><Unlock size={8} className="text-neon-red" /><span className="text-neon-red">Exported — any app can invoke</span></>
                      : <><Lock size={8} className="text-neon-green" /><span className="text-t3">Private component</span></>
                    }
                  </div>
                  {tooltip.node.perm && (
                    <div className="flex items-center gap-1 text-[9px] font-mono text-neon-green">
                      <Lock size={8} />Permission: {tooltip.node.perm.split('.').pop()}
                    </div>
                  )}
                  {tooltip.node.exported && !tooltip.node.perm && (
                    <div className="text-[9px] font-mono text-neon-red font-bold">⚠ No permission guard</div>
                  )}
                  {tooltip.node.schemes?.length > 0 && (
                    <div className="flex items-center gap-1 text-[9px] font-mono" style={{ color: '#d29922' }}>
                      <Wifi size={8} />Deeplink: {tooltip.node.schemes.join(', ')}://
                    </div>
                  )}
                  {tooltip.node.risk > 0 && (
                    <div className="mt-1 pt-1" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                      <div className="flex items-center justify-between text-[9px] font-mono">
                        <span className="text-t3">Risk</span>
                        <span style={{ color: SEV_COLOR[riskLevel(tooltip.node.risk)] }}>{tooltip.node.risk}/100</span>
                      </div>
                      <div className="mt-0.5 h-1 rounded-full bg-white/5 overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${tooltip.node.risk}%`, background: SEV_COLOR[riskLevel(tooltip.node.risk)] }} />
                      </div>
                    </div>
                  )}
                </div>
              )}
              <div className="mt-1.5 text-[8px] font-mono text-t3 italic">Click to focus connections</div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {scanState && scanState.parsed.components.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-t3 text-xs font-mono">
          No components to display
        </div>
      )}
    </motion.div>
  )
}
