import { useState, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import Header from './components/Header.jsx'
import DropZone from './components/DropZone.jsx'
import Sidebar from './components/Sidebar.jsx'
import RiskGauge from './components/RiskGauge.jsx'
import AttackGraph from './components/AttackGraph.jsx'
import FindingsGrid from './components/FindingsGrid.jsx'
import AIPanel from './components/AIPanel.jsx'
import HistoryPanel from './components/HistoryPanel.jsx'
import { parseManifest, DEMO_XML } from './lib/parser.js'
import { buildFindings, computeSurfaceScore } from './lib/findings.js'
import { loadAPK } from './lib/apk.js'
import { useTheme } from './hooks/useTheme.js'
import { saveToHistory, loadHistory } from './lib/historyService.js'

const SCAN_STEPS = [
  'Extracting manifest…',
  'Parsing components…',
  'Running security checks…',
  'Computing risk score…',
  'Building attack graph…',
]

function ScanningOverlay() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center gap-8 relative overflow-hidden">
      {/* Subtle grid */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: 'linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px)',
          backgroundSize: '44px 44px',
        }}
      />

      {/* Radial ambient glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: 'radial-gradient(ellipse 55% 55% at 50% 50%, rgba(0,212,255,0.04) 0%, transparent 70%)',
        }}
      />

      {/* Scanner rings */}
      <div className="relative flex items-center justify-center">
        {/* Outer orbit */}
        <motion.div
          className="absolute w-36 h-36 rounded-full border"
          style={{ borderColor: 'rgba(0,212,255,0.1)' }}
          animate={{ rotate: -360 }}
          transition={{ duration: 12, repeat: Infinity, ease: 'linear' }}
        />
        {/* Spinning arc */}
        <motion.div
          className="absolute w-28 h-28 rounded-full"
          style={{
            border: '2px solid transparent',
            borderTopColor: '#00d4ff',
            borderRightColor: '#a371f7',
            filter: 'drop-shadow(0 0 6px rgba(0,212,255,0.5))',
          }}
          animate={{ rotate: 360 }}
          transition={{ duration: 1.8, repeat: Infinity, ease: 'linear' }}
        />
        {/* Pulse ring */}
        <motion.div
          className="absolute w-20 h-20 rounded-full border"
          style={{ borderColor: 'rgba(0,212,255,0.2)' }}
          animate={{ scale: [1, 1.12, 1], opacity: [0.4, 1, 0.4] }}
          transition={{ duration: 1.6, repeat: Infinity, ease: 'easeInOut' }}
        />
        {/* Core */}
        <div
          className="w-12 h-12 rounded-full flex items-center justify-center"
          style={{
            background: 'radial-gradient(circle, rgba(0,212,255,0.15) 0%, rgba(0,212,255,0.04) 70%)',
            border: '1px solid rgba(0,212,255,0.3)',
            boxShadow: '0 0 24px rgba(0,212,255,0.2)',
          }}
        >
          <motion.div
            className="w-2 h-2 rounded-full bg-neon-cyan"
            animate={{ opacity: [0.6, 1, 0.6], scale: [0.9, 1.1, 0.9] }}
            transition={{ duration: 1.2, repeat: Infinity }}
          />
        </div>
      </div>

      {/* Status text */}
      <div className="flex flex-col items-center gap-2">
        <div
          className="text-xs font-mono font-bold tracking-[0.22em] uppercase"
          style={{ color: '#00d4ff', textShadow: '0 0 16px rgba(0,212,255,0.5)' }}
        >
          Analyzing Attack Surface
        </div>
        <motion.div
          key="step"
          animate={{ opacity: [0, 1, 1, 0] }}
          transition={{ duration: 2, repeat: Infinity, times: [0, 0.1, 0.85, 1] }}
          className="text-t3 text-[11px] font-mono"
        >
          Parsing manifest and running security checks…
        </motion.div>
      </div>

      {/* Progress bar */}
      <div
        className="w-48 h-[2px] rounded-full overflow-hidden"
        style={{ background: 'rgba(255,255,255,0.06)' }}
      >
        <motion.div
          className="h-full rounded-full"
          style={{ background: 'linear-gradient(90deg, #00d4ff, #a371f7)', transformOrigin: 'left' }}
          animate={{ scaleX: [0.1, 0.9, 0.2, 0.7, 0.4, 0.95] }}
          transition={{ duration: 2.5, repeat: Infinity, ease: 'easeInOut' }}
        />
      </div>
    </div>
  )
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a   = Object.assign(document.createElement('a'), { href: url, download: filename })
  a.click()
  URL.revokeObjectURL(url)
}

export default function App() {
  const { toggle: toggleTheme, isDark } = useTheme()
  const [scanState,       setScanState]       = useState(null)
  const [xmlInput,        setXmlInput]        = useState('')
  const [isScanning,      setIsScanning]      = useState(false)
  const [scanError,       setScanError]       = useState('')
  const [apkInfo,         setApkInfo]         = useState(null)
  const [selectedFinding, setSelectedFinding] = useState(null)
  const [highlightedNode, setHighlightedNode] = useState(null)
  const [aiPanelOpen,     setAiPanelOpen]     = useState(false)
  const [aiHasKey,        setAiHasKey]        = useState(false)
  const [historyOpen,     setHistoryOpen]     = useState(false)
  const [historyKey,      setHistoryKey]      = useState(0)   // bump to force HistoryPanel re-mount with fresh data

  useEffect(() => {
    fetch('/config')
      .then(r => r.json())
      .then(d => setAiHasKey(d.hasKey))
      .catch(() => {})
  }, [])

  const runScan = useCallback(async (xml, infoOverride) => {
    if (!xml?.trim()) return
    setIsScanning(true)
    setScanError('')
    try {
      await new Promise(r => setTimeout(r, 120))
      const parsed   = parseManifest(xml)
      const findings = buildFindings(parsed)
      const score    = computeSurfaceScore({ ...parsed, findings })
      const state    = { parsed, findings, score }
      setScanState(state)
      saveToHistory(state, infoOverride ?? null)
      setHistoryKey(k => k + 1)
    } catch (err) {
      setScanError(err.message)
    } finally {
      setIsScanning(false)
    }
  }, [])

  const handleXmlScan = useCallback(() => runScan(xmlInput), [xmlInput, runScan])

  const handleAPK = useCallback(async (file) => {
    if (!file?.name.endsWith('.apk')) { setScanError('Please select a .apk file'); return }
    setIsScanning(true)
    setScanError('')
    try {
      const { xml, apkInfo: info, netSec, dexHits, sigInfo, suspiciousAssets } = await loadAPK(file, () => {})
      setXmlInput(xml)
      setApkInfo(info)
      const parsed   = parseManifest(xml)
      const findings = buildFindings({ ...parsed, netSec, dexHits, sigInfo, suspiciousAssets })
      const score    = computeSurfaceScore({ ...parsed, findings })
      const state    = { parsed, findings, score }
      setScanState(state)
      saveToHistory(state, info)
      setHistoryKey(k => k + 1)
    } catch (err) {
      setScanError(err.message)
    } finally {
      setIsScanning(false)
    }
  }, [])

  const loadDemo = useCallback(() => {
    setXmlInput(DEMO_XML)
    runScan(DEMO_XML)
  }, [runScan])

  const resetScan = useCallback(() => {
    setScanState(null)
    setXmlInput('')
    setApkInfo(null)
    setScanError('')
    setSelectedFinding(null)
    setHighlightedNode(null)
    setAiPanelOpen(false)
    setHistoryOpen(false)
  }, [])

  const restoreFromHistory = useCallback((entry) => {
    if (!entry?._scanState) return
    setScanState(entry._scanState)
    setApkInfo(entry._apkInfo ?? null)
    setXmlInput('')
    setSelectedFinding(null)
    setHighlightedNode(null)
    setAiPanelOpen(false)
    setHistoryOpen(false)
  }, [])

  const toggleHistory = useCallback(() => {
    setHistoryOpen(v => !v)
    setAiPanelOpen(false)
  }, [])

  const openAIPanel = useCallback((finding) => {
    setSelectedFinding(finding)
    setAiPanelOpen(true)
  }, [])

  const exportJSON = () => {
    if (!scanState) return
    const { parsed, findings, score } = scanState
    downloadBlob(
      new Blob([JSON.stringify({ package: parsed.pkg, riskScore: score, scannedAt: new Date().toISOString(), appFlags: { debuggable: parsed.debuggable, allowBackup: parsed.allowBackup, clearTextTraffic: parsed.clearTextTraffic, targetSdkVersion: parsed.targetSdk, minSdkVersion: parsed.minSdk }, permissions: parsed.permissions, components: parsed.components, findings }, null, 2)], { type: 'application/json' }),
      `${parsed.pkg}-attack-surface.json`
    )
  }

  const exportCSV = () => {
    if (!scanState) return
    const { findings, parsed } = scanState
    const esc = v => `"${String(v).replace(/"/g, '""')}"`
    const rows = [['severity', 'title', 'body', 'fix'], ...findings.map(f => [f.sev, f.title, f.body, f.fix].map(esc))]
    downloadBlob(
      new Blob([rows.map(r => r.join(',')).join('\n')], { type: 'text/csv' }),
      `${parsed.pkg}-findings.csv`
    )
  }

  const exportMermaid = () => {
    if (!scanState) return
    const { parsed } = scanState
    const { components, pkg } = parsed

    const sid   = name => 'N_' + name.replace(/[^a-zA-Z0-9]/g, '_')
    const short = name => name.split('.').pop()
    const shapeWrap = {
      Activity: n => `["${n}"]`,
      Service:  n => `(["${n}"])`,
      Receiver: n => `{{"${n}"}}`,
      Provider: n => `[("${n}")]`,
    }

    const lines = [
      'graph TD',
      `  %% Package: ${pkg}`,
      `  %% Rectangle=Activity · Stadium=Service · Hexagon=Receiver · Cylinder=Provider`,
      `  %% Red border = exported without permission DANGEROUS`,
      `  %% Solid arrow = exported access · Dashed arrow = deep link`,
      '',
      `  EXT(("External App"))`,
      '',
    ]

    components.forEach(c => {
      const wrap = shapeWrap[c.type] || (n => `["${n}"]`)
      lines.push(`  ${sid(c.name)}${wrap(short(c.name))}`)
    })

    lines.push('')

    components.filter(c => c.inferredExported).forEach(c => {
      const label = c.perm
        ? `"requires: ${c.perm.split('.').pop()}"`
        : `"NO PERMISSION"`
      lines.push(`  EXT -->|${label}| ${sid(c.name)}`)
    })

    components.filter(c => c.schemes.length > 0).forEach(c => {
      c.schemes.forEach(scheme => {
        lines.push(`  EXT -.->|"deeplink: ${scheme}"| ${sid(c.name)}`)
      })
    })

    lines.push('')
    lines.push('  classDef activity fill:#1a3a5c,stroke:#58a6ff,color:#c9d1d9')
    lines.push('  classDef service  fill:#2d1b69,stroke:#a371f7,color:#c9d1d9')
    lines.push('  classDef receiver fill:#3d2200,stroke:#d29922,color:#c9d1d9')
    lines.push('  classDef provider fill:#3a0f0f,stroke:#ff3b5c,color:#c9d1d9')
    lines.push('  classDef danger   stroke:#ff3b5c,stroke-width:3px,fill:#5a1a1a,color:#ffaaaa')
    lines.push('  classDef external fill:#0f3d0f,stroke:#3fb950,color:#c9d1d9')
    lines.push('')

    const byType = {}
    components.forEach(c => {
      const cls = c.type.toLowerCase()
      if (!byType[cls]) byType[cls] = []
      byType[cls].push(sid(c.name))
    })
    Object.entries(byType).forEach(([cls, ids]) => {
      lines.push(`  class ${ids.join(',')} ${cls}`)
    })
    lines.push('  class EXT external')

    const dangerous = components.filter(c => c.inferredExported && !c.perm).map(c => sid(c.name))
    if (dangerous.length) lines.push(`  class ${dangerous.join(',')} danger`)

    downloadBlob(
      new Blob([lines.join('\n')], { type: 'text/plain' }),
      `${pkg}-attack-graph.mmd`
    )
  }

  // ── History view (can be opened from any state) ───────────────────────────────
  const historyCount = loadHistory().length

  if (historyOpen) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        <Header
          scanState={scanState}
          onReset={scanState ? resetScan : null}
          apkInfo={apkInfo}
          aiHasKey={aiHasKey}
          onToggleTheme={toggleTheme}
          isDark={isDark}
          onToggleHistory={toggleHistory}
          historyActive={true}
          historyCount={historyCount}
        />
        <HistoryPanel
          key={historyKey}
          initialHistory={loadHistory()}
          onRestore={restoreFromHistory}
          onClose={toggleHistory}
        />
      </div>
    )
  }

  // ── Pre-scan state ────────────────────────────────────────────────────────────
  if (!scanState && !isScanning) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        <Header
          scanState={null}
          onReset={null}
          aiHasKey={aiHasKey}
          onToggleTheme={toggleTheme}
          isDark={isDark}
          onToggleHistory={toggleHistory}
          historyActive={false}
          historyCount={historyCount}
        />
        <div className="flex-1 flex items-center justify-center p-8 relative overflow-hidden">
          {/* Layered grid + ambient glow */}
          <div
            className="absolute inset-0"
            style={{
              backgroundImage: 'linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px)',
              backgroundSize: '56px 56px',
            }}
          />
          <div
            className="absolute inset-0 pointer-events-none"
            style={{
              background: 'radial-gradient(ellipse 70% 60% at 50% 40%, rgba(0,212,255,0.04) 0%, transparent 70%)',
            }}
          />
          <DropZone
            xmlInput={xmlInput}
            onXmlChange={setXmlInput}
            onAPK={handleAPK}
            onScan={handleXmlScan}
            onDemo={loadDemo}
            error={scanError}
            isScanning={isScanning}
          />
        </div>
      </div>
    )
  }

  // ── Scanning state ────────────────────────────────────────────────────────────
  if (isScanning) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        <Header
          scanState={null}
          onReset={null}
          aiHasKey={aiHasKey}
          onToggleTheme={toggleTheme}
          isDark={isDark}
          onToggleHistory={toggleHistory}
          historyActive={false}
          historyCount={historyCount}
        />
        <ScanningOverlay />
      </div>
    )
  }

  // ── Dashboard state ───────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Header
        scanState={scanState}
        onReset={resetScan}
        apkInfo={apkInfo}
        aiHasKey={aiHasKey}
        onExportJSON={exportJSON}
        onExportCSV={exportCSV}
        onExportMermaid={exportMermaid}
        onToggleTheme={toggleTheme}
        isDark={isDark}
        onToggleHistory={toggleHistory}
        historyActive={false}
        historyCount={historyCount}
      />

      <div
        className="flex flex-1 overflow-hidden"
        style={{
          background: 'var(--color-bg)',
          backgroundImage: `
            radial-gradient(ellipse 60% 50% at 25% 45%, rgba(0,212,255,0.025) 0%, transparent 70%),
            radial-gradient(ellipse 40% 40% at 75% 55%, rgba(163,113,247,0.018) 0%, transparent 65%)
          `,
        }}
      >
        {/* Left: Components sidebar */}
        <Sidebar
          scanState={scanState}
          highlightedNode={highlightedNode}
          onHighlight={setHighlightedNode}
        />

        {/* Center + Right */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="flex flex-1 gap-3 p-3 overflow-hidden">
            {/* Center: Risk gauge */}
            <RiskGauge scanState={scanState} />

            {/* Right: Attack graph */}
            <AttackGraph
              scanState={scanState}
              highlightedNode={highlightedNode}
              onHighlight={setHighlightedNode}
              isDark={isDark}
            />
          </div>

          {/* Bottom: Findings */}
          <FindingsGrid
            findings={scanState.findings}
            onSelectFinding={openAIPanel}
            onHighlightComponent={setHighlightedNode}
            aiHasKey={aiHasKey}
          />
        </div>
      </div>

      {/* AI Panel overlay */}
      <AnimatePresence>
        {aiPanelOpen && (
          <AIPanel
            finding={selectedFinding}
            scanState={scanState}
            onClose={() => setAiPanelOpen(false)}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
