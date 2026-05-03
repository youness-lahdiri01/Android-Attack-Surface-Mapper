import { useState, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import Header from './components/Header.jsx'
import DropZone from './components/DropZone.jsx'
import Sidebar from './components/Sidebar.jsx'
import RiskGauge from './components/RiskGauge.jsx'
import AttackGraph from './components/AttackGraph.jsx'
import FindingsGrid from './components/FindingsGrid.jsx'
import AIPanel from './components/AIPanel.jsx'
import { parseManifest, DEMO_XML } from './lib/parser.js'
import { buildFindings, computeSurfaceScore } from './lib/findings.js'
import { loadAPK } from './lib/apk.js'
import { useTheme } from './hooks/useTheme.js'

function ScanningOverlay() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center gap-6 relative overflow-hidden">
      {/* Background grid */}
      <div
        className="absolute inset-0 opacity-5"
        style={{
          backgroundImage: 'linear-gradient(rgba(0,212,255,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.3) 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />

      {/* Scanner */}
      <div className="relative">
        <motion.div
          className="w-24 h-24 rounded-full border-2 flex items-center justify-center"
          style={{ borderColor: 'rgba(0,212,255,0.3)' }}
          animate={{ rotate: 360 }}
          transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
        >
          <div className="absolute inset-0 rounded-full border-2 border-transparent" style={{ borderTopColor: '#00d4ff', borderRightColor: '#a371f7' }} />
        </motion.div>
        <motion.div
          className="absolute inset-2 rounded-full border border-neon-cyan/20"
          animate={{ scale: [1, 1.1, 1], opacity: [0.5, 1, 0.5] }}
          transition={{ duration: 1.5, repeat: Infinity }}
        />
        <div
          className="absolute inset-6 rounded-full"
          style={{ background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)' }}
        />
      </div>

      <div className="flex flex-col items-center gap-1">
        <div className="text-neon-cyan font-mono font-bold text-sm tracking-widest">
          ANALYZING ATTACK SURFACE
        </div>
        <motion.div
          animate={{ opacity: [0.4, 1, 0.4] }}
          transition={{ duration: 1.2, repeat: Infinity }}
          className="text-t3 text-xs font-mono"
        >
          Parsing manifest and running security checks…
        </motion.div>
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

  useEffect(() => {
    fetch('/config')
      .then(r => r.json())
      .then(d => setAiHasKey(d.hasKey))
      .catch(() => {})
  }, [])

  const runScan = useCallback(async (xml) => {
    if (!xml?.trim()) return
    setIsScanning(true)
    setScanError('')
    try {
      await new Promise(r => setTimeout(r, 120))
      const parsed   = parseManifest(xml)
      const findings = buildFindings(parsed)
      const score    = computeSurfaceScore({ ...parsed, findings })
      setScanState({ parsed, findings, score })
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
      const { xml, apkInfo: info } = await loadAPK(file, () => {})
      setXmlInput(xml)
      setApkInfo(info)
      const parsed   = parseManifest(xml)
      const findings = buildFindings(parsed)
      const score    = computeSurfaceScore({ ...parsed, findings })
      setScanState({ parsed, findings, score })
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

  // ── Pre-scan state ────────────────────────────────────────────────────────────
  if (!scanState && !isScanning) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        <Header scanState={null} onReset={null} aiHasKey={aiHasKey} onToggleTheme={toggleTheme} isDark={isDark} />
        {/* Subtle background grid */}
        <div className="flex-1 flex items-center justify-center p-8 relative overflow-hidden">
          <div
            className="absolute inset-0 opacity-[0.03]"
            style={{
              backgroundImage: 'linear-gradient(rgba(0,212,255,1) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,1) 1px, transparent 1px)',
              backgroundSize: '60px 60px',
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
        <Header scanState={null} onReset={null} aiHasKey={aiHasKey} onToggleTheme={toggleTheme} isDark={isDark} />
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
      />

      <div className="flex flex-1 overflow-hidden">
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
