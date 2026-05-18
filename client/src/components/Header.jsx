import {
  Shield, RotateCcw, FileJson, FileText, Cpu, Sun, Moon,
  GitBranch, History, ChevronDown,
} from 'lucide-react'
import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useTheme } from '../hooks/useTheme.js'

const SEV_COLOR = { critical: '#ff3b5c', high: '#ff9500', medium: '#ffd60a', low: '#3fb950' }

function ExportMenu({ onExportJSON, onExportCSV, onExportMermaid }) {
  const [open, setOpen] = useState(false)
  const { isDark } = useTheme()

  // Solid, high-contrast background regardless of theme
  const dropBg     = isDark ? 'rgba(13,17,24,0.98)' : 'rgba(255,255,255,0.99)'
  const dropBorder = isDark ? 'rgba(255,255,255,0.13)' : 'rgba(0,0,0,0.14)'
  const dropShadow = isDark
    ? '0 20px 60px rgba(0,0,0,0.7), 0 4px 16px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.05)'
    : '0 20px 60px rgba(0,0,0,0.18), 0 4px 16px rgba(0,0,0,0.09), inset 0 1px 0 rgba(255,255,255,0.8)'
  const dividerColor = isDark ? 'rgba(255,255,255,0.07)' : 'rgba(0,0,0,0.07)'
  const labelColor   = isDark ? 'rgba(255,255,255,0.3)' : 'rgba(0,0,0,0.35)'
  const itemTextColor = isDark ? '#e6edf3' : '#1c2128'
  const itemDescColor = isDark ? 'rgba(255,255,255,0.35)' : 'rgba(0,0,0,0.4)'
  const itemHoverBg   = isDark ? 'rgba(255,255,255,0.07)' : 'rgba(0,0,0,0.055)'

  const ITEMS = [
    { icon: FileJson,  label: 'JSON Report',   desc: 'Full scan data',  color: '#58a6ff', fn: onExportJSON },
    { icon: FileText,  label: 'CSV Findings',  desc: 'Findings table',  color: '#a371f7', fn: onExportCSV },
    { icon: GitBranch, label: 'Mermaid Graph', desc: 'Attack diagram',  color: '#00d4ff', fn: onExportMermaid },
  ]

  return (
    <div className="relative">
      <motion.button
        onClick={() => setOpen(v => !v)}
        whileHover={{ scale: 1.04 }}
        whileTap={{ scale: 0.96 }}
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-mono glass-light border border-b1 btn-shimmer"
        style={{
          color:      open ? 'var(--color-t1)' : 'var(--color-t2)',
          transition: 'color 0.15s ease',
        }}
      >
        <FileJson size={11} />
        Export
        <motion.div
          animate={{ rotate: open ? 180 : 0 }}
          transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
          style={{ opacity: 0.65, display: 'flex', alignItems: 'center' }}
        >
          <ChevronDown size={10} />
        </motion.div>
      </motion.button>

      <AnimatePresence>
        {open && (
          <>
            <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
            <motion.div
              initial={{ opacity: 0, y: -10, scale: 0.94 }}
              animate={{ opacity: 1,  y: 0,  scale: 1 }}
              exit={{   opacity: 0,  y: -10, scale: 0.94 }}
              transition={{ duration: 0.17, ease: [0.16, 1, 0.3, 1] }}
              className="absolute top-full mt-2 right-0 z-50 flex flex-col rounded-xl min-w-[185px]"
              style={{
                background:     dropBg,
                border:         `1px solid ${dropBorder}`,
                boxShadow:      dropShadow,
                backdropFilter: 'blur(24px)',
                WebkitBackdropFilter: 'blur(24px)',
                padding:        '6px',
              }}
            >
              {/* Section label */}
              <div
                className="px-2.5 py-1.5 mb-1"
                style={{ borderBottom: `1px solid ${dividerColor}` }}
              >
                <span
                  className="text-[9px] font-mono font-semibold tracking-[0.16em] uppercase"
                  style={{ color: labelColor }}
                >
                  Export as
                </span>
              </div>

              {ITEMS.map(({ icon: Icon, label, desc, color, fn }) => (
                <button
                  key={label}
                  onClick={() => { fn(); setOpen(false) }}
                  className="flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-left transition-colors duration-100"
                  style={{ color: itemTextColor }}
                  onMouseEnter={e => e.currentTarget.style.background = itemHoverBg}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  {/* Icon container */}
                  <div
                    className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
                    style={{
                      background: color + '18',
                      border:     `1px solid ${color}30`,
                    }}
                  >
                    <Icon size={12} style={{ color }} />
                  </div>

                  {/* Labels */}
                  <div className="min-w-0 flex-1">
                    <div className="text-[11px] font-mono font-semibold leading-tight">{label}</div>
                    <div className="text-[9px] font-mono leading-tight mt-0.5" style={{ color: itemDescColor }}>
                      {desc}
                    </div>
                  </div>
                </button>
              ))}
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function Header({
  scanState, onReset, apkInfo,
  onExportJSON, onExportCSV, onExportMermaid,
  onToggleTheme, isDark,
  onToggleHistory, historyActive, historyCount,
}) {
  const score = scanState?.score ?? null

  const scoreColor = score === null ? '#58a6ff'
    : score >= 80 ? '#ff3b5c'
    : score >= 60 ? '#ff9500'
    : score >= 30 ? '#ffd60a'
    : '#3fb950'

  const riskLabel = score === null ? null
    : score >= 80 ? 'CRITICAL'
    : score >= 60 ? 'HIGH RISK'
    : score >= 30 ? 'MEDIUM'
    : 'LOW RISK'

  return (
    <header
      className="flex items-center gap-2 px-4 py-2 glass border-b border-b1 z-10 flex-shrink-0"
      style={{ minHeight: 44 }}
    >
      {/* ── Logo ──────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 mr-1 flex-shrink-0">
        <div className="relative">
          <Shield size={20} className="text-neon-cyan" />
          <div className="absolute inset-0 blur-sm opacity-50" style={{ color: '#00d4ff' }}>
            <Shield size={20} />
          </div>
        </div>
        <div className="leading-none">
          <div className="text-t1 font-mono font-bold text-sm tracking-wide">AASM</div>
          <div className="text-t3 text-[8px] font-mono tracking-[0.16em] mt-0.5">ATTACK SURFACE MAPPER</div>
        </div>
      </div>

      {/* Divider */}
      <div className="w-px h-5 bg-b1 mx-1 flex-shrink-0" />

      {/* ── Active scan info ───────────────────────────────────────── */}
      {scanState && (
        <motion.div
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          className="flex items-center gap-1.5 min-w-0"
        >
          <span
            className="px-2 py-1 rounded-md text-[11px] font-mono text-t2 border border-b1 truncate max-w-[220px]"
            style={{ background: 'var(--color-b2)' }}
            title={scanState.parsed.pkg}
          >
            {scanState.parsed.pkg}
          </span>
          {apkInfo && (
            <span className="hidden lg:flex items-center gap-1 text-[10px] font-mono text-t3 glass-light px-2 py-1 rounded-md border border-b1">
              <Cpu size={9} className="text-neon-purple flex-shrink-0" />
              <span className="truncate max-w-[120px]">{apkInfo.fileName}</span>
              <span className="text-t3 opacity-60">·</span>
              <span>{apkInfo.fileSize}</span>
            </span>
          )}
        </motion.div>
      )}

      <div className="flex-1" />

      {/* ── Risk badge ────────────────────────────────────────────── */}
      {score !== null && (
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono font-bold border flex-shrink-0"
          style={{
            color:       scoreColor,
            borderColor: scoreColor + '45',
            background:  scoreColor + '12',
            boxShadow:   `0 0 14px ${scoreColor}28`,
          }}
        >
          <span style={{ color: scoreColor }}>{score}</span>
          <span className="text-t3 font-normal">/100</span>
          <span className="ml-0.5">{riskLabel}</span>
        </motion.div>
      )}

      {/* ── Severity chips ────────────────────────────────────────── */}
      {scanState && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="flex items-center gap-1 flex-shrink-0"
        >
          {['critical', 'high', 'medium'].map(sev => {
            const count = scanState.findings.filter(f => f.sev === sev).length
            if (!count) return null
            return (
              <span
                key={sev}
                className="px-1.5 py-0.5 rounded-md text-[10px] font-mono font-bold"
                style={{ color: SEV_COLOR[sev], background: SEV_COLOR[sev] + '18' }}
              >
                {count} {sev.slice(0, 4).toUpperCase()}
              </span>
            )
          })}
        </motion.div>
      )}

      {/* ── Export dropdown ───────────────────────────────────────── */}
      {scanState && (
        <ExportMenu
          onExportJSON={onExportJSON}
          onExportCSV={onExportCSV}
          onExportMermaid={onExportMermaid}
        />
      )}

      {/* ── History toggle ─────────────────────────────────────────
           Wrapper div owns `relative` so the badge sits outside the
           btn-shimmer button (which has overflow:hidden, clipping badges) */}
      <div className="relative flex-shrink-0">
        <motion.button
          onClick={onToggleHistory}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.94 }}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-mono transition-all duration-150 btn-shimmer"
          style={{
            color:      historyActive ? '#00d4ff' : 'var(--color-t2)',
            background: historyActive ? 'rgba(0,212,255,0.1)' : 'transparent',
            border:     `1px solid ${historyActive ? 'rgba(0,212,255,0.35)' : 'var(--color-b1)'}`,
            boxShadow:  historyActive ? '0 0 14px rgba(0,212,255,0.18)' : 'none',
          }}
          title="Scan history"
        >
          <History size={11} />
          History
        </motion.button>

        {/* Badge sits on the wrapper, not the overflow:hidden button */}
        <AnimatePresence>
          {historyCount > 0 && !historyActive && (
            <motion.span
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{   scale: 0, opacity: 0 }}
              transition={{ type: 'spring', stiffness: 500, damping: 22 }}
              className="absolute -top-2 -right-2 z-10 flex items-center justify-center pointer-events-none"
              style={{
                minWidth:   20,
                height:     20,
                padding:    '0 5px',
                borderRadius: 10,
                background: '#00d4ff',
                color:      '#061220',
                fontSize:   '9px',
                fontFamily: 'JetBrains Mono, monospace',
                fontWeight: 700,
                lineHeight: 1,
                boxShadow:  '0 0 12px rgba(0,212,255,0.75), 0 2px 6px rgba(0,0,0,0.35)',
                border:     '1.5px solid rgba(0,212,255,0.3)',
              }}
            >
              {historyCount > 9 ? '9+' : historyCount}
            </motion.span>
          )}
        </AnimatePresence>
      </div>

      {/* ── Theme toggle ──────────────────────────────────────────── */}
      <motion.button
        onClick={onToggleTheme}
        whileHover={{ scale: 1.08 }}
        whileTap={{ scale: 0.92 }}
        className="flex items-center justify-center w-7 h-7 rounded-lg glass-light border border-b1 text-t3 hover:text-t1 transition-colors duration-150"
        title={isDark ? 'Light mode' : 'Dark mode'}
      >
        {isDark ? <Sun size={12} /> : <Moon size={12} />}
      </motion.button>

      {/* ── New scan ──────────────────────────────────────────────── */}
      {onReset && (
        <motion.button
          onClick={onReset}
          whileHover={{ scale: 1.04 }}
          whileTap={{ scale: 0.96 }}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-mono text-t3 hover:text-t1 glass-light border border-b1 hover:border-white/20 transition-all duration-150 btn-shimmer"
        >
          <RotateCcw size={10} />
          New Scan
        </motion.button>
      )}
    </header>
  )
}
