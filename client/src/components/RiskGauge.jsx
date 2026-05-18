import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  AlertOctagon, AlertTriangle, Info, CheckCircle,
  Shield, ChevronDown, ChevronUp, Unlock, Key,
  Layers, Activity, Server, Radio, Database,
} from 'lucide-react'
import { useTheme } from '../hooks/useTheme.js'

const R    = 84
const CX   = 106
const CY   = 106
const CIRC = 2 * Math.PI * R

function getScoreColor(s) {
  return s >= 80 ? '#ff3b5c' : s >= 60 ? '#ff9500' : s >= 30 ? '#ffd60a' : '#3fb950'
}
function getScoreLabel(s) {
  return s >= 80 ? 'CRITICAL' : s >= 60 ? 'HIGH RISK' : s >= 30 ? 'MEDIUM' : 'LOW RISK'
}
function getWhyRisky(score, findings, parsed) {
  const crits = findings.filter(f => f.sev === 'critical')
  const highs  = findings.filter(f => f.sev === 'high')
  if (parsed.debuggable && score >= 70)
    return 'App is debuggable in production — attackers can dump heap memory and extract secrets via ADB without root.'
  if (crits.length > 0)
    return crits[0].body.split('.')[0] + '.'
  if (highs.length > 0) {
    const exp = parsed.components.filter(c => c.inferredExported && !c.perm)
    if (exp.length > 0)
      return `${exp.length} exported component${exp.length > 1 ? 's have' : ' has'} no permission guard — any installed app can invoke them directly.`
    return highs[0].body.split('.')[0] + '.'
  }
  if (score >= 30)
    return 'Several security practices need improvement. Exported components and weak SDK targeting increase attack surface.'
  return 'App follows most security best practices. Minor improvements recommended.'
}

function AnimatedNumber({ target, duration = 1200 }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    const start = Date.now()
    const tick  = () => {
      const progress = Math.min((Date.now() - start) / duration, 1)
      const eased    = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(target * eased))
      if (progress < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }, [target, duration])
  return display
}

function SevBar({ icon: Icon, label, count, total, color }) {
  const pct = total > 0 ? (count / total) * 100 : 0
  return (
    <div className="flex items-center gap-2">
      <Icon size={10} style={{ color, flexShrink: 0 }} />
      <span className="text-[9px] font-mono text-t2 w-11 flex-shrink-0">{label}</span>
      <div className="sev-bar-track flex-1">
        <motion.div
          className="h-full rounded-full"
          style={{ background: color }}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.9, delay: 0.5, ease: [0.16, 1, 0.3, 1] }}
        />
      </div>
      <span
        className="text-[9px] font-mono font-bold w-5 text-right flex-shrink-0"
        style={{ color: count > 0 ? color : 'var(--color-t3)' }}
      >
        {count}
      </span>
      {total > 0 && count > 0 && (
        <span className="text-[8px] font-mono text-t3 w-6 text-right flex-shrink-0">
          {Math.round(pct)}%
        </span>
      )}
    </div>
  )
}

const TYPE_META = {
  Activity: { icon: Activity, color: '#58a6ff' },
  Service:  { icon: Server,   color: '#a371f7' },
  Receiver: { icon: Radio,    color: '#d29922' },
  Provider: { icon: Database, color: '#ff3b5c' },
}

export default function RiskGauge({ scanState }) {
  const { isDark } = useTheme()
  const { findings, parsed, score } = scanState

  const color = getScoreColor(score)
  const label = getScoreLabel(score)
  const why   = getWhyRisky(score, findings, parsed)

  const crits    = findings.filter(f => f.sev === 'critical').length
  const highs    = findings.filter(f => f.sev === 'high').length
  const meds     = findings.filter(f => f.sev === 'medium').length
  const lows     = findings.filter(f => f.sev === 'low').length
  const exported = parsed.components.filter(c => c.inferredExported).length
  const unguarded= parsed.components.filter(c => c.inferredExported && !c.perm).length

  const [whyOpen, setWhyOpen] = useState(true)

  const arcLength  = CIRC * 0.75
  const trackColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.07)'
  const tickColor  = isDark ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.18)'
  const subtextColor = isDark ? 'rgba(255,255,255,0.28)' : 'rgba(0,0,0,0.3)'

  // Component breakdown counts
  const typeCounts = ['Activity','Service','Receiver','Provider'].map(t => ({
    type: t,
    count: parsed.components.filter(c => c.type === t).length,
    ...TYPE_META[t],
  })).filter(x => x.count > 0)

  const glowSize = score >= 80 ? 44 : score >= 60 ? 32 : score >= 30 ? 20 : 14
  const glowAlpha = score >= 80 ? '20' : score >= 60 ? '16' : score >= 30 ? '10' : '08'

  return (
    <motion.div
      initial={{ opacity: 0, x: -16 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ type: 'spring', stiffness: 280, damping: 26 }}
      className="w-72 flex-shrink-0 flex flex-col rounded-xl overflow-hidden"
      style={{
        background:    'var(--glass-bg)',
        backdropFilter:'blur(24px)',
        WebkitBackdropFilter: 'blur(24px)',
        border:        '1px solid var(--glass-border)',
        boxShadow:     `0 0 ${glowSize}px ${color}${glowAlpha}, 0 8px 32px rgba(0,0,0,0.4), 0 2px 8px rgba(0,0,0,0.25)`,
        transition:    'box-shadow 1.2s ease, background 0.25s ease, border-color 0.25s ease',
      }}
    >
      {/* ── Panel header ─────────────────────────────────────────── */}
      <div
        className="flex items-center justify-between px-4 py-2.5 border-b border-b1 flex-shrink-0"
        style={{ background: isDark ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.02)' }}
      >
        <div className="flex items-center gap-2">
          <Shield size={11} className="text-neon-cyan" />
          <span className="section-label">Risk Analysis</span>
        </div>
        <motion.span
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.4 }}
          className="text-[9px] font-mono font-bold px-2 py-0.5 rounded-full"
          style={{ color, background: color + '18', border: `1px solid ${color}35` }}
        >
          {label}
        </motion.span>
      </div>

      {/* ── Gauge ─────────────────────────────────────────────────── */}
      <div className="flex justify-center py-3">
        <div className="relative">
          <svg width="212" height="140" viewBox="0 0 212 140">
            <defs>
              <filter id="gauge-glow" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="4.5" result="blur" />
                <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
              <linearGradient id="arc-grad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor={color} stopOpacity="0.6" />
                <stop offset="100%" stopColor={color} />
              </linearGradient>
            </defs>

            {/* Track */}
            <circle cx={CX} cy={CY} r={R}
              fill="none"
              stroke={trackColor}
              strokeWidth="9"
              strokeDasharray={`${arcLength} ${CIRC - arcLength}`}
              strokeLinecap="round"
              transform={`rotate(-225 ${CX} ${CY})`}
            />

            {/* Score arc */}
            <motion.circle cx={CX} cy={CY} r={R}
              fill="none"
              stroke="url(#arc-grad)"
              strokeWidth="9"
              strokeLinecap="round"
              transform={`rotate(-225 ${CX} ${CY})`}
              strokeDasharray={`${arcLength} ${CIRC}`}
              initial={{ strokeDashoffset: arcLength }}
              animate={{ strokeDashoffset: arcLength * (1 - score / 100) }}
              transition={{ duration: 1.4, ease: [0.16, 1, 0.3, 1], delay: 0.15 }}
              style={{ filter: `drop-shadow(0 0 8px ${color}99)` }}
            />

            {/* Tick marks */}
            {[0, 25, 50, 75, 100].map(val => {
              const angle = (-225 + (val / 100) * 270) * (Math.PI / 180)
              return (
                <line key={val}
                  x1={CX + (R - 8)  * Math.cos(angle)}
                  y1={CY + (R - 8)  * Math.sin(angle)}
                  x2={CX + (R + 2)  * Math.cos(angle)}
                  y2={CY + (R + 2)  * Math.sin(angle)}
                  stroke={tickColor} strokeWidth="1.5" strokeLinecap="round"
                />
              )
            })}

            {/* Center score */}
            <text x={CX} y={CY - 10}
              textAnchor="middle" fontSize="36" fontWeight="700"
              fontFamily="JetBrains Mono, monospace" fill={color}>
              <AnimatedNumber target={score} />
            </text>
            <text x={CX} y={CY + 12}
              textAnchor="middle" fontSize="8.5"
              fontFamily="JetBrains Mono, monospace"
              fill={subtextColor} letterSpacing="2">
              / 100
            </text>

            {/* Min / Max labels */}
            <text x="18" y="132" textAnchor="middle" fontSize="8" fontFamily="JetBrains Mono, monospace" fill={subtextColor}>0</text>
            <text x="194" y="132" textAnchor="middle" fontSize="8" fontFamily="JetBrains Mono, monospace" fill={subtextColor}>100</text>
          </svg>
        </div>
      </div>

      {/* ── Why Risky ─────────────────────────────────────────────── */}
      <div
        className="mx-3 mb-2.5 rounded-lg overflow-hidden flex-shrink-0"
        style={{
          border: `1px solid ${color}28`,
          background: color + '08',
        }}
      >
        <button
          onClick={() => setWhyOpen(v => !v)}
          className="w-full flex items-center justify-between px-3 py-2 hover:opacity-80 transition-opacity"
        >
          <span className="section-label" style={{ color: color + 'cc' }}>Why is this risky?</span>
          <motion.div animate={{ rotate: whyOpen ? 180 : 0 }} transition={{ duration: 0.2 }}>
            <ChevronDown size={10} style={{ color }} />
          </motion.div>
        </button>
        <AnimatePresence>
          {whyOpen && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.22 }}
              className="overflow-hidden"
            >
              <p
                className="px-3 pb-2.5 text-[10px] font-mono leading-relaxed"
                style={{ color: score >= 60 ? '#ff9500' : score >= 30 ? '#c9a227' : 'var(--color-t2)' }}
              >
                {why}
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ── Severity breakdown ────────────────────────────────────── */}
      <div className="px-4 pb-3 flex flex-col gap-1.5 flex-shrink-0">
        <SevBar icon={AlertOctagon} label="Critical" count={crits} total={findings.length} color="#ff3b5c" />
        <SevBar icon={AlertTriangle} label="High"    count={highs} total={findings.length} color="#ff9500" />
        <SevBar icon={Info}          label="Medium"  count={meds}  total={findings.length} color="#ffd60a" />
        <SevBar icon={CheckCircle}   label="Low"     count={lows}  total={findings.length} color="#3fb950" />
      </div>

      {/* ── Enterprise stats grid ─────────────────────────────────── */}
      <div className="border-t border-b1 px-3 py-2.5 grid grid-cols-2 gap-2 flex-shrink-0">
        {[
          {
            label: 'Components',
            value: parsed.components.length,
            icon: Layers,
            color: '#58a6ff',
            sub: `${typeCounts.length} type${typeCounts.length !== 1 ? 's' : ''}`,
          },
          {
            label: 'Exported',
            value: exported,
            icon: Unlock,
            color: exported > 0 ? '#ff9500' : '#3fb950',
            sub: unguarded > 0 ? `${unguarded} unguarded` : 'all protected',
            danger: unguarded > 0,
          },
          {
            label: 'Permissions',
            value: parsed.permissions.length,
            icon: Key,
            color: '#a371f7',
            sub: parsed.permissions.length > 0 ? 'declared' : 'none',
          },
          {
            label: 'Findings',
            value: findings.length,
            icon: AlertOctagon,
            color: crits > 0 ? '#ff3b5c' : highs > 0 ? '#ff9500' : '#ffd60a',
            sub: crits > 0 ? `${crits} critical` : highs > 0 ? `${highs} high` : 'no critical',
          },
        ].map(({ label, value, icon: Icon, color: c, sub, danger }) => (
          <motion.div
            key={label}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="flex items-center gap-2.5 px-2.5 py-2 rounded-lg"
            style={{
              background: c + '0d',
              border: `1px solid ${c}${danger ? '40' : '22'}`,
            }}
          >
            <div
              className="w-7 h-7 rounded-md flex items-center justify-center flex-shrink-0"
              style={{ background: c + '18', border: `1px solid ${c}30` }}
            >
              <Icon size={12} style={{ color: c }} />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-mono font-bold leading-none" style={{ color: c }}>
                <AnimatedNumber target={value} duration={900} />
              </div>
              <div className="text-[8px] font-mono text-t3 mt-0.5 leading-none">{label}</div>
              {sub && (
                <div
                  className="text-[8px] font-mono leading-none mt-0.5 truncate"
                  style={{ color: danger ? '#ff9500' : 'var(--color-t3)' }}
                >
                  {sub}
                </div>
              )}
            </div>
          </motion.div>
        ))}
      </div>

      {/* ── Component type breakdown ──────────────────────────────── */}
      {typeCounts.length > 0 && (
        <div className="border-t border-b1 px-3 py-2 flex-shrink-0">
          <div className="section-label mb-1.5">Component breakdown</div>
          <div className="flex flex-wrap gap-1.5">
            {typeCounts.map(({ type, count, icon: Icon, color: c }) => (
              <div
                key={type}
                className="flex items-center gap-1 px-1.5 py-0.5 rounded-md text-[9px] font-mono"
                style={{ background: c + '12', border: `1px solid ${c}25`, color: c }}
              >
                <Icon size={8} />
                <span>{count} {type.toLowerCase()}{count !== 1 ? 's' : ''}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  )
}
