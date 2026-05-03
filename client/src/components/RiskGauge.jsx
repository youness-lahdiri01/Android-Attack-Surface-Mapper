import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertOctagon, AlertTriangle, Info, CheckCircle, Shield, ChevronDown, ChevronUp } from 'lucide-react'

const R    = 88
const CX   = 110
const CY   = 110
const CIRC = 2 * Math.PI * R

function getScoreColor(score) {
  if (score >= 80) return '#ff3b5c'
  if (score >= 60) return '#ff9500'
  if (score >= 30) return '#ffd60a'
  return '#3fb950'
}

function getScoreLabel(score) {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH RISK'
  if (score >= 30) return 'MEDIUM'
  return 'LOW RISK'
}

function getWhyRisky(score, findings, parsed) {
  const crits = findings.filter(f => f.sev === 'critical')
  const highs  = findings.filter(f => f.sev === 'high')

  if (parsed.debuggable && score >= 70) {
    return 'App is debuggable in production — any attacker can dump heap memory and extract secrets via ADB without root.'
  }
  if (crits.length > 0) {
    const f = crits[0]
    return f.body.split('.')[0] + '.'
  }
  if (highs.length > 0) {
    const exp = parsed.components.filter(c => c.inferredExported && !c.perm)
    if (exp.length > 0)
      return `${exp.length} exported component${exp.length > 1 ? 's have' : ' has'} no permission guard — any installed app can invoke them directly.`
    return highs[0].body.split('.')[0] + '.'
  }
  if (score >= 30) {
    return 'Several security practices need improvement. Exported components and weak SDK targeting increase attack surface.'
  }
  return 'App follows most security best practices. Minor improvements recommended.'
}

function AnimatedNumber({ target }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    const start    = Date.now()
    const duration = 1300
    const update   = () => {
      const progress = Math.min((Date.now() - start) / duration, 1)
      const eased    = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(target * eased))
      if (progress < 1) requestAnimationFrame(update)
    }
    requestAnimationFrame(update)
  }, [target])
  return display
}

function SevBar({ icon: Icon, label, count, total, color }) {
  const pct = total > 0 ? (count / total) * 100 : 0
  return (
    <div className="flex items-center gap-2">
      <Icon size={11} style={{ color, flexShrink: 0 }} />
      <div className="text-[10px] font-mono text-t2 w-12 flex-shrink-0">{label}</div>
      <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
        <motion.div
          className="h-full rounded-full"
          style={{ background: color }}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.8, delay: 0.6, ease: [0.16, 1, 0.3, 1] }}
        />
      </div>
      <div className="text-[10px] font-mono font-bold w-4 text-right flex-shrink-0"
        style={{ color: count > 0 ? color : '#6e7681' }}>
        {count}
      </div>
    </div>
  )
}

export default function RiskGauge({ scanState }) {
  const { findings, parsed, score } = scanState
  const color = getScoreColor(score)
  const label = getScoreLabel(score)
  const why   = getWhyRisky(score, findings, parsed)

  const crits    = findings.filter(f => f.sev === 'critical').length
  const highs    = findings.filter(f => f.sev === 'high').length
  const meds     = findings.filter(f => f.sev === 'medium').length
  const lows     = findings.filter(f => f.sev === 'low').length
  const exported = parsed.components.filter(c => c.inferredExported).length

  const [whyOpen, setWhyOpen] = useState(true)

  // Gauge arc math: 0.75 of the full circle = 270°
  const arcLength = CIRC * 0.75

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ type: 'spring', stiffness: 250, damping: 25 }}
      className="w-72 flex-shrink-0 flex flex-col glass rounded-xl border border-b1 overflow-hidden"
    >
      {/* Header */}
      <div className="px-4 pt-3 pb-2 border-b border-b1 flex items-center gap-2">
        <Shield size={12} className="text-neon-cyan" />
        <span className="text-[10px] font-mono text-t3 tracking-widest">RISK SCORE</span>
      </div>

      {/* Gauge */}
      <div className="flex justify-center pt-3 pb-1">
        <div className="relative">
          <svg width="220" height="148" viewBox="0 0 220 150">
            <defs>
              <filter id="gauge-glow">
                <feGaussianBlur stdDeviation="5" result="blur" />
                <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
              {/* Gradient for arc */}
              <linearGradient id="arc-grad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor={color} stopOpacity="0.7" />
                <stop offset="100%" stopColor={color} stopOpacity="1" />
              </linearGradient>
            </defs>

            {/* Track */}
            <circle cx={CX} cy={CY} r={R}
              fill="none"
              stroke="rgba(255,255,255,0.05)"
              strokeWidth="10"
              strokeDasharray={`${arcLength} ${CIRC - arcLength}`}
              strokeLinecap="round"
              transform={`rotate(-225 ${CX} ${CY})`}
            />

            {/* Score arc — animated */}
            <motion.circle cx={CX} cy={CY} r={R}
              fill="none"
              stroke={color}
              strokeWidth="10"
              strokeLinecap="round"
              transform={`rotate(-225 ${CX} ${CY})`}
              strokeDasharray={`${arcLength} ${CIRC}`}
              initial={{ strokeDashoffset: arcLength }}
              animate={{ strokeDashoffset: arcLength * (1 - score / 100) }}
              transition={{ duration: 1.3, ease: [0.16, 1, 0.3, 1], delay: 0.1 }}
              filter="url(#gauge-glow)"
              style={{ filter: `drop-shadow(0 0 10px ${color})` }}
            />

            {/* Tick marks */}
            {[0, 25, 50, 75, 100].map(val => {
              const angle = (-225 + (val / 100) * 270) * (Math.PI / 180)
              const x1 = CX + (R - 7) * Math.cos(angle)
              const y1 = CY + (R - 7) * Math.sin(angle)
              const x2 = CX + (R + 2) * Math.cos(angle)
              const y2 = CY + (R + 2) * Math.sin(angle)
              return (
                <line key={val} x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke="rgba(255,255,255,0.15)" strokeWidth="1.5" strokeLinecap="round" />
              )
            })}

            {/* Center score */}
            <text x={CX} y={CY - 8}
              textAnchor="middle" fontSize="38" fontWeight="700"
              fontFamily="JetBrains Mono, monospace" fill={color}>
              <AnimatedNumber target={score} />
            </text>
            <text x={CX} y={CY + 14}
              textAnchor="middle" fontSize="9"
              fontFamily="JetBrains Mono, monospace"
              fill="rgba(255,255,255,0.28)" letterSpacing="2">
              / 100
            </text>
          </svg>

          {/* Label */}
          <div className="absolute bottom-0 left-0 right-0 flex justify-center">
            <motion.span
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.9 }}
              className="px-3 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-widest"
              style={{
                color,
                background: color + '18',
                border: `1px solid ${color}40`,
                boxShadow: `0 0 14px ${color}35`,
              }}
            >
              {label}
            </motion.span>
          </div>
        </div>
      </div>

      {/* Why risky section */}
      <div className="mx-3 mb-2 rounded-lg overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.06)' }}>
        <button
          onClick={() => setWhyOpen(v => !v)}
          className="w-full flex items-center justify-between px-3 py-1.5 text-t3 hover:text-t1 transition-colors"
          style={{ background: 'rgba(255,255,255,0.03)' }}
        >
          <span className="text-[9px] font-mono tracking-widest">WHY IS THIS RISKY?</span>
          {whyOpen ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
        </button>
        <AnimatePresence>
          {whyOpen && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="overflow-hidden"
            >
              <div className="px-3 py-2">
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.1 }}
                  className="text-[10px] font-mono leading-relaxed"
                  style={{ color: score >= 60 ? '#ff9500' : score >= 30 ? '#ffd60a' : '#8b949e' }}
                >
                  {why}
                </motion.p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Severity bars */}
      <div className="px-4 py-2 flex flex-col gap-2 border-t border-b1">
        <SevBar icon={AlertOctagon} label="Critical" count={crits} total={findings.length} color="#ff3b5c" />
        <SevBar icon={AlertTriangle} label="High"    count={highs} total={findings.length} color="#ff9500" />
        <SevBar icon={Info}          label="Medium"  count={meds}  total={findings.length} color="#ffd60a" />
        <SevBar icon={CheckCircle}   label="Low"     count={lows}  total={findings.length} color="#3fb950" />
      </div>

      {/* Quick stats */}
      <div className="grid grid-cols-2 border-t border-b1 divide-x divide-b1">
        {[
          { label: 'Components', value: parsed.components.length },
          { label: 'Exported',   value: exported },
          { label: 'Permissions', value: parsed.permissions.length },
          { label: 'Findings',   value: findings.length },
        ].map(({ label, value }) => (
          <div key={label} className="flex flex-col items-center py-2">
            <div className="text-sm font-mono font-bold text-t1">{value}</div>
            <div className="text-[9px] font-mono text-t3">{label}</div>
          </div>
        ))}
      </div>
    </motion.div>
  )
}
