import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  AlertOctagon, AlertTriangle, Info, CheckCircle,
  ChevronDown, ChevronUp, Sparkles, List, ExternalLink,
  ShieldAlert, Wrench,
} from 'lucide-react'

const SEV_META = {
  critical: {
    color:  '#ff3b5c',
    bg:     'rgba(255,59,92,0.07)',
    border: 'rgba(255,59,92,0.22)',
    hover:  'rgba(255,59,92,0.14)',
    icon:   AlertOctagon,
    label:  'CRITICAL',
  },
  high: {
    color:  '#ff9500',
    bg:     'rgba(255,149,0,0.07)',
    border: 'rgba(255,149,0,0.22)',
    hover:  'rgba(255,149,0,0.12)',
    icon:   AlertTriangle,
    label:  'HIGH',
  },
  medium: {
    color:  '#ffd60a',
    bg:     'rgba(255,214,10,0.06)',
    border: 'rgba(255,214,10,0.2)',
    hover:  'rgba(255,214,10,0.1)',
    icon:   Info,
    label:  'MEDIUM',
  },
  low: {
    color:  '#3fb950',
    bg:     'rgba(63,185,80,0.07)',
    border: 'rgba(63,185,80,0.2)',
    hover:  'rgba(63,185,80,0.1)',
    icon:   CheckCircle,
    label:  'LOW',
  },
}

/* ── Inline glossary tooltips ───────────────────────────────────────── */
const GLOSSARY = {
  'exported':      'Component accessible to other apps on the device without any permission',
  'permission':    'Android permission guard that restricts which apps can invoke this component',
  'intent-filter': 'Declares what types of intents this component can receive',
  'ADB':           'Android Debug Bridge — command-line tool to communicate with an Android device',
  'allowBackup':   'Enables adb backup to extract the app\'s private data directory',
  'debuggable':    'Allows ADB debugging on any device, even non-rooted',
  'cleartext':     'Unencrypted HTTP traffic — susceptible to man-in-the-middle attacks',
  'taskAffinity':  'Controls which task an activity belongs to — can enable task hijacking',
}

function TermTooltip({ children, term }) {
  const [show, setShow] = useState(false)
  const def = GLOSSARY[term]
  if (!def) return <span>{children}</span>
  return (
    <span className="relative inline-block">
      <span
        className="border-b border-dashed cursor-help"
        style={{ borderColor: 'rgba(88,166,255,0.4)', color: '#7ab8ff' }}
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
      >
        {children}
      </span>
      <AnimatePresence>
        {show && (
          <motion.div
            initial={{ opacity: 0, y: 4, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 4, scale: 0.95 }}
            transition={{ duration: 0.1 }}
            className="absolute z-50 bottom-full left-0 mb-2 w-52 rounded-lg p-2.5 text-[10px] font-mono text-t2 pointer-events-none"
            style={{
              background: 'var(--color-card-hover)',
              border: '1px solid rgba(88,166,255,0.22)',
              boxShadow: '0 8px 24px rgba(0,0,0,0.35)',
            }}
          >
            <div className="text-neon-blue text-[9px] font-bold mb-0.5 tracking-wide">{term}</div>
            {def}
          </motion.div>
        )}
      </AnimatePresence>
    </span>
  )
}

function AnnotatedText({ text }) {
  const terms = Object.keys(GLOSSARY)
  const regex = new RegExp(`\\b(${terms.join('|')})\\b`, 'gi')
  const parts = text.split(regex)
  return (
    <>
      {parts.map((part, i) => {
        const match = terms.find(t => t.toLowerCase() === part.toLowerCase())
        return match
          ? <TermTooltip key={i} term={match}>{part}</TermTooltip>
          : <span key={i}>{part}</span>
      })}
    </>
  )
}

/* ── Single finding card ────────────────────────────────────────────── */
function FindingCard({ finding, index, onAsk, onHighlightComponent, aiHasKey }) {
  const [expanded, setExpanded] = useState(false)
  const [hovered,  setHovered]  = useState(false)
  const meta       = SEV_META[finding.sev] || SEV_META.low
  const Icon       = meta.icon
  const isCritical = finding.sev === 'critical'
  const isHigh     = finding.sev === 'high'

  return (
    <motion.div
      className="finding-card-wrap"
      initial={{ opacity: 0, y: 16, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ delay: index * 0.045, type: 'spring', stiffness: 300, damping: 28 }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <motion.div
        animate={{
          boxShadow: hovered
            ? `0 0 28px ${meta.color}22, 0 6px 20px rgba(0,0,0,0.28), inset 0 1px 0 rgba(255,255,255,0.06)`
            : isCritical
              ? `0 0 14px ${meta.color}14, inset 0 1px 0 rgba(255,255,255,0.03)`
              : 'none',
        }}
        transition={{ duration: 0.22 }}
        className="relative flex flex-col rounded-xl overflow-hidden"
        style={{
          width:      expanded ? 385 : 274,
          minHeight:  88,
          background: hovered ? meta.hover : meta.bg,
          border:     `1px solid ${hovered ? meta.color + '55' : meta.border}`,
          transition: 'width 0.28s cubic-bezier(0.16,1,0.3,1), background 0.18s ease, border-color 0.18s ease',
        }}
      >
        {/* Left accent bar */}
        <div
          className={`absolute left-0 top-0 bottom-0 w-[3px] rounded-l-xl ${isCritical ? 'critical-bar' : ''}`}
          style={{
            background:  meta.color,
            boxShadow:   `0 0 ${isCritical ? '12px' : '5px'} ${meta.color}${isCritical ? '' : '88'}`,
          }}
        />

        <div className="pl-4 pr-3 pt-2.5 pb-2.5">
          {/* Severity badge + controls row */}
          <div className="flex items-center justify-between mb-2">
            <div
              className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono font-bold"
              style={{ color: meta.color, background: meta.color + '20' }}
            >
              <Icon size={8} />
              {meta.label}
            </div>

            <div className="flex items-center gap-0.5">
              {finding.componentId && (
                <motion.button
                  whileHover={{ scale: 1.15 }}
                  whileTap={{ scale: 0.9 }}
                  onClick={() => onHighlightComponent?.(finding.componentId)}
                  className="p-1 rounded-md text-t3 hover:text-neon-cyan transition-colors"
                  title="Highlight in graph"
                >
                  <ExternalLink size={9} />
                </motion.button>
              )}
              <motion.button
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.9 }}
                onClick={() => setExpanded(v => !v)}
                className="p-1 rounded-md text-t3 hover:text-t1 transition-colors"
              >
                <motion.div animate={{ rotate: expanded ? 180 : 0 }} transition={{ duration: 0.2 }}>
                  <ChevronDown size={11} />
                </motion.div>
              </motion.button>
            </div>
          </div>

          {/* Title */}
          <div
            className="text-[11px] font-mono font-semibold leading-snug"
            style={{
              color: 'var(--color-t1)',
              overflow: 'hidden',
              display: '-webkit-box',
              WebkitLineClamp: expanded ? 'unset' : 2,
              WebkitBoxOrient: 'vertical',
            }}
          >
            {finding.title}
          </div>

          {/* Expanded body */}
          <AnimatePresence>
            {expanded && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1] }}
                className="overflow-hidden"
              >
                {/* Description */}
                <div
                  className="mt-2.5 text-[10px] font-mono leading-relaxed"
                  style={{ color: 'var(--color-t2)' }}
                >
                  <AnnotatedText text={finding.body} />
                </div>

                {/* Fix section */}
                <motion.div
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.12 }}
                  className="mt-2.5 rounded-lg p-2.5 text-[10px] font-mono leading-relaxed"
                  style={{
                    background: 'rgba(63,185,80,0.07)',
                    border: '1px solid rgba(63,185,80,0.2)',
                  }}
                >
                  <div className="flex items-center gap-1.5 mb-1">
                    <Wrench size={9} style={{ color: '#3fb950', flexShrink: 0 }} />
                    <span className="font-bold text-[9px] tracking-wide" style={{ color: '#3fb950' }}>
                      HOW TO FIX
                    </span>
                  </div>
                  <span style={{ color: 'var(--color-t2)' }}>{finding.fix}</span>
                </motion.div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* AI button */}
          {aiHasKey && (
            <div className="mt-2.5">
              <motion.button
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                onClick={() => onAsk(finding)}
                className="flex items-center gap-1.5 text-[9px] font-mono px-2.5 py-1 rounded-lg btn-shimmer"
                style={{
                  color:      '#a371f7',
                  background: 'rgba(163,113,247,0.1)',
                  border:     '1px solid rgba(163,113,247,0.25)',
                }}
              >
                <Sparkles size={8} />
                Ask AI
              </motion.button>
            </div>
          )}
        </div>
      </motion.div>
    </motion.div>
  )
}

/* ── Findings grid container ────────────────────────────────────────── */
export default function FindingsGrid({ findings, onSelectFinding, onHighlightComponent, aiHasKey }) {
  const counts = ['critical', 'high', 'medium', 'low'].map(sev => ({
    sev,
    count: findings.filter(f => f.sev === sev).length,
    ...SEV_META[sev],
  }))

  const totalFindings = findings.length
  const criticalCount = counts[0].count

  return (
    <div
      className="flex-shrink-0 border-t border-b1"
      style={{ background: 'var(--glass-bg)', backdropFilter: 'blur(20px)' }}
    >
      {/* Header row */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-b1">
        <div className="flex items-center gap-2">
          <ShieldAlert size={11} className="text-t3" />
          <span className="section-label">Security Findings</span>
          <span
            className="text-[10px] font-mono text-t2 px-1.5 py-0.5 rounded-md"
            style={{ background: 'var(--color-b2)' }}
          >
            {totalFindings}
          </span>
        </div>

        {/* Severity summary chips */}
        <div className="flex items-center gap-1.5 ml-1">
          {counts.filter(c => c.count > 0).map(({ sev, count, color }) => (
            <span
              key={sev}
              className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded-md"
              style={{ color, background: color + '18' }}
            >
              {count} {sev}
            </span>
          ))}
        </div>

        <div className="flex-1" />

        <span className="text-[9px] font-mono text-t3 italic hidden md:block">
          hover terms for definitions · click ↗ to focus in graph
        </span>
      </div>

      {/* Cards row */}
      <div className="findings-scroll px-4 py-3" style={{ minHeight: 116, maxHeight: 218 }}>
        {findings.length === 0 ? (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-2.5 text-neon-green text-xs font-mono py-5"
          >
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center"
              style={{ background: 'rgba(63,185,80,0.1)', border: '1px solid rgba(63,185,80,0.25)' }}
            >
              <CheckCircle size={14} />
            </div>
            <div>
              <div className="font-semibold">No findings detected</div>
              <div className="text-[10px] text-t3 mt-0.5">App follows security best practices</div>
            </div>
          </motion.div>
        ) : (
          findings.map((f, i) => (
            <FindingCard
              key={`${f.sev}-${f.title}`}
              finding={f}
              index={i}
              onAsk={onSelectFinding}
              onHighlightComponent={onHighlightComponent}
              aiHasKey={aiHasKey}
            />
          ))
        )}
      </div>
    </div>
  )
}
