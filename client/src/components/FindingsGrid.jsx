import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  AlertOctagon, AlertTriangle, Info, CheckCircle,
  ChevronDown, ChevronUp, Sparkles, List, ExternalLink,
} from 'lucide-react'

const SEV_META = {
  critical: { color: '#ff3b5c', bg: 'rgba(255,59,92,0.07)',  border: 'rgba(255,59,92,0.3)',  icon: AlertOctagon,  label: 'CRITICAL' },
  high:     { color: '#ff9500', bg: 'rgba(255,149,0,0.07)',  border: 'rgba(255,149,0,0.3)',  icon: AlertTriangle, label: 'HIGH' },
  medium:   { color: '#ffd60a', bg: 'rgba(255,214,10,0.07)', border: 'rgba(255,214,10,0.3)', icon: Info,          label: 'MEDIUM' },
  low:      { color: '#3fb950', bg: 'rgba(63,185,80,0.07)',  border: 'rgba(63,185,80,0.3)',  icon: CheckCircle,   label: 'LOW' },
}

/* Simple inline tooltip for technical terms */
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
            className="absolute z-50 bottom-full left-0 mb-1.5 w-52 rounded-lg p-2 text-[10px] font-mono text-t2 pointer-events-none"
            style={{ background: 'var(--color-card-hover)', border: '1px solid rgba(88,166,255,0.25)', boxShadow: '0 4px 20px rgba(0,0,0,0.4)' }}
          >
            <div className="text-neon-blue text-[9px] font-bold mb-0.5">{term}</div>
            {def}
          </motion.div>
        )}
      </AnimatePresence>
    </span>
  )
}

/* Highlight technical terms in a body of text */
function AnnotatedText({ text }) {
  const terms  = Object.keys(GLOSSARY)
  const regex  = new RegExp(`\\b(${terms.join('|')})\\b`, 'gi')
  const parts  = text.split(regex)

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

function FindingCard({ finding, index, onAsk, onHighlightComponent, aiHasKey }) {
  const [expanded, setExpanded] = useState(false)
  const [hovered,  setHovered]  = useState(false)
  const meta = SEV_META[finding.sev] || SEV_META.low
  const Icon = meta.icon
  const isCritical = finding.sev === 'critical'

  return (
    <motion.div
      className="finding-card-wrap"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05, type: 'spring', stiffness: 280, damping: 26 }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <motion.div
        animate={{
          scale: hovered ? 1.015 : 1,
          boxShadow: hovered
            ? `0 0 24px ${meta.color}25, 0 4px 16px rgba(0,0,0,0.3)`
            : isCritical
              ? `0 0 14px ${meta.color}18`
              : '0 0 0px transparent',
        }}
        transition={{ duration: 0.2 }}
        className="relative flex flex-col rounded-xl overflow-hidden"
        style={{
          width: expanded ? 380 : 270,
          background: meta.bg,
          border: `1px solid ${hovered ? meta.color + '55' : meta.border}`,
          transition: 'width 0.25s cubic-bezier(0.16,1,0.3,1), border-color 0.2s',
        }}
      >
        {/* Accent bar — pulsing for critical */}
        <div
          className={`absolute left-0 top-0 bottom-0 w-0.5 rounded-l-xl ${isCritical ? 'critical-bar' : ''}`}
          style={{ background: meta.color, boxShadow: `0 0 ${isCritical ? '10px' : '6px'} ${meta.color}` }}
        />

        <div className="pl-3.5 pr-3 pt-2.5 pb-2">
          {/* Severity + controls */}
          <div className="flex items-center justify-between mb-1.5">
            <div
              className="flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[9px] font-mono font-bold"
              style={{ color: meta.color, background: meta.color + '22' }}
            >
              <Icon size={8} />
              {meta.label}
            </div>
            <div className="flex items-center gap-1">
              {finding.componentId && (
                <button
                  onClick={() => onHighlightComponent?.(finding.componentId)}
                  className="p-0.5 rounded text-t3 hover:text-neon-cyan transition-colors"
                  title="Highlight in graph"
                >
                  <ExternalLink size={9} />
                </button>
              )}
              <button
                onClick={() => setExpanded(v => !v)}
                className="p-0.5 text-t3 hover:text-t1 transition-colors"
              >
                {expanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
              </button>
            </div>
          </div>

          {/* Title */}
          <div
            className="text-[11px] font-mono font-semibold text-t1 leading-tight"
            style={{
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
                transition={{ duration: 0.22 }}
                className="overflow-hidden"
              >
                <div className="mt-2 text-[10px] font-mono text-t2 leading-relaxed">
                  <AnnotatedText text={finding.body} />
                </div>
                <motion.div
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 }}
                  className="mt-2 p-2 rounded-lg text-[10px] font-mono leading-relaxed"
                  style={{ background: 'rgba(63,185,80,0.07)', border: '1px solid rgba(63,185,80,0.2)', color: '#3fb950' }}
                >
                  <span className="font-bold text-neon-green">FIX: </span>
                  {finding.fix}
                </motion.div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Actions */}
          {aiHasKey && (
            <div className="mt-2">
              <motion.button
                whileHover={{ scale: 1.04 }}
                whileTap={{ scale: 0.97 }}
                onClick={() => onAsk(finding)}
                className="flex items-center gap-1 text-[9px] font-mono px-2 py-1 rounded-md"
                style={{
                  color: '#a371f7',
                  background: 'rgba(163,113,247,0.1)',
                  border: '1px solid rgba(163,113,247,0.3)',
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

export default function FindingsGrid({ findings, onSelectFinding, onHighlightComponent, aiHasKey }) {
  const counts = ['critical', 'high', 'medium', 'low'].map(sev => ({
    sev,
    count: findings.filter(f => f.sev === sev).length,
    ...SEV_META[sev],
  }))

  return (
    <div className="flex-shrink-0 border-t border-b1" style={{ background: 'var(--glass-bg)' }}>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-b1">
        <div className="flex items-center gap-1.5">
          <List size={11} className="text-t3" />
          <span className="text-[10px] font-mono text-t3 tracking-widest">FINDINGS</span>
          <span className="text-[10px] font-mono text-t2 ml-1">{findings.length} total</span>
        </div>
        <div className="flex items-center gap-2 ml-2">
          {counts.filter(c => c.count > 0).map(({ sev, count, color }) => (
            <span
              key={sev}
              className="text-[9px] font-mono px-1.5 py-0.5 rounded"
              style={{ color, background: color + '18' }}
            >
              {count} {sev}
            </span>
          ))}
        </div>
        <div className="flex-1" />
        <span className="text-[9px] font-mono text-t3 italic">hover terms for definitions · click ↗ to highlight in graph</span>
      </div>

      {/* Cards row */}
      <div className="findings-scroll px-4 py-3" style={{ minHeight: 120, maxHeight: 230 }}>
        {findings.length === 0 ? (
          <div className="flex items-center gap-2 text-neon-green text-xs font-mono py-6">
            <CheckCircle size={14} />
            No findings detected — looks clean!
          </div>
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
