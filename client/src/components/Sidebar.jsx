import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Search, Activity, Server, Radio, Database,
  Lock, Unlock, Bug, HardDrive, Wifi, ChevronRight,
  X,
} from 'lucide-react'
import { calcComponentRisk, riskLevel } from '../lib/parser.js'

const TYPE_META = {
  Activity: { icon: Activity, color: '#58a6ff', cls: 'badge-activity' },
  Service:  { icon: Server,   color: '#a371f7', cls: 'badge-service'  },
  Receiver: { icon: Radio,    color: '#d29922', cls: 'badge-receiver' },
  Provider: { icon: Database, color: '#ff3b5c', cls: 'badge-provider' },
}

const SEV_COLOR = { critical: '#ff3b5c', high: '#ff9500', medium: '#ffd60a', low: '#3fb950' }

function RiskDot({ score }) {
  const lvl   = riskLevel(score)
  const color = SEV_COLOR[lvl] || '#3fb950'
  return (
    <div
      className="w-2 h-2 rounded-full flex-shrink-0"
      style={{
        background: color,
        boxShadow:  `0 0 5px ${color}88`,
        opacity:    score > 10 ? 1 : 0.3,
      }}
    />
  )
}

function ComponentRow({ c, isHighlighted, onHighlight }) {
  const risk = calcComponentRisk(c)
  const meta = TYPE_META[c.type] || TYPE_META.Activity
  const Icon = meta.icon
  const short = c.name.replace(/^.*\./, '')

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      className="relative flex items-center gap-2 px-2.5 py-1.5 rounded-lg cursor-pointer group overflow-hidden"
      style={{
        background:   isHighlighted ? meta.color + '14' : 'transparent',
        border:       `1px solid ${isHighlighted ? meta.color + '45' : 'transparent'}`,
        transition:   'background 0.15s ease, border-color 0.15s ease',
      }}
      onMouseEnter={() => onHighlight(c.name)}
      onMouseLeave={() => onHighlight(null)}
      onClick={() => onHighlight(isHighlighted ? null : c.name)}
    >
      {/* Left accent bar on hover/active */}
      {isHighlighted && (
        <motion.div
          initial={{ scaleY: 0, opacity: 0 }}
          animate={{ scaleY: 1, opacity: 1 }}
          transition={{ duration: 0.14 }}
          className="absolute left-0 top-0 bottom-0 w-[2px] rounded-r-full"
          style={{ background: meta.color, boxShadow: `0 0 8px ${meta.color}`, transformOrigin: 'center' }}
        />
      )}
      {/* Type icon */}
      <div
        className="w-5 h-5 rounded-md flex items-center justify-center flex-shrink-0"
        style={{ background: meta.color + '1a' }}
      >
        <Icon size={9} style={{ color: meta.color }} />
      </div>

      {/* Name + status */}
      <div className="flex-1 min-w-0">
        <div className="text-[11px] font-mono text-t1 truncate leading-none" title={c.name}>
          {short}
        </div>
        <div className="flex items-center gap-1.5 mt-0.5">
          {c.inferredExported ? (
            <span className="flex items-center gap-0.5 text-[9px] font-mono" style={{ color: '#ff9500' }}>
              <Unlock size={7} />
              exported
            </span>
          ) : (
            <span className="flex items-center gap-0.5 text-[9px] font-mono text-t3">
              <Lock size={7} />
              private
            </span>
          )}
          {c.schemes.length > 0 && (
            <span className="flex items-center gap-0.5 text-[9px] font-mono" style={{ color: '#d29922' }}>
              <Wifi size={7} />
              deeplink
            </span>
          )}
        </div>
      </div>

      <RiskDot score={risk} />
    </motion.div>
  )
}

export default function Sidebar({ scanState, highlightedNode, onHighlight }) {
  const [filter, setFilter] = useState('')
  const { parsed, findings } = scanState

  const exported  = parsed.components.filter(c => c.inferredExported)
  const unguarded = exported.filter(c => !c.perm)

  const filtered = filter
    ? parsed.components.filter(c =>
        c.name.toLowerCase().includes(filter.toLowerCase()) ||
        c.type.toLowerCase().includes(filter.toLowerCase())
      )
    : parsed.components

  const groups    = ['Activity', 'Service', 'Receiver', 'Provider']
  const flagChips = [
    parsed.debuggable       && { label: 'debuggable', color: '#ff3b5c', icon: Bug },
    parsed.allowBackup      && { label: 'allowBackup', color: '#ff9500', icon: HardDrive },
    parsed.clearTextTraffic && { label: 'cleartext',   color: '#ffd60a', icon: Wifi },
  ].filter(Boolean)

  return (
    <motion.aside
      initial={{ x: -264, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      className="w-60 flex-shrink-0 flex flex-col glass border-r border-b1 overflow-hidden"
    >
      {/* ── Package info ───────────────────────────────────────────── */}
      <div className="px-3 py-3 border-b border-b1 flex-shrink-0">
        <div className="section-label mb-1">Package</div>
        <div className="text-[11px] font-mono text-t1 break-all leading-snug">{parsed.pkg}</div>

        {/* SDK row */}
        {(parsed.targetSdk > 0 || parsed.minSdk > 0) && (
          <div className="flex gap-4 mt-2">
            {parsed.minSdk > 0 && (
              <div>
                <div className="section-label">Min SDK</div>
                <div className="text-xs font-mono text-neon-blue font-semibold mt-0.5">API {parsed.minSdk}</div>
              </div>
            )}
            {parsed.targetSdk > 0 && (
              <div>
                <div className="section-label">Target SDK</div>
                <div
                  className="text-xs font-mono font-semibold mt-0.5"
                  style={{ color: parsed.targetSdk < 31 ? '#d29922' : '#3fb950' }}
                >
                  API {parsed.targetSdk}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Flag chips */}
        {flagChips.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2.5">
            {flagChips.map(({ label, color, icon: Icon }) => (
              <span
                key={label}
                className="flex items-center gap-1 px-1.5 py-0.5 rounded-md text-[9px] font-mono font-medium"
                style={{ color, background: color + '18', border: `1px solid ${color}30` }}
              >
                <Icon size={8} />
                {label}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* ── Exposure stats ─────────────────────────────────────────── */}
      <div className="grid grid-cols-3 border-b border-b1 divide-x divide-b1 flex-shrink-0">
        {[
          { label: 'Total',    value: parsed.components.length, color: 'var(--color-t1)' },
          { label: 'Exported', value: exported.length,           color: exported.length    > 0 ? '#ff9500' : '#3fb950' },
          { label: 'No Perm',  value: unguarded.length,          color: unguarded.length   > 0 ? '#ff3b5c' : '#3fb950' },
        ].map(({ label, value, color }) => (
          <div key={label} className="flex flex-col items-center py-2.5">
            <div className="text-base font-mono font-bold" style={{ color }}>{value}</div>
            <div className="text-[8px] font-mono text-t3 mt-0.5">{label}</div>
          </div>
        ))}
      </div>

      {/* ── Search ─────────────────────────────────────────────────── */}
      <div className="px-3 py-2 border-b border-b1 flex-shrink-0">
        <div
          className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg"
          style={{ background: 'var(--color-b2)', border: '1px solid var(--color-b1)' }}
        >
          <Search size={11} className="text-t3 flex-shrink-0" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter components…"
            className="flex-1 bg-transparent text-[11px] font-mono text-t1 placeholder:text-t3 outline-none min-w-0"
          />
          {filter && (
            <button onClick={() => setFilter('')} className="text-t3 hover:text-t1 transition-colors">
              <X size={10} />
            </button>
          )}
        </div>
      </div>

      {/* ── Component list ─────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto px-2 py-1.5">
        {groups.map(type => {
          const items = filtered.filter(c => c.type === type)
          if (!items.length) return null
          const meta = TYPE_META[type]
          const Icon = meta.icon
          const exportedCount = items.filter(c => c.inferredExported).length
          return (
            <div key={type} className="mb-3">
              {/* Group header */}
              <div
                className="flex items-center justify-between px-2.5 py-1 mb-0.5 rounded-md"
                style={{ background: meta.color + '0a' }}
              >
                <div className="flex items-center gap-1.5">
                  <Icon size={9} style={{ color: meta.color }} />
                  <span className="section-label" style={{ color: meta.color }}>
                    {type}s
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  {exportedCount > 0 && (
                    <span
                      className="text-[8px] font-mono px-1 py-0.5 rounded"
                      style={{ color: '#ff9500', background: 'rgba(255,149,0,0.12)' }}
                    >
                      {exportedCount} exp
                    </span>
                  )}
                  <span className="text-[9px] font-mono text-t3">{items.length}</span>
                </div>
              </div>
              {items.map(c => (
                <ComponentRow
                  key={c.name}
                  c={c}
                  isHighlighted={highlightedNode === c.name}
                  onHighlight={onHighlight}
                />
              ))}
            </div>
          )
        })}

        {filtered.length === 0 && (
          <div className="text-center text-t3 text-[11px] font-mono py-10">
            No components match
          </div>
        )}
      </div>

      {/* ── Permissions ────────────────────────────────────────────── */}
      {parsed.permissions.length > 0 && (
        <div className="px-3 py-2.5 border-t border-b1 flex-shrink-0">
          <div className="flex items-center justify-between mb-1.5">
            <div className="section-label">Permissions</div>
            <span className="text-[9px] font-mono text-t3">{parsed.permissions.length}</span>
          </div>
          <div className="flex flex-wrap gap-1">
            {parsed.permissions.slice(0, 8).map(p => (
              <span
                key={p}
                className="text-[8px] font-mono text-t3 px-1.5 py-0.5 rounded-md"
                style={{ background: 'var(--color-b2)', border: '1px solid var(--color-b1)' }}
                title={p}
              >
                {p.split('.').pop()}
              </span>
            ))}
            {parsed.permissions.length > 8 && (
              <span className="text-[8px] font-mono text-t3 px-1.5 py-0.5">
                +{parsed.permissions.length - 8} more
              </span>
            )}
          </div>
        </div>
      )}
    </motion.aside>
  )
}
