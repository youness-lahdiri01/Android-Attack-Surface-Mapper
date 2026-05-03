import { useState } from 'react'
import { motion } from 'framer-motion'
import { Search, Activity, Server, Radio, Database, Lock, Unlock, Bug, HardDrive, Wifi } from 'lucide-react'
import { calcComponentRisk, riskLevel } from '../lib/parser.js'

const TYPE_META = {
  Activity: { icon: Activity, color: '#58a6ff', cls: 'badge-activity' },
  Service:  { icon: Server,   color: '#a371f7', cls: 'badge-service' },
  Receiver: { icon: Radio,    color: '#d29922', cls: 'badge-receiver' },
  Provider: { icon: Database, color: '#ff3b5c', cls: 'badge-provider' },
}

const SEV_COLOR = { critical: '#ff3b5c', high: '#ff9500', medium: '#ffd60a', low: '#3fb950' }
const SEV_DOT   = { critical: 3, high: 2, medium: 1, low: 0 }

function RiskDots({ score }) {
  const lvl  = riskLevel(score)
  const dots = SEV_DOT[lvl] ?? 0
  return (
    <div className="flex gap-0.5">
      {[0, 1, 2].map(i => (
        <div
          key={i}
          className="w-1.5 h-1.5 rounded-full"
          style={{ background: i < dots ? SEV_COLOR[lvl] : 'rgba(255,255,255,0.12)' }}
        />
      ))}
    </div>
  )
}

function ComponentRow({ c, isHighlighted, onHighlight }) {
  const risk  = calcComponentRisk(c)
  const meta  = TYPE_META[c.type] || TYPE_META.Activity
  const Icon  = meta.icon
  const short = c.name.replace(/^.*\./, '')

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      className="flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer transition-all duration-150 group"
      style={{
        background: isHighlighted ? `${meta.color}14` : 'transparent',
        border: `1px solid ${isHighlighted ? meta.color + '40' : 'transparent'}`,
      }}
      onMouseEnter={() => onHighlight(c.name)}
      onMouseLeave={() => onHighlight(null)}
      onClick={() => onHighlight(isHighlighted ? null : c.name)}
    >
      <div
        className="w-5 h-5 rounded flex items-center justify-center flex-shrink-0"
        style={{ background: meta.color + '20' }}
      >
        <Icon size={10} style={{ color: meta.color }} />
      </div>

      <div className="flex-1 min-w-0">
        <div className="text-[11px] font-mono text-t1 truncate" title={c.name}>
          {short}
        </div>
        <div className="flex items-center gap-1 mt-0.5">
          {c.inferredExported ? (
            <span className="flex items-center gap-0.5 text-[9px] font-mono" style={{ color: SEV_COLOR.high }}>
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
            <span className="text-[9px] font-mono" style={{ color: '#d29922' }}>
              <Wifi size={7} className="inline mr-0.5" />
              deeplink
            </span>
          )}
        </div>
      </div>

      <RiskDots score={risk} />
    </motion.div>
  )
}

export default function Sidebar({ scanState, highlightedNode, onHighlight }) {
  const [filter, setFilter] = useState('')
  const { parsed, findings } = scanState

  const exported = parsed.components.filter(c => c.inferredExported)
  const noPerm   = exported.filter(c => !c.perm)

  const filtered = filter
    ? parsed.components.filter(c =>
        c.name.toLowerCase().includes(filter.toLowerCase()) ||
        c.type.toLowerCase().includes(filter.toLowerCase())
      )
    : parsed.components

  const groups = ['Activity', 'Service', 'Receiver', 'Provider']

  const flagChips = [
    parsed.debuggable       && { label: 'debuggable', color: '#ff3b5c', icon: Bug },
    parsed.allowBackup      && { label: 'allowBackup', color: '#ff9500', icon: HardDrive },
    parsed.clearTextTraffic && { label: 'cleartext', color: '#ffd60a', icon: Wifi },
  ].filter(Boolean)

  return (
    <motion.aside
      initial={{ x: -280, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      className="w-64 flex-shrink-0 flex flex-col glass border-r border-b1 overflow-hidden"
    >
      {/* App info */}
      <div className="px-3 py-3 border-b border-b1">
        <div className="text-[10px] font-mono text-t3 mb-1 tracking-widest">PACKAGE</div>
        <div className="text-xs font-mono text-t1 break-all leading-tight">{parsed.pkg}</div>

        {(parsed.targetSdk > 0 || parsed.minSdk > 0) && (
          <div className="flex gap-3 mt-2">
            {parsed.minSdk > 0 && (
              <div>
                <div className="text-[9px] text-t3 font-mono">MIN SDK</div>
                <div className="text-xs font-mono text-neon-blue">API {parsed.minSdk}</div>
              </div>
            )}
            {parsed.targetSdk > 0 && (
              <div>
                <div className="text-[9px] text-t3 font-mono">TARGET SDK</div>
                <div className={`text-xs font-mono ${parsed.targetSdk < 31 ? 'text-neon-orange' : 'text-neon-green'}`}>
                  API {parsed.targetSdk}
                </div>
              </div>
            )}
          </div>
        )}

        {flagChips.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {flagChips.map(({ label, color, icon: Icon }) => (
              <span
                key={label}
                className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono"
                style={{ color, background: color + '18', border: `1px solid ${color}30` }}
              >
                <Icon size={8} />
                {label}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 border-b border-b1 divide-x divide-b1">
        {[
          { label: 'Total', value: parsed.components.length, color: '#e6edf3' },
          { label: 'Exported', value: exported.length, color: exported.length > 0 ? '#ff3b5c' : '#3fb950' },
          { label: 'No Perm', value: noPerm.length, color: noPerm.length > 0 ? '#ff9500' : '#3fb950' },
        ].map(({ label, value, color }) => (
          <div key={label} className="flex flex-col items-center py-2">
            <div className="text-base font-mono font-bold" style={{ color }}>{value}</div>
            <div className="text-[9px] font-mono text-t3">{label}</div>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="px-3 py-2 border-b border-b1">
        <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <Search size={11} className="text-t3 flex-shrink-0" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter components…"
            className="flex-1 bg-transparent text-[11px] font-mono text-t1 placeholder-t3 outline-none min-w-0"
          />
        </div>
      </div>

      {/* Component list */}
      <div className="flex-1 overflow-y-auto px-1 py-1">
        {groups.map(type => {
          const items = filtered.filter(c => c.type === type)
          if (!items.length) return null
          const meta = TYPE_META[type]
          const Icon = meta.icon
          return (
            <div key={type} className="mb-2">
              <div className="flex items-center gap-1.5 px-3 py-1">
                <Icon size={9} style={{ color: meta.color }} />
                <span className="text-[9px] font-mono tracking-widest" style={{ color: meta.color }}>
                  {type.toUpperCase()}S
                </span>
                <span className="text-[9px] font-mono text-t3 ml-auto">{items.length}</span>
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
          <div className="text-center text-t3 text-xs font-mono py-8">No components match</div>
        )}
      </div>

      {/* Permissions count */}
      {parsed.permissions.length > 0 && (
        <div className="px-3 py-2 border-t border-b1">
          <div className="text-[9px] font-mono text-t3 tracking-widest mb-1">PERMISSIONS ({parsed.permissions.length})</div>
          <div className="flex flex-wrap gap-1">
            {parsed.permissions.slice(0, 6).map(p => (
              <span key={p} className="text-[9px] font-mono text-t3 px-1.5 py-0.5 rounded" style={{ background: 'rgba(255,255,255,0.04)' }}>
                {p.split('.').pop()}
              </span>
            ))}
            {parsed.permissions.length > 6 && (
              <span className="text-[9px] font-mono text-t3">+{parsed.permissions.length - 6}</span>
            )}
          </div>
        </div>
      )}
    </motion.aside>
  )
}
