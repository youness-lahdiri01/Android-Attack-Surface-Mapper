import { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  History, Search, Trash2, FileJson, FileText,
  X, Clock, Package, ChevronRight, Filter,
  ShieldOff, SortDesc,
} from 'lucide-react'
import { deleteHistoryEntry, clearHistory, exportHistoryJSON, exportHistoryCSV } from '../lib/historyService.js'

// ── Constants ───────────────────────────────────────────────────────────────

const SEV_COLOR = {
  critical: '#ff3b5c',
  high:     '#ff9500',
  medium:   '#ffd60a',
  low:      '#3fb950',
}

const RISK_FILTERS = [
  { label: 'All',      value: 'all' },
  { label: 'Critical', value: 'critical' },
  { label: 'High',     value: 'high' },
  { label: 'Medium',   value: 'medium' },
  { label: 'Low',      value: 'low' },
]

const SORT_OPTIONS = [
  { label: 'Newest',    value: 'newest' },
  { label: 'Oldest',   value: 'oldest' },
  { label: 'Risk ↓',   value: 'risk_desc' },
  { label: 'Risk ↑',   value: 'risk_asc' },
]

// ── Helpers ─────────────────────────────────────────────────────────────────

function riskLevelForScore(score) {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

function riskLabel(score) {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 30) return 'MEDIUM'
  return 'LOW'
}

function formatDate(iso) {
  const d = new Date(iso)
  return (
    d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) +
    ' · ' +
    d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
  )
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a   = Object.assign(document.createElement('a'), { href: url, download: filename })
  a.click()
  URL.revokeObjectURL(url)
}

// ── HistoryCard ──────────────────────────────────────────────────────────────

function HistoryCard({ entry, index, onRestore, onDelete }) {
  const [hovered,       setHovered]       = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const level      = riskLevelForScore(entry.riskScore)
  const scoreColor = SEV_COLOR[level]

  function handleDelete(e) {
    e.stopPropagation()
    if (confirmDelete) {
      onDelete(entry.id)
    } else {
      setConfirmDelete(true)
      setTimeout(() => setConfirmDelete(false), 2500)
    }
  }

  const sevCounts = ['critical', 'high', 'medium', 'low'].filter(s => entry.counts[s] > 0)

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 18, scale: 0.97 }}
      animate={{ opacity: 1, y: 0,  scale: 1 }}
      exit={{ opacity: 0, x: -24, scale: 0.95 }}
      transition={{ delay: Math.min(index * 0.035, 0.3), type: 'spring', stiffness: 300, damping: 28 }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => { setHovered(false); setConfirmDelete(false) }}
      onClick={() => onRestore(entry)}
      className="relative flex flex-col gap-3 p-4 rounded-xl cursor-pointer select-none"
      style={{
        background:   hovered ? 'var(--color-card-hover)' : 'var(--color-card)',
        border:       `1px solid ${hovered ? scoreColor + '45' : 'var(--glass-border)'}`,
        boxShadow:    hovered ? `0 0 22px ${scoreColor}14, 0 4px 20px rgba(0,0,0,0.25)` : 'none',
        transition:   'background 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease',
      }}
    >
      {/* Left accent bar */}
      <div
        className="absolute left-0 top-4 bottom-4 w-[3px] rounded-full"
        style={{ background: scoreColor, boxShadow: `0 0 ${hovered ? '8px' : '4px'} ${scoreColor}`, transition: 'box-shadow 0.18s' }}
      />

      {/* Top row */}
      <div className="pl-3 flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="text-xs font-mono font-semibold text-t1 truncate mb-0.5" title={entry.apkName}>
            {entry.apkName}
          </div>
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-t3">
            <Package size={9} className="flex-shrink-0" />
            <span className="truncate" title={entry.packageName}>{entry.packageName}</span>
          </div>
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-t3 mt-0.5">
            <Clock size={9} className="flex-shrink-0" />
            <span>{formatDate(entry.scanDate)}</span>
          </div>
        </div>

        {/* Score badge */}
        <div
          className="flex-shrink-0 flex flex-col items-center gap-0.5 px-2.5 py-1.5 rounded-lg"
          style={{
            background:   scoreColor + '12',
            border:       `1px solid ${scoreColor}45`,
            boxShadow:    hovered ? `0 0 12px ${scoreColor}20` : 'none',
            transition:   'box-shadow 0.18s',
          }}
        >
          <span className="text-base font-mono font-bold leading-none" style={{ color: scoreColor }}>
            {entry.riskScore}
          </span>
          <span className="text-[8px] font-mono font-bold tracking-wider" style={{ color: scoreColor + 'bb' }}>
            {riskLabel(entry.riskScore)}
          </span>
        </div>
      </div>

      {/* Severity chips */}
      <div className="pl-3 flex items-center flex-wrap gap-1.5">
        {sevCounts.map(sev => (
          <span
            key={sev}
            className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold"
            style={{ color: SEV_COLOR[sev], background: SEV_COLOR[sev] + '1a' }}
          >
            {entry.counts[sev]} {sev.toUpperCase().slice(0, 4)}
          </span>
        ))}
        {entry.exportedComponents.length > 0 && (
          <span className="ml-auto text-[9px] font-mono text-t3">
            {entry.exportedComponents.length} exported
          </span>
        )}
      </div>

      {/* Permissions preview */}
      {entry.permissions.length > 0 && (
        <div className="pl-3 flex flex-wrap gap-1">
          {entry.permissions.slice(0, 3).map(p => (
            <span
              key={p}
              className="text-[8px] font-mono text-t3 px-1.5 py-0.5 rounded"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)' }}
            >
              {p.split('.').pop()}
            </span>
          ))}
          {entry.permissions.length > 3 && (
            <span className="text-[8px] font-mono text-t3 px-1.5 py-0.5">
              +{entry.permissions.length - 3}
            </span>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="pl-3 flex items-center gap-2">
        <motion.button
          whileHover={{ scale: 1.04 }}
          whileTap={{ scale: 0.96 }}
          onClick={e => { e.stopPropagation(); onRestore(entry) }}
          className="flex items-center gap-1 text-[10px] font-mono px-2.5 py-1 rounded-md"
          style={{
            color:      '#00d4ff',
            background: 'rgba(0,212,255,0.08)',
            border:     '1px solid rgba(0,212,255,0.25)',
          }}
        >
          <ChevronRight size={10} />
          View Scan
        </motion.button>

        <motion.button
          whileHover={{ scale: 1.04 }}
          whileTap={{ scale: 0.96 }}
          onClick={handleDelete}
          className="flex items-center gap-1 text-[10px] font-mono px-2.5 py-1 rounded-md"
          style={{
            color:      confirmDelete ? '#ff3b5c' : 'var(--color-t3)',
            background: confirmDelete ? 'rgba(255,59,92,0.1)' : 'transparent',
            border:     `1px solid ${confirmDelete ? 'rgba(255,59,92,0.3)' : 'transparent'}`,
            transition: 'all 0.15s ease',
          }}
        >
          <Trash2 size={9} />
          {confirmDelete ? 'Confirm?' : 'Delete'}
        </motion.button>
      </div>
    </motion.div>
  )
}

// ── Empty States ─────────────────────────────────────────────────────────────

function EmptyHistory({ onClose }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-col items-center justify-center h-full gap-5 text-center px-8"
    >
      <motion.div
        animate={{ scale: [1, 1.04, 1], opacity: [0.6, 1, 0.6] }}
        transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
        className="w-20 h-20 rounded-2xl flex items-center justify-center"
        style={{ background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.15)' }}
      >
        <History size={32} className="text-t3" />
      </motion.div>
      <div>
        <div className="text-sm font-mono font-semibold text-t1 mb-1.5">No scan history yet</div>
        <div className="text-xs font-mono text-t3 max-w-xs leading-relaxed">
          Scans are saved automatically when you analyze an APK or manifest.
        </div>
      </div>
      <motion.button
        whileHover={{ scale: 1.04 }}
        whileTap={{ scale: 0.97 }}
        onClick={onClose}
        className="flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-mono"
        style={{
          color:      '#00d4ff',
          background: 'rgba(0,212,255,0.08)',
          border:     '1px solid rgba(0,212,255,0.25)',
        }}
      >
        Start scanning →
      </motion.button>
    </motion.div>
  )
}

function NoResults({ onClear }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="flex flex-col items-center justify-center h-64 gap-3 text-center"
    >
      <Search size={22} className="text-t3" />
      <div className="text-sm font-mono text-t2">No matches found</div>
      <button
        onClick={onClear}
        className="text-[11px] font-mono text-neon-cyan hover:underline"
      >
        Clear filters
      </button>
    </motion.div>
  )
}

// ── Main HistoryPanel ────────────────────────────────────────────────────────

export default function HistoryPanel({ initialHistory, onRestore, onClose }) {
  const [history,       setHistory]       = useState(initialHistory)
  const [search,        setSearch]        = useState('')
  const [riskFilter,    setRiskFilter]    = useState('all')
  const [sortBy,        setSortBy]        = useState('newest')
  const [showSort,      setShowSort]      = useState(false)
  const [confirmClear,  setConfirmClear]  = useState(false)

  const filtered = useMemo(() => {
    let result = [...history]

    if (search.trim()) {
      const q = search.toLowerCase()
      result = result.filter(e =>
        e.packageName.toLowerCase().includes(q) ||
        e.apkName.toLowerCase().includes(q)
      )
    }

    if (riskFilter !== 'all') {
      result = result.filter(e => riskLevelForScore(e.riskScore) === riskFilter)
    }

    switch (sortBy) {
      case 'oldest':    result.sort((a, b) => new Date(a.scanDate) - new Date(b.scanDate));  break
      case 'risk_desc': result.sort((a, b) => b.riskScore - a.riskScore);                    break
      case 'risk_asc':  result.sort((a, b) => a.riskScore - b.riskScore);                    break
      default:          result.sort((a, b) => new Date(b.scanDate) - new Date(a.scanDate));  break
    }

    return result
  }, [history, search, riskFilter, sortBy])

  function handleDelete(id) {
    setHistory(deleteHistoryEntry(id))
  }

  function handleClearAll() {
    if (confirmClear) {
      clearHistory()
      setHistory([])
      setConfirmClear(false)
    } else {
      setConfirmClear(true)
      setTimeout(() => setConfirmClear(false), 2500)
    }
  }

  function handleExportJSON() {
    downloadBlob(
      new Blob([exportHistoryJSON(history)], { type: 'application/json' }),
      'aasm-scan-history.json'
    )
  }

  function handleExportCSV() {
    downloadBlob(
      new Blob([exportHistoryCSV(history)], { type: 'text/csv' }),
      'aasm-scan-history.csv'
    )
  }

  const sortLabel = SORT_OPTIONS.find(s => s.value === sortBy)?.label ?? 'Newest'

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.18 }}
      className="flex flex-col flex-1 overflow-hidden"
      style={{ background: 'var(--color-bg)' }}
    >
      {/* ── Toolbar ── */}
      <div
        className="flex items-center gap-2 px-4 py-2.5 border-b border-b1 flex-shrink-0"
        style={{ background: 'var(--glass-bg)', backdropFilter: 'blur(16px)' }}
      >
        {/* Title */}
        <div className="flex items-center gap-2">
          <History size={13} className="text-neon-cyan" />
          <span className="text-xs font-mono font-bold text-t1 tracking-wider">SCAN HISTORY</span>
          <span
            className="px-2 py-0.5 rounded-full text-[9px] font-mono text-t3"
            style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--glass-border)' }}
          >
            {history.length} saved
          </span>
        </div>

        {/* Search */}
        {history.length > 0 && (
          <div className="relative ml-3">
            <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-t3 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search package or APK…"
              className="pl-7 pr-7 py-1.5 rounded-lg text-[11px] font-mono text-t1 placeholder:text-t3 outline-none w-56"
              style={{
                background: 'var(--color-card)',
                border:     '1px solid var(--glass-border)',
                transition: 'border-color 0.15s',
              }}
              onFocus={e  => (e.target.style.borderColor = 'rgba(0,212,255,0.4)')}
              onBlur={e   => (e.target.style.borderColor = 'var(--glass-border)')}
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-t3 hover:text-t1 transition-colors"
              >
                <X size={10} />
              </button>
            )}
          </div>
        )}

        {/* Risk filter */}
        {history.length > 0 && (
          <div className="flex items-center gap-1 ml-1">
            <Filter size={10} className="text-t3 mr-0.5" />
            {RISK_FILTERS.map(f => {
              const active = riskFilter === f.value
              const color  = f.value === 'all' ? '#00d4ff' : SEV_COLOR[f.value]
              return (
                <button
                  key={f.value}
                  onClick={() => setRiskFilter(f.value)}
                  className="px-2 py-1 rounded-md text-[10px] font-mono transition-all duration-150"
                  style={{
                    color:      active ? color : 'var(--color-t3)',
                    background: active ? color + '18' : 'transparent',
                    border:     `1px solid ${active ? color + '40' : 'transparent'}`,
                  }}
                >
                  {f.label}
                </button>
              )
            })}
          </div>
        )}

        {/* Sort */}
        {history.length > 0 && (
          <div className="relative">
            <button
              onClick={() => setShowSort(v => !v)}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[10px] font-mono text-t2 hover:text-t1 glass-light border border-b1 transition-colors"
            >
              <SortDesc size={10} />
              {sortLabel}
            </button>
            <AnimatePresence>
              {showSort && (
                <motion.div
                  initial={{ opacity: 0, y: -4, scale: 0.96 }}
                  animate={{ opacity: 1, y: 0,  scale: 1 }}
                  exit={{ opacity: 0, y: -4, scale: 0.96 }}
                  transition={{ duration: 0.1 }}
                  className="absolute top-full mt-1 right-0 z-50 flex flex-col gap-0.5 p-1 rounded-lg min-w-[120px]"
                  style={{
                    background:   'var(--color-card-hover)',
                    border:       '1px solid var(--glass-border)',
                    boxShadow:    '0 8px 24px rgba(0,0,0,0.35)',
                  }}
                >
                  {SORT_OPTIONS.map(o => (
                    <button
                      key={o.value}
                      onClick={() => { setSortBy(o.value); setShowSort(false) }}
                      className="px-3 py-1.5 rounded-md text-[10px] font-mono text-left transition-colors"
                      style={{
                        color:      sortBy === o.value ? '#00d4ff' : 'var(--color-t2)',
                        background: sortBy === o.value ? 'rgba(0,212,255,0.1)' : 'transparent',
                      }}
                    >
                      {o.label}
                    </button>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}

        <div className="flex-1" />

        {/* Result count */}
        {history.length > 0 && (search || riskFilter !== 'all') && (
          <span className="text-[10px] font-mono text-t3">
            {filtered.length} / {history.length}
          </span>
        )}

        {/* Export buttons */}
        {history.length > 0 && (
          <div className="flex items-center gap-1">
            <button
              onClick={handleExportJSON}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[11px] font-mono text-t2 hover:text-t1 glass-light border border-b1 hover:border-neon-blue/30 transition-all duration-150"
            >
              <FileJson size={11} />
              JSON
            </button>
            <button
              onClick={handleExportCSV}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[11px] font-mono text-t2 hover:text-t1 glass-light border border-b1 hover:border-neon-purple/30 transition-all duration-150"
            >
              <FileText size={11} />
              CSV
            </button>
          </div>
        )}

        {/* Clear all */}
        {history.length > 0 && (
          <motion.button
            whileTap={{ scale: 0.96 }}
            onClick={handleClearAll}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-mono transition-all duration-200"
            style={{
              color:      confirmClear ? '#ff3b5c' : 'var(--color-t3)',
              background: confirmClear ? 'rgba(255,59,92,0.08)' : 'transparent',
              border:     `1px solid ${confirmClear ? 'rgba(255,59,92,0.25)' : 'transparent'}`,
            }}
          >
            <Trash2 size={11} />
            {confirmClear ? 'Confirm Clear' : 'Clear All'}
          </motion.button>
        )}

        {/* Close / back */}
        <motion.button
          whileHover={{ scale: 1.08 }}
          whileTap={{ scale: 0.92 }}
          onClick={onClose}
          className="flex items-center justify-center w-7 h-7 rounded-md glass-light border border-b1 text-t3 hover:text-t1 transition-colors"
          title="Back"
        >
          <X size={13} />
        </motion.button>
      </div>

      {/* ── Content ── */}
      <div
        className="flex-1 overflow-y-auto"
        style={{
          backgroundImage: 'linear-gradient(rgba(0,212,255,0.015) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.015) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      >
        {history.length === 0 ? (
          <EmptyHistory onClose={onClose} />
        ) : filtered.length === 0 ? (
          <NoResults onClear={() => { setSearch(''); setRiskFilter('all') }} />
        ) : (
          <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            <AnimatePresence mode="popLayout">
              {filtered.map((entry, i) => (
                <HistoryCard
                  key={entry.id}
                  entry={entry}
                  index={i}
                  onRestore={onRestore}
                  onDelete={handleDelete}
                />
              ))}
            </AnimatePresence>
          </div>
        )}
      </div>

      {/* ── Stats footer ── */}
      {history.length > 0 && (
        <div
          className="flex items-center gap-4 px-4 py-2 border-t border-b1 flex-shrink-0"
          style={{ background: 'var(--glass-bg)' }}
        >
          {[
            { label: 'Total scans',  value: history.length,                                              color: 'var(--color-t2)' },
            { label: 'Critical',     value: history.filter(e => riskLevelForScore(e.riskScore) === 'critical').length, color: '#ff3b5c' },
            { label: 'High risk',    value: history.filter(e => riskLevelForScore(e.riskScore) === 'high').length,     color: '#ff9500' },
            { label: 'Avg score',    value: Math.round(history.reduce((s, e) => s + e.riskScore, 0) / history.length), color: '#00d4ff' },
          ].map(({ label, value, color }) => (
            <div key={label} className="flex items-center gap-1.5">
              <span className="text-sm font-mono font-bold" style={{ color }}>{value}</span>
              <span className="text-[9px] font-mono text-t3">{label}</span>
            </div>
          ))}
          <div className="flex-1" />
          <div className="flex items-center gap-1 text-[9px] font-mono text-t3">
            <ShieldOff size={9} />
            Stored locally · never uploaded
          </div>
        </div>
      )}
    </motion.div>
  )
}
