import { useState, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, Shield, Zap, FileCode, ChevronRight, AlertCircle, Eye, Lock, Network } from 'lucide-react'
import { useTheme } from '../hooks/useTheme.js'

const CAPABILITIES = [
  { icon: Eye,     label: 'Component Analysis',  color: '#58a6ff', desc: 'Activities, Services, Receivers, Providers' },
  { icon: Shield,  label: 'Risk Scoring',        color: '#a371f7', desc: 'Weighted 0–100 attack surface score' },
  { icon: Network, label: 'Attack Graph',        color: '#00d4ff', desc: 'Force-directed D3 visualization' },
  { icon: Lock,    label: 'Deep Link Detection', color: '#d29922', desc: 'URI scheme & intent-filter analysis' },
]

const FEATURE_TAGS = [
  { label: 'In-browser only',       color: '#3fb950' },
  { label: 'No upload required',    color: '#3fb950' },
  { label: 'AndroidManifest.xml',   color: '#58a6ff' },
  { label: 'AI-powered analysis',   color: '#a371f7' },
]

export default function DropZone({ xmlInput, onXmlChange, onAPK, onScan, onDemo, error, isScanning }) {
  const { isDark } = useTheme()
  const [isDragging, setIsDragging] = useState(false)
  const [showXml,    setShowXml]    = useState(false)
  const fileRef = useRef(null)

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setIsDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) onAPK(file)
  }, [onAPK])
  const handleDragOver  = useCallback((e) => { e.preventDefault(); setIsDragging(true) },  [])
  const handleDragLeave = useCallback(() => setIsDragging(false), [])

  const zoneBg = isDragging
    ? 'rgba(0,212,255,0.06)'
    : isDark
      ? 'rgba(22,27,34,0.97)'
      : 'rgba(255,255,255,0.97)'

  return (
    <div className="w-full max-w-xl flex flex-col gap-4">

      {/* ── Hero title ──────────────────────────────────────────────── */}
      <div className="text-center mb-1">
        <motion.div
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-center gap-2.5 mb-3"
        >
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center"
            style={{
              background: 'rgba(0,212,255,0.1)',
              border: '1px solid rgba(0,212,255,0.3)',
              boxShadow: '0 0 20px rgba(0,212,255,0.15)',
            }}
          >
            <Shield size={20} className="text-neon-cyan" />
          </div>
          <div className="text-left">
            <div className="text-xl font-bold text-t1 tracking-tight leading-none">AASM</div>
            <div className="text-[10px] font-mono text-t3 tracking-[0.18em] leading-none mt-0.5">
              ANDROID ATTACK SURFACE MAPPER
            </div>
          </div>
        </motion.div>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="text-sm text-t2 max-w-sm mx-auto leading-relaxed"
        >
          Automated static analysis for APK manifests — find security vulnerabilities
          before attackers do.
        </motion.p>

        {/* Feature tags */}
        <motion.div
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="flex items-center justify-center gap-2 flex-wrap mt-3"
        >
          {FEATURE_TAGS.map(({ label, color }) => (
            <span
              key={label}
              className="text-[9px] font-mono px-2 py-0.5 rounded-full"
              style={{ color, background: color + '18', border: `1px solid ${color}30` }}
            >
              {label}
            </span>
          ))}
        </motion.div>
      </div>

      {/* ── Drop zone ───────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.18 }}
        className="relative rounded-xl overflow-hidden drop-zone-border"
        style={{ padding: '1px' }}
      >
        <div
          className="relative flex flex-col items-center justify-center gap-5 p-9 rounded-xl cursor-pointer"
          style={{ background: zoneBg, backdropFilter: 'blur(16px)', transition: 'background 0.2s ease' }}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={() => fileRef.current?.click()}
        >
          <input
            ref={fileRef}
            type="file"
            accept=".apk"
            className="hidden"
            onChange={e => { const f = e.target.files?.[0]; if (f) onAPK(f) }}
          />

          {/* Upload icon */}
          <motion.div
            animate={{ scale: isDragging ? 1.08 : 1, y: isDragging ? -5 : 0 }}
            transition={{ type: 'spring', stiffness: 320, damping: 20 }}
          >
            <div
              className="relative w-16 h-16 rounded-2xl flex items-center justify-center"
              style={{
                background: isDragging ? 'rgba(0,212,255,0.15)' : 'rgba(0,212,255,0.09)',
                border: `1px solid ${isDragging ? 'rgba(0,212,255,0.6)' : 'rgba(0,212,255,0.28)'}`,
                boxShadow: isDragging ? '0 0 24px rgba(0,212,255,0.3)' : '0 0 12px rgba(0,212,255,0.1)',
                transition: 'all 0.2s ease',
              }}
            >
              <Upload size={26} className="text-neon-cyan" />
              {isDragging && (
                <motion.div
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ scale: 1.6, opacity: 0 }}
                  transition={{ duration: 0.8, repeat: Infinity }}
                  className="absolute inset-0 rounded-2xl border border-neon-cyan"
                />
              )}
            </div>
          </motion.div>

          <div className="text-center">
            <div className="text-sm font-semibold text-t1 mb-1">
              {isDragging ? 'Release to analyze APK' : 'Drop APK file or click to browse'}
            </div>
            <div className="text-xs font-mono text-t3">
              Decoded entirely in-browser — nothing is uploaded
            </div>
          </div>

          {/* Capability pills */}
          <div className="grid grid-cols-2 gap-2 w-full max-w-xs">
            {CAPABILITIES.map(({ icon: Icon, label, color }) => (
              <div
                key={label}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[10px] font-mono"
                style={{ background: color + '0f', border: `1px solid ${color}25`, color }}
              >
                <Icon size={10} style={{ flexShrink: 0 }} />
                {label}
              </div>
            ))}
          </div>
        </div>
      </motion.div>

      {/* ── XML paste panel ─────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.28 }}
        className="glass rounded-xl overflow-hidden border border-b1"
      >
        <button
          className="w-full flex items-center justify-between px-4 py-3 text-t2 hover:text-t1 transition-colors duration-150"
          onClick={() => setShowXml(v => !v)}
        >
          <div className="flex items-center gap-2 text-xs font-mono">
            <FileCode size={13} className="text-neon-purple" />
            Paste AndroidManifest.xml manually
          </div>
          <motion.div animate={{ rotate: showXml ? 90 : 0 }} transition={{ duration: 0.18 }}>
            <ChevronRight size={14} className="text-t3" />
          </motion.div>
        </button>

        <AnimatePresence>
          {showXml && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="overflow-hidden"
            >
              <div className="px-4 pb-4">
                <textarea
                  value={xmlInput}
                  onChange={e => onXmlChange(e.target.value)}
                  placeholder={'<?xml version="1.0" encoding="utf-8"?>\n<manifest ...'}
                  rows={8}
                  className="w-full rounded-lg p-3 font-mono text-[11px] text-t2 placeholder:text-t3 outline-none resize-none focus-ring"
                  style={{
                    background: 'var(--color-bg)',
                    border: '1px solid var(--color-b1)',
                  }}
                  spellCheck={false}
                />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* ── Error ───────────────────────────────────────────────────── */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 8, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8 }}
            className="flex items-center gap-2.5 px-4 py-3 rounded-xl text-xs font-mono"
            style={{
              background: 'rgba(255,59,92,0.08)',
              border: '1px solid rgba(255,59,92,0.28)',
              color: '#ff3b5c',
            }}
          >
            <AlertCircle size={13} style={{ flexShrink: 0 }} />
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Action buttons ───────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.32 }}
        className="flex gap-3"
      >
        <motion.button
          onClick={onScan}
          disabled={!xmlInput.trim() || isScanning}
          whileHover={xmlInput.trim() ? { scale: 1.02 } : {}}
          whileTap={xmlInput.trim() ? { scale: 0.98 } : {}}
          className="flex-1 flex items-center justify-center gap-2 py-3 rounded-xl font-mono font-semibold text-sm disabled:opacity-35 disabled:cursor-not-allowed btn-shimmer"
          style={{
            background: 'linear-gradient(135deg, rgba(0,212,255,0.14), rgba(88,166,255,0.12))',
            border: '1px solid rgba(0,212,255,0.38)',
            color: '#00d4ff',
            boxShadow: xmlInput.trim() ? '0 0 22px rgba(0,212,255,0.18)' : 'none',
            transition: 'box-shadow 0.2s ease, opacity 0.2s ease',
          }}
        >
          <Shield size={14} />
          Scan Manifest
        </motion.button>

        <motion.button
          onClick={onDemo}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          className="flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-mono text-sm text-t2 hover:text-t1 glass border border-b1 hover:border-neon-purple/30 btn-shimmer"
          style={{ transition: 'all 0.18s ease' }}
        >
          <Zap size={13} className="text-neon-purple" />
          Demo
        </motion.button>
      </motion.div>
    </div>
  )
}
