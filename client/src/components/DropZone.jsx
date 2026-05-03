import { useState, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, Shield, Zap, FileCode, ChevronRight, AlertCircle } from 'lucide-react'

export default function DropZone({ xmlInput, onXmlChange, onAPK, onScan, onDemo, error, isScanning }) {
  const [isDragging, setIsDragging] = useState(false)
  const [showXml, setShowXml] = useState(false)
  const fileRef = useRef(null)

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setIsDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) onAPK(file)
  }, [onAPK])

  const handleDragOver = useCallback((e) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback(() => setIsDragging(false), [])

  return (
    <div className="w-full max-w-2xl flex flex-col gap-4">
      {/* Title */}
      <div className="text-center mb-2">
        <motion.h1
          initial={{ opacity: 0, y: -16 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-2xl font-mono font-bold text-t1 tracking-tight"
        >
          Android Attack Surface Mapper
        </motion.h1>
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="text-t3 text-sm font-mono mt-1"
        >
          Analyze APK manifests for security vulnerabilities
        </motion.p>
      </div>

      {/* Drop zone */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
        className="relative rounded-xl overflow-hidden drop-zone-border"
        style={{ padding: '1px' }}
      >
        <div
          className="relative flex flex-col items-center justify-center gap-4 p-10 rounded-xl cursor-pointer transition-all duration-300"
          style={{
            background: isDragging
              ? 'rgba(0, 212, 255, 0.06)'
              : 'rgba(22, 27, 34, 0.95)',
            backdropFilter: 'blur(16px)',
          }}
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

          {/* Icon */}
          <motion.div
            animate={{ scale: isDragging ? 1.1 : 1, y: isDragging ? -4 : 0 }}
            transition={{ type: 'spring', stiffness: 300 }}
            className="relative"
          >
            <div
              className="w-16 h-16 rounded-2xl flex items-center justify-center"
              style={{ background: 'rgba(0, 212, 255, 0.1)', border: '1px solid rgba(0,212,255,0.3)' }}
            >
              <Upload size={28} className="text-neon-cyan" />
            </div>
            {isDragging && (
              <motion.div
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1.5, opacity: 0 }}
                transition={{ duration: 0.8, repeat: Infinity }}
                className="absolute inset-0 rounded-2xl border border-neon-cyan"
              />
            )}
          </motion.div>

          <div className="text-center">
            <div className="text-t1 font-mono font-semibold">
              {isDragging ? 'Drop APK here' : 'Drop APK or click to upload'}
            </div>
            <div className="text-t3 text-xs font-mono mt-1">
              .apk files — decoded in-browser, nothing uploaded
            </div>
          </div>

          {/* Feature pills */}
          <div className="flex items-center gap-2 flex-wrap justify-center">
            {[
              { icon: Shield, label: 'Component Analysis', color: '#58a6ff' },
              { icon: Zap, label: 'Risk Scoring', color: '#a371f7' },
              { icon: FileCode, label: 'Deep Link Detection', color: '#d29922' },
            ].map(({ icon: Icon, label, color }) => (
              <div
                key={label}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono"
                style={{ background: color + '15', border: `1px solid ${color}30`, color }}
              >
                <Icon size={10} />
                {label}
              </div>
            ))}
          </div>
        </div>
      </motion.div>

      {/* XML Toggle */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.25 }}
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
          <motion.div animate={{ rotate: showXml ? 90 : 0 }} transition={{ duration: 0.2 }}>
            <ChevronRight size={14} />
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
                  placeholder="<?xml version=&quot;1.0&quot; encoding=&quot;utf-8&quot;?>&#10;<manifest ..."
                  rows={8}
                  className="w-full bg-bg border border-b1 rounded-lg p-3 font-mono text-[11px] text-t2 placeholder-t3 focus:outline-none focus:border-neon-blue/40 resize-none"
                  spellCheck={false}
                />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Error */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 8 }}
            className="flex items-center gap-2 px-4 py-3 rounded-lg text-xs font-mono text-neon-red"
            style={{ background: 'rgba(255,59,92,0.1)', border: '1px solid rgba(255,59,92,0.3)' }}
          >
            <AlertCircle size={13} />
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Action buttons */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
        className="flex gap-3"
      >
        <button
          onClick={onScan}
          disabled={!xmlInput.trim() || isScanning}
          className="flex-1 flex items-center justify-center gap-2 py-3 rounded-xl font-mono font-semibold text-sm transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed"
          style={{
            background: 'linear-gradient(135deg, rgba(0,212,255,0.15), rgba(88,166,255,0.15))',
            border: '1px solid rgba(0,212,255,0.4)',
            color: '#00d4ff',
            boxShadow: !xmlInput.trim() ? 'none' : '0 0 20px rgba(0,212,255,0.2)',
          }}
        >
          <Shield size={15} />
          Scan Manifest
        </button>
        <button
          onClick={onDemo}
          className="flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-mono text-sm text-t2 hover:text-t1 glass border border-b1 hover:border-neon-purple/30 transition-all duration-150"
        >
          <Zap size={13} className="text-neon-purple" />
          Load Demo
        </button>
      </motion.div>
    </div>
  )
}
