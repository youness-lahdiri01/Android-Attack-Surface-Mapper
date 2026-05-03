import { Shield, RotateCcw, FileJson, FileText, Cpu, Sun, Moon, GitBranch } from 'lucide-react'
import { motion } from 'framer-motion'

const SEV_COLOR = { critical: '#ff3b5c', high: '#ff9500', medium: '#ffd60a', low: '#3fb950' }

export default function Header({ scanState, onReset, apkInfo, onExportJSON, onExportCSV, onExportMermaid, onToggleTheme, isDark }) {
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
    <header className="flex items-center gap-3 px-4 py-2.5 glass border-b border-b1 z-10 flex-shrink-0">
      {/* Logo */}
      <div className="flex items-center gap-2 mr-2">
        <div className="relative">
          <Shield size={22} className="text-neon-cyan" />
          <div className="absolute inset-0 blur-sm opacity-60" style={{ color: '#00d4ff' }}>
            <Shield size={22} />
          </div>
        </div>
        <div>
          <div className="text-t1 font-mono font-bold text-sm tracking-wide">
            AASM
          </div>
          <div className="text-t3 text-[9px] font-mono tracking-widest -mt-0.5">
            ATTACK SURFACE MAPPER
          </div>
        </div>
      </div>

      {/* Package + score (after scan) */}
      {scanState && (
        <motion.div
          initial={{ opacity: 0, x: -12 }}
          animate={{ opacity: 1, x: 0 }}
          className="flex items-center gap-2"
        >
          <span className="glass-light px-2.5 py-1 rounded-md text-xs font-mono text-t2 border border-b1">
            {scanState.parsed.pkg}
          </span>
          {apkInfo && (
            <span className="flex items-center gap-1 text-[10px] font-mono text-t3 glass-light px-2 py-1 rounded border border-b1">
              <Cpu size={10} className="text-neon-purple" />
              {apkInfo.fileName} · {apkInfo.fileSize}
            </span>
          )}
        </motion.div>
      )}

      <div className="flex-1" />

      {/* Risk score badge */}
      {score !== null && (
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold border"
          style={{
            color: scoreColor,
            borderColor: scoreColor + '50',
            background: scoreColor + '15',
            boxShadow: `0 0 12px ${scoreColor}30`,
          }}
        >
          <span style={{ color: scoreColor }}>{score}</span>
          <span className="text-t3 font-normal">/100</span>
          <span className="ml-0.5">{riskLabel}</span>
        </motion.div>
      )}

      {/* Findings count badges */}
      {scanState && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex items-center gap-1"
        >
          {(['critical', 'high', 'medium'] ).map(sev => {
            const count = scanState.findings.filter(f => f.sev === sev).length
            if (!count) return null
            return (
              <span
                key={sev}
                className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold"
                style={{ color: SEV_COLOR[sev], background: SEV_COLOR[sev] + '18' }}
              >
                {count} {sev.slice(0, 4).toUpperCase()}
              </span>
            )
          })}
        </motion.div>
      )}

      {/* Export buttons */}
      {scanState && (
        <div className="flex items-center gap-1 ml-1">
          <button
            onClick={onExportJSON}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[11px] font-mono text-t2 hover:text-t1 glass-light border border-b1 hover:border-neon-blue/30 transition-all duration-150"
          >
            <FileJson size={12} />
            JSON
          </button>
          <button
            onClick={onExportCSV}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[11px] font-mono text-t2 hover:text-t1 glass-light border border-b1 hover:border-neon-purple/30 transition-all duration-150"
          >
            <FileText size={12} />
            CSV
          </button>
          <button
            onClick={onExportMermaid}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[11px] font-mono text-t2 hover:text-t1 glass-light border border-b1 hover:border-neon-cyan/30 transition-all duration-150"
            title="Export attack graph as Mermaid diagram (.mmd)"
          >
            <GitBranch size={12} />
            Mermaid
          </button>
        </div>
      )}

      {/* Theme toggle */}
      <motion.button
        onClick={onToggleTheme}
        whileHover={{ scale: 1.08 }}
        whileTap={{ scale: 0.92 }}
        className="flex items-center justify-center w-7 h-7 rounded-md glass-light border border-b1 text-t3 hover:text-t1 transition-colors duration-150"
        title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      >
        {isDark ? <Sun size={13} /> : <Moon size={13} />}
      </motion.button>

      {/* Reset */}
      {onReset && (
        <button
          onClick={onReset}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-mono text-t3 hover:text-t1 glass-light border border-b1 hover:border-white/20 transition-all duration-150"
        >
          <RotateCcw size={11} />
          New Scan
        </button>
      )}
    </header>
  )
}
