const STORAGE_KEY = 'aasm_scan_history'
const MAX_ENTRIES = 50

function genId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
}

function persistHistory(history) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history))
  } catch {
    // Quota exceeded — drop oldest half and retry
    const trimmed = history.slice(0, Math.ceil(history.length / 2))
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed))
    } catch {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(history.slice(0, 1)))
      } catch { /* storage unavailable */ }
    }
  }
}

export function loadHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

export function saveToHistory(scanState, apkInfo) {
  if (!scanState?.parsed) return null
  const { parsed, findings, score } = scanState

  const entry = {
    id: genId(),
    apkName: apkInfo?.fileName ?? `${parsed.pkg.split('.').pop()}.apk`,
    packageName: parsed.pkg,
    riskScore: score,
    counts: {
      critical: findings.filter(f => f.sev === 'critical').length,
      high:     findings.filter(f => f.sev === 'high').length,
      medium:   findings.filter(f => f.sev === 'medium').length,
      low:      findings.filter(f => f.sev === 'low').length,
    },
    permissions:        parsed.permissions ?? [],
    findings,
    exportedComponents: (parsed.components ?? []).filter(c => c.inferredExported),
    scanDate:           new Date().toISOString(),
    _scanState:         scanState,
    _apkInfo:           apkInfo ?? null,
  }

  const history = loadHistory()

  // Skip duplicate if same package was saved in the last 30 s
  const last = history[0]
  if (last?.packageName === entry.packageName) {
    const ageSec = (Date.now() - new Date(last.scanDate).getTime()) / 1000
    if (ageSec < 30) return last
  }

  const updated = [entry, ...history].slice(0, MAX_ENTRIES)
  persistHistory(updated)
  return entry
}

export function deleteHistoryEntry(id) {
  const updated = loadHistory().filter(e => e.id !== id)
  persistHistory(updated)
  return updated
}

export function clearHistory() {
  try { localStorage.removeItem(STORAGE_KEY) } catch { /* ignore */ }
}

export function exportHistoryJSON(history) {
  const clean = history.map(({ id, apkName, packageName, riskScore, counts, permissions, findings, exportedComponents, scanDate }) => ({
    id, apkName, packageName, riskScore, counts, permissions, findings, exportedComponents, scanDate,
  }))
  return JSON.stringify(clean, null, 2)
}

export function exportHistoryCSV(history) {
  const esc  = v => `"${String(v ?? '').replace(/"/g, '""')}"`
  const hdrs = ['scanDate', 'apkName', 'packageName', 'riskScore', 'critical', 'high', 'medium', 'low', 'totalFindings', 'exportedComponents']
  const rows = history.map(e => [
    e.scanDate, e.apkName, e.packageName, e.riskScore,
    e.counts.critical, e.counts.high, e.counts.medium, e.counts.low,
    e.findings.length, e.exportedComponents.length,
  ].map(esc))
  return [hdrs.map(esc).join(','), ...rows.map(r => r.join(','))].join('\n')
}
