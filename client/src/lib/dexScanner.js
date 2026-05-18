function readULEB128end(bytes, pos) {
  let shift = 0
  while (pos < bytes.length) {
    const b = bytes[pos++]
    if (!(b & 0x80) || shift > 28) break
    shift += 7
  }
  return pos
}

function extractDexStrings(dexBytes) {
  if (dexBytes.length < 112) return []
  // DEX magic: "dex\n"
  if (dexBytes[0] !== 0x64 || dexBytes[1] !== 0x65 || dexBytes[2] !== 0x78 || dexBytes[3] !== 0x0A) return []

  const dv       = new DataView(dexBytes.buffer, dexBytes.byteOffset, dexBytes.byteLength)
  const strCount = dv.getUint32(0x38, true)
  const strOff   = dv.getUint32(0x3C, true)
  if (strCount === 0 || strOff + strCount * 4 > dexBytes.length) return []

  const strings = []
  const decoder = new TextDecoder('utf-8', { fatal: false })
  const limit   = Math.min(strCount, 150_000)

  for (let i = 0; i < limit; i++) {
    const dataOff = dv.getUint32(strOff + i * 4, true)
    if (dataOff >= dexBytes.length) continue
    const start = readULEB128end(dexBytes, dataOff)
    let end = start
    while (end < dexBytes.length && dexBytes[end] !== 0) end++
    if (end - start > 4) strings.push(decoder.decode(dexBytes.subarray(start, end)))
  }
  return strings
}

const SKIP_PREFIXES = [
  'android.', 'com.android.', 'com.google.android.',
  'java.', 'javax.', 'dalvik.', 'kotlin.', 'kotlinx.',
  'org.apache.', 'org.w3c.', 'org.xml.', 'sun.', 'com.sun.',
]

const PATTERNS = [
  { id: 'aws-key',    label: 'AWS Access Key ID',       sev: 'critical', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'gcp-key',   label: 'Google API Key',           sev: 'critical', re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { id: 'firebase',  label: 'Firebase Database URL',    sev: 'high',     re: /https:\/\/[a-z0-9][a-z0-9-]*\.firebaseio\.com/i },
  { id: 'jwt',       label: 'JWT Token',                sev: 'high',     re: /^ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/ },
  { id: 'priv-ip',   label: 'Internal IP Address',      sev: 'medium',   re: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/ },
  { id: 'http-url',  label: 'Hardcoded HTTP URL',       sev: 'medium',   re: /^http:\/\/(?!schemas\.android\.com|www\.w3\.org|xml\.org|purl\.org|ns\.adobe\.com|apache\.org)[a-zA-Z0-9][a-zA-Z0-9.-]{3,}\.[a-zA-Z]{2,}/ },
]

export async function scanDexFiles(zip) {
  const dexNames = Object.keys(zip.files).filter(f => /^classes\d*\.dex$/.test(f)).slice(0, 4)
  const hitMap   = {}

  for (const name of dexNames) {
    const bytes = await zip.files[name].async('uint8array')
    if (bytes.length > 8_000_000) continue  // skip oversized DEX

    for (const str of extractDexStrings(bytes)) {
      if (SKIP_PREFIXES.some(p => str.startsWith(p))) continue
      for (const { id, label, sev, re } of PATTERNS) {
        const m = str.match(re)
        if (m) {
          if (!hitMap[id]) hitMap[id] = { label, sev, values: new Set() }
          hitMap[id].values.add(m[0])
          break
        }
      }
    }
  }

  return Object.values(hitMap).map(({ label, sev, values }) => ({
    label, sev,
    samples: [...values].slice(0, 3),
    count:   values.size,
  }))
}

export function buildDexFindings(dexHits) {
  if (!dexHits?.length) return []
  return dexHits.map(({ label, sev, samples, count }) => {
    const examples = samples.map(v => `"${v.length > 60 ? v.slice(0, 57) + '…' : v}"`).join(', ')
    return {
      sev,
      title: `DEX: ${label} hardcoded (${count} occurrence${count > 1 ? 's' : ''})`,
      body:  `Found ${count} hardcoded ${label} value(s) in the application bytecode. Any attacker who decompiles the APK can read these in seconds. Examples: ${examples}.`,
      fix:   `Remove all hardcoded ${label} values. Fetch secrets from a secure backend at runtime, use Android Keystore for on-device cryptographic keys, and rotate any already-exposed credentials immediately.`,
    }
  })
}
