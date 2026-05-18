// "APK Sig Block 42" encoded as bytes — marks presence of v2/v3 signing block
const SIG_BLOCK_MAGIC = [0x41,0x50,0x4B,0x20,0x53,0x69,0x67,0x20,0x42,0x6C,0x6F,0x63,0x6B,0x20,0x34,0x32]

function detectSigningBlock(buffer) {
  const bytes = new Uint8Array(buffer)
  // Walk backwards from end to find EOCD (0x504B0506)
  const limit = Math.max(0, bytes.length - 65558)
  for (let i = bytes.length - 22; i >= limit; i--) {
    if (bytes[i] !== 0x50 || bytes[i+1] !== 0x4B || bytes[i+2] !== 0x05 || bytes[i+3] !== 0x06) continue
    const cdOff = new DataView(buffer).getUint32(i + 16, true)
    if (cdOff < 16) break
    // APK Signing Block magic sits in the 16 bytes immediately before Central Directory
    if (SIG_BLOCK_MAGIC.every((b, j) => bytes[cdOff - 16 + j] === b)) return true
    break
  }
  return false
}

export function analyzeSignature(allFiles, buffer) {
  const meta  = allFiles.filter(f => f.startsWith('META-INF/'))
  const hasV1 = meta.some(f => f.endsWith('.SF')) && meta.some(f => /\.(RSA|DSA|EC)$/.test(f))
  const hasV2V3 = detectSigningBlock(buffer)
  return { hasV1, hasV2V3 }
}

export function buildSigFindings(sigInfo) {
  if (!sigInfo) return []
  const findings = []

  if (!sigInfo.hasV1 && !sigInfo.hasV2V3) {
    findings.push({
      sev:   'critical',
      title: 'APK has no detectable signature',
      body:  'No v1 signature files (META-INF/*.SF / *.RSA) and no APK Signing Block (v2/v3) were detected. An unsigned APK cannot be installed on production devices and may be corrupt or tampered.',
      fix:   'Sign the APK with a production keystore. Enable both v1 and v2 signing in build.gradle (v3 recommended for Android 9+ targets).',
    })
  } else if (sigInfo.hasV1 && !sigInfo.hasV2V3) {
    findings.push({
      sev:   'high',
      title: 'APK signed with v1 scheme only — Janus vulnerability (CVE-2017-13156)',
      body:  'Only the JAR signature scheme (v1) is present. On Android 5.0–6.0, v1-only APKs can be prepended with malicious DEX bytecode without invalidating the signature. v1 also leaves ZIP metadata (file names, compression) completely unprotected.',
      fix:   'Enable v2 (and v3 for API 28+) in your signing config: v1SigningEnabled true; v2SigningEnabled true; v3SigningEnabled true.',
    })
  }

  return findings
}

const ASSET_RULES = [
  { re: /\.(db|sqlite|sqlite3)$/i,        label: 'SQLite database',               sev: 'medium',   fix: 'Do not ship pre-populated databases containing sensitive data. Populate from a secure backend after first launch, or encrypt with SQLCipher.' },
  { re: /\.(pem|crt|cer|der)$/i,          label: 'X.509 certificate file',        sev: 'medium',   fix: 'Ensure only public certificates (no private keys) are bundled. Consider using Android Network Security Config for certificate pinning instead.' },
  { re: /\.(p12|pfx|jks|bks|keystore)$/i, label: 'Keystore / key material',       sev: 'critical', fix: 'Never bundle keystores or private key material in the APK. Use Android Keystore System for all on-device cryptographic key storage.' },
  { re: /\.key$/i,                         label: 'Private key file (.key)',        sev: 'critical', fix: 'Remove private key files from the APK immediately. Use Android Keystore System for on-device key storage.' },
  { re: /\.apk$/i,                         label: 'Embedded APK (dropper pattern)', sev: 'critical', fix: 'Embedding APKs is a classic malware dropper technique. Remove the embedded APK; distribute companion apps through the Play Store.' },
  { re: /\.(sh|bash|py|ps1|bat|cmd)$/i,   label: 'Executable script',             sev: 'high',     fix: 'Remove script files from the APK bundle. They can be extracted and executed, posing a code injection risk.' },
]

export function analyzeAssets(allFiles) {
  const targets = allFiles.filter(f => f.startsWith('assets/') || f.startsWith('res/raw/'))
  const byLabel = {}
  for (const path of targets) {
    const name = path.split('/').pop()
    for (const { re, label, sev, fix } of ASSET_RULES) {
      if (re.test(name)) {
        if (!byLabel[label]) byLabel[label] = { files: [], sev, fix }
        byLabel[label].files.push(path)
        break
      }
    }
  }
  return byLabel
}

export function buildAssetsFindings(suspiciousAssets) {
  if (!suspiciousAssets || !Object.keys(suspiciousAssets).length) return []
  return Object.entries(suspiciousAssets).map(([label, { files, sev, fix }]) => {
    const preview = files.slice(0, 3).map(f => f.split('/').pop()).join(', ')
    const extra   = files.length > 3 ? ` +${files.length - 3} more` : ''
    return {
      sev,
      title: `Suspicious file in APK bundle: ${label} (${files.length})`,
      body:  `Found ${files.length} ${label} file(s) that can be extracted from the APK by anyone with ADB access or decompilation tools: ${preview}${extra}.`,
      fix,
    }
  })
}
