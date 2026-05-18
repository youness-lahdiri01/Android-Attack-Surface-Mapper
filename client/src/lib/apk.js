import JSZip from 'jszip'
import { parseAXML } from './axml.js'
import { parseNetworkSecurityConfig } from './netSecConfig.js'
import { scanDexFiles } from './dexScanner.js'
import { analyzeSignature, analyzeAssets } from './apkMeta.js'

export async function loadAPK(file, onProgress = () => {}) {
  onProgress('Reading file…')
  const buffer = await file.arrayBuffer()

  onProgress('Opening APK archive…')
  let zip
  try {
    zip = await JSZip.loadAsync(buffer)
  } catch (e) {
    throw new Error('Cannot open as ZIP: ' + e.message + '. Is this a valid APK?')
  }

  const allFiles   = Object.keys(zip.files)
  const dexFiles   = allFiles.filter(f => /^classes\d*\.dex$/.test(f))
  const nativeLibs = allFiles.filter(f => f.startsWith('lib/') && f.endsWith('.so'))

  onProgress('Extracting AndroidManifest.xml…')
  const manifestFile = zip.file('AndroidManifest.xml')
  if (!manifestFile)
    throw new Error('AndroidManifest.xml missing from APK. This may be a split APK or corrupt file.')

  onProgress('Decoding binary manifest…')
  const manifestBytes = await manifestFile.async('uint8array')

  let xml
  try {
    xml = parseAXML(manifestBytes)
  } catch (e) {
    throw new Error('Failed to decode manifest: ' + e.message)
  }

  const archs = [...new Set(nativeLibs.map(f => f.split('/')[1]).filter(Boolean))]

  onProgress('Scanning DEX bytecode for secrets…')
  const dexHits = await scanDexFiles(zip)

  onProgress('Analyzing APK signature…')
  const sigInfo = analyzeSignature(allFiles, buffer)

  onProgress('Checking for suspicious embedded files…')
  const suspiciousAssets = analyzeAssets(allFiles)

  onProgress('Scanning network security config…')
  let netSec = null
  const nsConfigMatch = xml.match(/networkSecurityConfig="@xml\/([^"]+)"/)
  const nsConfigName  = nsConfigMatch ? nsConfigMatch[1] : 'network_security_config'
  const nsConfigFile  = zip.file(`res/xml/${nsConfigName}.xml`)
  if (nsConfigFile) {
    try {
      const bytes  = await nsConfigFile.async('uint8array')
      const nsXml  = parseAXML(bytes)
      netSec = parseNetworkSecurityConfig(nsXml)
    } catch {
      // not critical — skip on decode failure
    }
  }

  const apkInfo = {
    fileName:    file.name,
    fileSize:    (file.size / 1024 / 1024).toFixed(2) + ' MB',
    dexCount:    dexFiles.length,
    nativeArchs: archs.length ? archs.join(', ') : 'none',
    hasAssets:   allFiles.some(f => f.startsWith('assets/')),
    hasResources: zip.file('resources.arsc') !== null,
    totalFiles:  allFiles.length,
  }

  return { xml, apkInfo, netSec, dexHits, sigInfo, suspiciousAssets }
}
